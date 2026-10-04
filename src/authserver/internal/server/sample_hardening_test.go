package server

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"gopkg.in/yaml.v3"
)

// writableDirs are the directories each image creates owned by its uid 10001, the only places a
// service on a read-only root can be given a volume it can write: Docker copies a mount point's
// ownership into an empty named volume, and creates a mount point the image lacks owned by root.
// The admin console's image creates none, since it writes nothing (#396 decision 1).
var writableDirs = map[string][]string{
	authServerImage:   {"/data", "/bootstrap"},
	adminConsoleImage: nil,
}

// pinnedDatabaseImage is a MySQL or PostgreSQL image, whose tag must name a major: a container on
// an existing data volume refuses to start once latest moves a major (#396 decision 11).
var pinnedDatabaseImage = regexp.MustCompile(`^(mysql|postgres):`)

var majorTag = regexp.MustCompile(`^[0-9]+$`)

// Every sample Compose file runs both servers as the images' uid 10001 with no capabilities, no new
// privileges and a read-only root with /tmp on tmpfs, gives the auth server only named volumes, at
// the directories its image creates for it, with its SQLite file and its bootstrap file inside
// them, names a MySQL or PostgreSQL major under a comment saying an upgrade is not a tag edit, and
// says beside its latest tags to pin one. The generator's files are held to the same posture by
// the setup wizard's TestComposeFile_RunsEachServerHardened (#396 decisions 1, 2, 10 and 11).
func TestSampleComposeFiles_RunEachServerHardened(t *testing.T) {
	assertSampleHardening(t, guard.SourceRoot(t), sampleComposeFiles)
}

func TestSampleComposeFiles_AnUnhardenedServiceFailsNamingTheFile(t *testing.T) {
	root := t.TempDir()
	writeDeploymentFixture(t, root, "build/docker-compose-root.yml", `
services:
  db:
    image: mysql:latest
  auth:
    image: leodip/goiabada:authserver-latest
    volumes:
      - sqlite-data:/app/data
      - ./bootstrap:/bootstrap
    environment:
      - GOIABADA_DB_DSN=file:/app/data/goiabada.db?_pragma=busy_timeout=5000
      - GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE=/bootstrap/bootstrap.env
  console:
    image: leodip/goiabada:adminconsole-1.5.0
    user: "10001:0"
    cap_drop: [CHOWN]
    security_opt: [no-new-privileges:false]
    read_only: false
    tmpfs: [/var/tmp]
    volumes:
      - sqlite-data:/data
`)
	writeDeploymentFixture(t, root, "build/docker-compose-hardened.yml", `
services:
  db:
    # A major upgrade is a dump and restore, not a tag edit.
    image: postgres:18
  auth:
    # Pin a release's version tag here.
    image: leodip/goiabada:authserver-latest
    user: "10001:10001"
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    read_only: true
    tmpfs: [/tmp]
    volumes:
      - sqlite-data:/data
      - bootstrap:/bootstrap
    environment:
      - GOIABADA_DB_DSN=file:/data/goiabada.db?_pragma=busy_timeout=5000
      - GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE=/bootstrap/bootstrap.env
  console:
    image: leodip/goiabada:adminconsole-1.5.0
    user: "10001:10001"
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    read_only: true
    tmpfs: [/tmp]
`)
	files := []string{"build/docker-compose-root.yml", "build/docker-compose-hardened.yml"}

	report := guard.Run(func(r guard.Reporter) {
		assertSampleHardening(r, root, files)
	})

	if report.Stopped {
		t.Fatalf("the walk stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	want := []string{
		`build/docker-compose-root.yml: service auth runs as user <nil>, want "10001:10001"`,
		`build/docker-compose-root.yml: service auth drops capabilities <nil>, want [ALL]`,
		`build/docker-compose-root.yml: service auth has security_opt <nil>, want [no-new-privileges:true]`,
		`build/docker-compose-root.yml: service auth has read_only <nil>, want true`,
		`build/docker-compose-root.yml: service auth has tmpfs <nil>, want [/tmp]`,
		`build/docker-compose-root.yml: service auth mounts sqlite-data at /app/data`,
		`build/docker-compose-root.yml: service auth bind-mounts ./bootstrap`,
		`build/docker-compose-root.yml: service auth writes GOIABADA_DB_DSN to /app/data/goiabada.db`,
		`build/docker-compose-root.yml: service auth's latest tag has no comment saying to pin a version`,
		`build/docker-compose-root.yml: service console runs as user "10001:0", want "10001:10001"`,
		`build/docker-compose-root.yml: service console drops capabilities [CHOWN], want [ALL]`,
		`build/docker-compose-root.yml: service console has security_opt [no-new-privileges:false], want [no-new-privileges:true]`,
		`build/docker-compose-root.yml: service console has read_only false, want true`,
		`build/docker-compose-root.yml: service console has tmpfs [/var/tmp], want [/tmp]`,
		`build/docker-compose-root.yml: service console mounts sqlite-data at /data`,
		`build/docker-compose-root.yml: service db runs mysql:latest`,
		`build/docker-compose-root.yml: service db's image has no comment saying a major upgrade is not a tag edit`,
	}
	for _, line := range want {
		if !strings.Contains(text, line) {
			t.Errorf("no failure says %q:\n%s", line, text)
		}
	}
	if strings.Contains(text, "docker-compose-hardened.yml") {
		t.Errorf("a failure names docker-compose-hardened.yml, which is hardened:\n%s", text)
	}
	if len(report.Errors) != len(want) {
		t.Errorf("%d failures, want %d:\n%s", len(report.Errors), len(want), text)
	}
}

func TestSampleComposeFiles_AHardeningWalkFindingNothingFails(t *testing.T) {
	root := t.TempDir()
	writeDeploymentFixture(t, root, "build/docker-compose-sqlite.yml", `
services:
  db:
    image: postgres:18
`)

	for _, files := range [][]string{
		{"build/docker-compose-sqlite.yml"},
		{"build/docker-compose-mysql.yml"},
	} {
		report := guard.Run(func(r guard.Reporter) {
			assertSampleHardening(r, root, files)
		})
		if !report.Stopped || !strings.Contains(report.Fatal, files[0]) {
			t.Errorf("a sample that is missing or runs no auth server did not stop the walk naming it: %+v", report)
		}
	}
}

// assertSampleHardening is the reporting half: one failure per shortfall, and a stop when a file is
// missing or runs no auth server, so a sample renamed or emptied fails rather than passing unread.
func assertSampleHardening(r guard.Reporter, root string, files []string) {
	r.Helper()
	for _, file := range files {
		shortfalls, err := hardeningShortfalls(root, file)
		if err != nil {
			r.Fatalf("%s: %v", file, err)
		}
		for _, shortfall := range shortfalls {
			r.Errorf("%s: %s", file, shortfall)
		}
	}
}

// hardeningShortfalls reads one single-document Compose file and returns one line per property a
// service of ours, or a MySQL or PostgreSQL service, lacks.
func hardeningShortfalls(root, file string) ([]string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := node.Decode(&doc); err != nil {
		return nil, err
	}
	services, _ := doc["services"].(map[string]any)

	var shortfalls []string
	authServers := 0
	for name, s := range services {
		service, _ := s.(map[string]any)
		image, _ := service["image"].(string)
		comment := imageHeadComment(&node, name)
		switch {
		case imageIs(service, authServerImage):
			authServers++
			shortfalls = append(shortfalls, serviceShortfalls(name, service, writableDirs[authServerImage], comment)...)
		case imageIs(service, adminConsoleImage):
			shortfalls = append(shortfalls, serviceShortfalls(name, service, writableDirs[adminConsoleImage], comment)...)
		case pinnedDatabaseImage.MatchString(image):
			if _, tag, _ := strings.Cut(image, ":"); !majorTag.MatchString(tag) {
				shortfalls = append(shortfalls, fmt.Sprintf(
					"service %s runs %s, which moves a major under an existing data volume; name the major", name, image))
			}
			if !strings.Contains(comment, "not a tag edit") {
				shortfalls = append(shortfalls, fmt.Sprintf(
					"service %s's image has no comment saying a major upgrade is not a tag edit", name))
			}
		}
	}
	if authServers == 0 {
		return nil, fmt.Errorf("no service runs %s", authServerImage)
	}
	// Map order is random; a sorted list reads the same on every run.
	sort.Strings(shortfalls)
	return shortfalls, nil
}

// serviceShortfalls is what one service of ours lacks of the hardened posture, given the
// directories its image creates for it to write and the comment above its image key.
func serviceShortfalls(name string, service map[string]any, writable []string, imageComment string) []string {
	var shortfalls []string
	for _, want := range []struct {
		key, what string
		value     any
	}{
		{"user", "runs as user", "10001:10001"},
		{"cap_drop", "drops capabilities", []any{"ALL"}},
		{"security_opt", "has security_opt", []any{"no-new-privileges:true"}},
		{"read_only", "has read_only", true},
		{"tmpfs", "has tmpfs", []any{"/tmp"}},
	} {
		got := service[want.key]
		if fmt.Sprintf("%#v", got) != fmt.Sprintf("%#v", want.value) {
			shortfalls = append(shortfalls, fmt.Sprintf("service %s %s %s, want %s", name, want.what, show(got), show(want.value)))
		}
	}

	var targets []string
	volumes, _ := service["volumes"].([]any)
	for _, v := range volumes {
		entry, _ := v.(string)
		parts := strings.Split(entry, ":")
		if len(parts) < 2 {
			shortfalls = append(shortfalls, fmt.Sprintf("service %s mounts %q, which this test cannot read", name, entry))
			continue
		}
		source, target := parts[0], parts[1]
		if strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") || strings.HasPrefix(source, "~") {
			targets = append(targets, target)
			shortfalls = append(shortfalls, fmt.Sprintf(
				"service %s bind-mounts %s, a host directory Docker creates owned by root; use a named volume", name, source))
			continue
		}
		if !slices.Contains(writable, target) {
			shortfalls = append(shortfalls, fmt.Sprintf(
				"service %s mounts %s at %s, which its image does not create owned by 10001; use one of %v",
				name, source, target, writable))
			continue
		}
		targets = append(targets, target)
	}

	environment, _ := service["environment"].([]any)
	for _, e := range environment {
		entry, _ := e.(string)
		variable, value, _ := strings.Cut(entry, "=")
		var file string
		switch variable {
		case "GOIABADA_DB_DSN":
			file, _, _ = strings.Cut(strings.TrimPrefix(value, "file:"), "?")
		case "GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE":
			file = value
		default:
			continue
		}
		if !slices.Contains(targets, path.Dir(file)) {
			shortfalls = append(shortfalls, fmt.Sprintf(
				"service %s writes %s to %s, outside every volume it mounts, which a read-only root refuses",
				name, variable, file))
		}
	}

	if image, _ := service["image"].(string); strings.HasSuffix(image, "-latest") &&
		!strings.Contains(strings.ToLower(imageComment), "pin") {
		shortfalls = append(shortfalls, fmt.Sprintf(
			"service %s's latest tag has no comment saying to pin a version", name))
	}
	return shortfalls
}

// show renders a decoded YAML value as the failure line names it.
func show(value any) string {
	switch v := value.(type) {
	case nil:
		return "<nil>"
	case string:
		return fmt.Sprintf("%q", v)
	default:
		return fmt.Sprint(v)
	}
}

// imageHeadComment is the comment written directly above a service's image key, or "".
func imageHeadComment(root *yaml.Node, service string) string {
	node := root
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	for _, key := range []string{"services", service, "image"} {
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				if key == "image" {
					return node.Content[i].HeadComment
				}
				next = node.Content[i+1]
				break
			}
		}
		if next == nil {
			return ""
		}
		node = next
	}
	return ""
}
