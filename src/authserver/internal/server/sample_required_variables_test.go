package server

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"gopkg.in/yaml.v3"
)

// sampleRequiredVariables are the auth server variables no sample Compose file may give a value:
// each must be a required interpolation of itself, so Compose refuses every command until the
// operator sets it, rather than the sample publishing one value every deployment copied from it
// shares. The admin password seeds a full administrator on the first start (#500).
var sampleRequiredVariables = []string{
	"GOIABADA_ADMIN_PASSWORD",
}

// Every sample Compose file requires the admin password through Compose's required interpolation,
// `${GOIABADA_ADMIN_PASSWORD:?message}`, which refuses an unset or empty variable before any
// container or volume is created. The samples used to set it to changeme, a password this project
// published, which seeded an administrator holding authserver:manage (#500 decision 3).
func TestSampleComposeFiles_RequireTheVariablesTheyMustNotPublish(t *testing.T) {
	assertSampleRequiredVariables(t, guard.SourceRoot(t), sampleComposeFiles, sampleRequiredVariables)
}

func TestSampleComposeFiles_AVariableNotRequiredFailsNamingTheFile(t *testing.T) {
	root := t.TempDir()
	writeDeploymentFixture(t, root, "build/docker-compose-literal.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      - GOIABADA_ADMIN_EMAIL=admin@example.com
      - GOIABADA_ADMIN_PASSWORD=changeme
`)
	writeDeploymentFixture(t, root, "build/docker-compose-missing.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      - GOIABADA_ADMIN_EMAIL=admin@example.com
`)
	writeDeploymentFixture(t, root, "build/docker-compose-defaulted.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      GOIABADA_ADMIN_PASSWORD: ${GOIABADA_ADMIN_PASSWORD:-changeme}
`)
	writeDeploymentFixture(t, root, "build/docker-compose-optional.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      - GOIABADA_ADMIN_PASSWORD=${GOIABADA_ADMIN_PASSWORD}
`)
	writeDeploymentFixture(t, root, "build/docker-compose-emptyallowed.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      - GOIABADA_ADMIN_PASSWORD=${GOIABADA_ADMIN_PASSWORD?set it}
`)
	writeDeploymentFixture(t, root, "build/docker-compose-other.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      - GOIABADA_ADMIN_PASSWORD=${ADMIN_PASSWORD:?set it}
`)
	writeDeploymentFixture(t, root, "build/docker-compose-passthrough.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      - GOIABADA_ADMIN_PASSWORD
`)
	writeDeploymentFixture(t, root, "build/docker-compose-required.yml", `
services:
  db:
    image: postgres:18
    environment:
      POSTGRES_PASSWORD: abc123
  auth:
    image: leodip/goiabada:authserver-latest
    environment:
      - GOIABADA_ADMIN_PASSWORD=${GOIABADA_ADMIN_PASSWORD:?set GOIABADA_ADMIN_PASSWORD to the first administrator's password, at least 15 characters}
  auth-map:
    image: leodip/goiabada:authserver-1.5.0
    environment:
      GOIABADA_ADMIN_PASSWORD: ${GOIABADA_ADMIN_PASSWORD:?set it}
`)
	files := []string{
		"build/docker-compose-literal.yml",
		"build/docker-compose-missing.yml",
		"build/docker-compose-defaulted.yml",
		"build/docker-compose-optional.yml",
		"build/docker-compose-emptyallowed.yml",
		"build/docker-compose-other.yml",
		"build/docker-compose-passthrough.yml",
		"build/docker-compose-required.yml",
	}

	report := guard.Run(func(r guard.Reporter) {
		assertSampleRequiredVariables(r, root, files, []string{"GOIABADA_ADMIN_PASSWORD"})
	})

	if report.Stopped {
		t.Fatalf("the walk stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	want := []string{
		`build/docker-compose-literal.yml: service auth sets GOIABADA_ADMIN_PASSWORD to "changeme", want ${GOIABADA_ADMIN_PASSWORD:?<message>}`,
		`build/docker-compose-missing.yml: service auth does not set GOIABADA_ADMIN_PASSWORD, want ${GOIABADA_ADMIN_PASSWORD:?<message>}`,
		`build/docker-compose-defaulted.yml: service auth sets GOIABADA_ADMIN_PASSWORD to "${GOIABADA_ADMIN_PASSWORD:-changeme}", want ${GOIABADA_ADMIN_PASSWORD:?<message>}`,
		`build/docker-compose-optional.yml: service auth sets GOIABADA_ADMIN_PASSWORD to "${GOIABADA_ADMIN_PASSWORD}", want ${GOIABADA_ADMIN_PASSWORD:?<message>}`,
		`build/docker-compose-emptyallowed.yml: service auth sets GOIABADA_ADMIN_PASSWORD to "${GOIABADA_ADMIN_PASSWORD?set it}", want ${GOIABADA_ADMIN_PASSWORD:?<message>}`,
		`build/docker-compose-other.yml: service auth sets GOIABADA_ADMIN_PASSWORD to "${ADMIN_PASSWORD:?set it}", want ${GOIABADA_ADMIN_PASSWORD:?<message>}`,
		`build/docker-compose-passthrough.yml: service auth passes GOIABADA_ADMIN_PASSWORD through unchecked, want ${GOIABADA_ADMIN_PASSWORD:?<message>}`,
	}
	for _, line := range want {
		if !strings.Contains(text, line) {
			t.Errorf("no failure says %q:\n%s", line, text)
		}
	}
	if strings.Contains(text, "docker-compose-required.yml") {
		t.Errorf("a failure names docker-compose-required.yml, which requires the variable:\n%s", text)
	}
	if len(report.Errors) != len(want) {
		t.Errorf("%d failures, want %d:\n%s", len(report.Errors), len(want), text)
	}
}

func TestSampleComposeFiles_ARequiredVariablesWalkFindingNothingFails(t *testing.T) {
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
			assertSampleRequiredVariables(r, root, files, sampleRequiredVariables)
		})
		if !report.Stopped || !strings.Contains(report.Fatal, files[0]) {
			t.Errorf("a sample that is missing or runs no auth server did not stop the walk naming it: %+v", report)
		}
	}

	report := guard.Run(func(r guard.Reporter) {
		assertSampleRequiredVariables(r, root, nil, sampleRequiredVariables)
	})
	if !report.Stopped {
		t.Errorf("a walk given no sample did not stop: %+v", report)
	}
	report = guard.Run(func(r guard.Reporter) {
		assertSampleRequiredVariables(r, root, sampleComposeFiles, nil)
	})
	if !report.Stopped {
		t.Errorf("a walk given no variable did not stop: %+v", report)
	}
}

// assertSampleRequiredVariables is the reporting half: one failure per auth server service that
// does not require a variable, and a stop when there is nothing to check, a file is missing, or a
// file runs no auth server, so a sample renamed or emptied fails rather than passing unread.
func assertSampleRequiredVariables(r guard.Reporter, root string, files, variables []string) {
	r.Helper()
	if len(files) == 0 || len(variables) == 0 {
		r.Fatalf("nothing to check: %d sample files, %d variables", len(files), len(variables))
	}
	for _, file := range files {
		shortfalls, err := requiredVariableShortfalls(root, file, variables)
		if err != nil {
			r.Fatalf("%s: %v", file, err)
		}
		for _, shortfall := range shortfalls {
			r.Errorf("%s: %s", file, shortfall)
		}
	}
}

// requiredVariableShortfalls reads one single-document Compose file and returns one line per auth
// server service and variable whose value is anything but `${VARIABLE:?message}`: the colon is what
// makes Compose refuse an empty value as well as an unset one.
func requiredVariableShortfalls(root, file string, variables []string) ([]string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, err
	}
	services, _ := doc["services"].(map[string]any)

	var shortfalls []string
	authServers := 0
	for name, s := range services {
		service, _ := s.(map[string]any)
		if !imageIs(service, authServerImage) {
			continue
		}
		authServers++
		environment := composeEnvironment(service["environment"])
		for _, variable := range variables {
			want := fmt.Sprintf("want ${%s:?<message>}", variable)
			value, set := environment[variable]
			required := regexp.MustCompile(`^\$\{` + regexp.QuoteMeta(variable) + `:\?[^}]+\}$`)
			switch {
			case !set:
				shortfalls = append(shortfalls, fmt.Sprintf("service %s does not set %s, %s", name, variable, want))
			case value == nil:
				shortfalls = append(shortfalls, fmt.Sprintf("service %s passes %s through unchecked, %s", name, variable, want))
			case !required.MatchString(*value):
				shortfalls = append(shortfalls, fmt.Sprintf("service %s sets %s to %q, %s", name, variable, *value, want))
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

// composeEnvironment reads a service's environment in either of Compose's two forms, a list of
// `KEY=value` or a mapping, into one map; a nil value is a variable passed through from the shell.
func composeEnvironment(raw any) map[string]*string {
	environment := map[string]*string{}
	switch entries := raw.(type) {
	case []any:
		for _, e := range entries {
			entry := fmt.Sprint(e)
			if key, value, ok := strings.Cut(entry, "="); ok {
				environment[key] = &value
			} else {
				environment[entry] = nil
			}
		}
	case map[string]any:
		for key, v := range entries {
			if v == nil {
				environment[key] = nil
				continue
			}
			value := fmt.Sprint(v)
			environment[key] = &value
		}
	}
	return environment
}
