package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/guard"
	"gopkg.in/yaml.v3"
)

// sampleComposeFiles are the hand-written Compose files under src/build that run the auth server,
// relative to the source root. Unlike the goldens, nothing generates them, so nothing but this test
// holds them to the startup window the generator writes.
var sampleComposeFiles = []string{
	"build/docker-compose-mssql.yml",
	"build/docker-compose-mysql.yml",
	"build/docker-compose-postgres.yml",
	"build/docker-compose-reverse-proxy.yml",
	"build/docker-compose-sqlite.yml",
}

// adminConsoleImage is the image reference every deployment file running the admin console names.
const adminConsoleImage = "leodip/goiabada:adminconsole-"

// The auth server's Compose healthcheck: five minutes for a first start to seed or an upgrade to
// migrate before a failure counts, checked every ten seconds (#390 decision 5).
const (
	composeStartPeriod = 300 * time.Second
	composeInterval    = 10 * time.Second
)

// Every sample Compose file gives the auth server five minutes to start before a failed healthcheck
// counts, checks it every ten seconds, and starts the admin console only once it is healthy. Its
// 10-second start period used to turn a seeding or migrating auth server unhealthy at about 40
// seconds and leave the admin console created but never started. The generator's files are held to
// the same values by the setup wizard's TestComposeFile_GivesTheAuthServerTimeToStart (#390
// decision 5).
func TestSampleComposeFiles_GiveTheAuthServerTimeToStart(t *testing.T) {
	assertSampleStartupWindows(t, guard.SourceRoot(t), sampleComposeFiles)
}

func TestSampleComposeFiles_AShortStartupWindowFailsNamingTheFile(t *testing.T) {
	root := t.TempDir()
	writeDeploymentFixture(t, root, "build/docker-compose-short.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    healthcheck:
      interval: 10s
      start_period: 10s
  console:
    image: leodip/goiabada:adminconsole-latest
    depends_on:
      auth:
        condition: service_healthy
`)
	writeDeploymentFixture(t, root, "build/docker-compose-slow.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    healthcheck:
      interval: 30s
      start_period: 300s
  console:
    image: leodip/goiabada:adminconsole-latest
    depends_on:
      auth:
        condition: service_healthy
`)
	writeDeploymentFixture(t, root, "build/docker-compose-unchecked.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
  console:
    image: leodip/goiabada:adminconsole-latest
    depends_on:
      auth:
        condition: service_healthy
`)
	writeDeploymentFixture(t, root, "build/docker-compose-eager.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    healthcheck:
      interval: 10s
      start_period: 300s
  console:
    image: leodip/goiabada:adminconsole-latest
    depends_on:
      - auth
`)
	writeDeploymentFixture(t, root, "build/docker-compose-enough.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    healthcheck:
      interval: 10s
      start_period: 300s
  console:
    image: leodip/goiabada:adminconsole-latest
    depends_on:
      auth:
        condition: service_healthy
  unrelated:
    image: postgres:18
`)
	files := []string{
		"build/docker-compose-short.yml",
		"build/docker-compose-slow.yml",
		"build/docker-compose-unchecked.yml",
		"build/docker-compose-eager.yml",
		"build/docker-compose-enough.yml",
	}

	report := guard.Run(func(r guard.Reporter) {
		assertSampleStartupWindows(r, root, files)
	})

	if report.Stopped {
		t.Fatalf("the walk stopped rather than reporting: %s", report.Fatal)
	}
	text := report.Text()
	for _, want := range []string{
		"build/docker-compose-short.yml: service auth has start_period 10s",
		"build/docker-compose-slow.yml: service auth has interval 30s",
		"build/docker-compose-unchecked.yml: service auth has no healthcheck",
		"build/docker-compose-eager.yml: service console does not wait for auth to be healthy",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no failure says %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"docker-compose-enough.yml", "unrelated"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failure names %s, which gives the auth server its startup window or runs neither server:\n%s", unwanted, text)
		}
	}
	if len(report.Errors) != 4 {
		t.Errorf("%d failures, want 4:\n%s", len(report.Errors), text)
	}
}

func TestSampleComposeFiles_AMissingSampleFails(t *testing.T) {
	root := t.TempDir()
	writeDeploymentFixture(t, root, "build/docker-compose-sqlite.yml", `
services:
  auth:
    image: leodip/goiabada:authserver-latest
    healthcheck:
      interval: 10s
      start_period: 300s
`)

	report := guard.Run(func(r guard.Reporter) {
		assertSampleStartupWindows(r, root, []string{"build/docker-compose-sqlite.yml", "build/docker-compose-mysql.yml"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "build/docker-compose-mysql.yml") {
		t.Errorf("a sample that is not there did not stop the walk naming it: %+v", report)
	}
}

// assertSampleStartupWindows is the reporting half: one failure per service falling short, and a
// stop when a file is missing or runs no auth server, so a sample renamed or emptied fails the test
// rather than leaving it nothing to read.
func assertSampleStartupWindows(r guard.Reporter, root string, files []string) {
	r.Helper()
	for _, file := range files {
		shortfalls, err := startupWindowShortfalls(root, file)
		if err != nil {
			r.Fatalf("%s: %v", file, err)
		}
		for _, shortfall := range shortfalls {
			r.Errorf("%s: %s", file, shortfall)
		}
	}
}

// startupWindowShortfalls reads one Compose file and returns one line per auth server service whose
// healthcheck does not give it the startup window, and per admin console service that does not wait
// for an auth server to be healthy.
func startupWindowShortfalls(root, file string) ([]string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	var shortfalls []string
	authServers := 0
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		services, _ := doc["services"].(map[string]any)

		var authNames []string
		for name, s := range services {
			service, _ := s.(map[string]any)
			if !imageIs(service, authServerImage) {
				continue
			}
			authServers++
			authNames = append(authNames, name)
			shortfalls = append(shortfalls, healthcheckShortfalls(name, service)...)
		}
		for name, s := range services {
			service, _ := s.(map[string]any)
			if !imageIs(service, adminConsoleImage) {
				continue
			}
			for _, auth := range authNames {
				if mapAt(service, "depends_on", auth)["condition"] != "service_healthy" {
					shortfalls = append(shortfalls, fmt.Sprintf(
						"service %s does not wait for %s to be healthy, so it starts against an auth server still migrating",
						name, auth))
				}
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

// healthcheckShortfalls is what one auth server service's healthcheck lacks of the startup window.
func healthcheckShortfalls(name string, service map[string]any) []string {
	healthcheck, ok := service["healthcheck"].(map[string]any)
	if !ok {
		return []string{fmt.Sprintf("service %s has no healthcheck, so nothing waits for it to start", name)}
	}
	var shortfalls []string
	for _, want := range []struct {
		key   string
		value time.Duration
	}{
		{"start_period", composeStartPeriod},
		{"interval", composeInterval},
	} {
		raw, ok := healthcheck[want.key]
		if !ok {
			shortfalls = append(shortfalls, fmt.Sprintf("service %s has no %s, want %s", name, want.key, want.value))
			continue
		}
		got, err := time.ParseDuration(fmt.Sprint(raw))
		if err != nil || got != want.value {
			shortfalls = append(shortfalls, fmt.Sprintf("service %s has %s %v, want %s", name, want.key, raw, want.value))
		}
	}
	return shortfalls
}
