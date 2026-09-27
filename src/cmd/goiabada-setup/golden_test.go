package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateGoldens rewrites testdata/*.golden from the generators: `go test ./... -update` from this
// module. A golden is the whole file an operator deploys from, so a change to any generator shows
// up here as a diff to read rather than as a line a test happened not to look for (#430).
var updateGoldens = flag.Bool("update", false, "rewrite testdata/*.golden from the generators")

// goldenCase is one reachable deployment type and engine. The name is the CLI's own spelling of
// both, so a failure names the configuration an operator would ask for.
type goldenCase struct {
	name           string
	deploymentType string
	dbType         string
}

func (c goldenCase) path() string {
	return filepath.Join("testdata", c.name+".golden")
}

// goldenCases is every deployment type by every engine it accepts: Kubernetes has no SQLite, since
// a pod's filesystem is not where an auth server's only copy of its data can live.
func goldenCases() []goldenCase {
	types := []struct {
		name, value string
		engines     []string
	}{
		{"local", "1", []string{"mysql", "postgres", "mssql", "sqlite"}},
		{"production", "2", []string{"mysql", "postgres", "mssql", "sqlite"}},
		{"kubernetes", "3", []string{"mysql", "postgres", "mssql"}},
		{"native", "4", []string{"mysql", "postgres", "mssql", "sqlite"}},
	}
	var cases []goldenCase
	for _, deploymentType := range types {
		for _, engine := range deploymentType.engines {
			cases = append(cases, goldenCase{
				name:           deploymentType.name + "-" + engine,
				deploymentType: deploymentType.value,
				dbType:         engine,
			})
		}
	}
	return cases
}

// goldenConfig is testConfig with the deployment type and the engine varied, and with every field
// main derives from those two set the way main sets it. The values are literals rather than a call
// into main's own defaults, so a later change to a default does not move a golden, and a change to
// a generator does.
func goldenConfig(deploymentType, dbType string) *Config {
	config := testConfig()
	config.DeploymentType = deploymentType
	config.DBType = dbType

	switch dbType {
	case "mysql":
		config.DBImage, config.DBPort = "mysql:latest", "3306"
	case "postgres":
		config.DBImage, config.DBPort = "postgres:latest", "5432"
	case "mssql":
		config.DBImage, config.DBPort = "mcr.microsoft.com/mssql/server:2022-latest", "1433"
	case "sqlite":
		config.DBImage, config.DBPort = "", ""
	}

	// The two Docker types ask for a database password and nothing else, since the database is a
	// service of the compose file; SQLite asks for nothing at all.
	if deploymentType == "1" || deploymentType == "2" || dbType == "sqlite" {
		config.DBHost, config.DBName, config.DBUsername = "", "", ""
	}
	if dbType == "sqlite" {
		config.DBPassword = ""
	}
	// Local testing is served on localhost whatever the operator would have typed.
	if deploymentType == "1" {
		config.AuthServerURL = "http://localhost:9090"
		config.AdminConsoleURL = "http://localhost:9091"
	}
	// Only the Kubernetes type asks for a namespace.
	if deploymentType != "3" {
		config.K8sNamespace = ""
	}
	return config
}

func TestGeneratedConfiguration_MatchesTheGoldens(t *testing.T) {
	for _, testCase := range goldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			config := goldenConfig(testCase.deploymentType, testCase.dbType)
			_, content := generatedConfiguration(config.DeploymentType, config)

			if *updateGoldens {
				if err := os.MkdirAll("testdata", 0o750); err != nil {
					t.Fatalf("creating testdata: %v", err)
				}
				if err := os.WriteFile(testCase.path(), []byte(content), 0o600); err != nil {
					t.Fatalf("writing %s: %v", testCase.path(), err)
				}
			}

			// A missing golden is a failure, never a skip: a case whose file is gone would
			// otherwise pass having compared nothing.
			want, err := os.ReadFile(testCase.path())
			if err != nil {
				t.Fatalf("reading %s: %v (regenerate with `go test ./... -update` from src/cmd/goiabada-setup)",
					testCase.path(), err)
			}
			if content != string(want) {
				t.Errorf("%s differs from the generator's output. %s\nIf the change is intended, regenerate with "+
					"`go test ./... -update` from src/cmd/goiabada-setup and read the diff.",
					testCase.path(), firstDifference(string(want), content))
			}
		})
	}
}

// A golden no case writes is a file nobody compares: it would read as pinned output while pinning
// nothing, so it fails until it is deleted. In -update mode too, since that is when a renamed case
// leaves its old file behind.
func TestGoldens_EveryFileHasACase(t *testing.T) {
	expected := map[string]bool{}
	for _, testCase := range goldenCases() {
		expected[testCase.path()] = true
	}

	found, err := filepath.Glob(filepath.Join("testdata", "*.golden"))
	if err != nil {
		t.Fatalf("listing testdata: %v", err)
	}
	sort.Strings(found)
	for _, path := range found {
		if !expected[path] {
			t.Errorf("%s is a golden no case writes; delete it or add its case", path)
		}
	}
	if len(found) == 0 {
		t.Fatalf("no golden under testdata, so this reached nothing")
	}
}

// firstDifference names the first line at which two texts part, with both versions of it, so a
// failure reads without a diff tool.
func firstDifference(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		wantLine, gotLine := "<end of file>", "<end of file>"
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if wantLine != gotLine {
			return fmt.Sprintf("First difference at line %d:\n  golden:    %s\n  generated: %s", i+1, wantLine, gotLine)
		}
	}
	return "The texts differ only in a way line splitting does not show."
}

// The two variables the admin console stopped reading. The client id is the compile-time
// constant `admin-console-client` and the issuer comes from the auth server's public
// settings, so a deployment artifact that sets either is asking an operator for a value
// they cannot choose, and the admin console now refuses to start when the issuer one is
// present at all (#285).
//
// These generators are pure and their output is what an operator pastes into a server, so
// a reintroduced line here ships silently: nothing else in the repository reads what they
// produce. Before this test the module had no tests at all, and `go test ./...` reported
// `[no test files]` with the removed lines restored.
var removedAdminConsoleVars = []string{
	"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID",
	"GOIABADA_ADMINCONSOLE_ISSUER",
}

func TestGeneratedOutputsOmitTheRemovedAdminConsoleVars(t *testing.T) {
	config := testConfig()

	// Each case names a line the generator must still emit. Absence alone would pass
	// against a generator that returned nothing, which is the way this test could go
	// quietly false as the wizard changes.
	testCases := []struct {
		name         string
		generated    string
		stillEmitted string
	}{
		{
			name:         "admin console compose service",
			generated:    generateAdminConsoleService(config),
			stillEmitted: "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=oauth-client-secret",
		},
		{
			name:         "whole compose file",
			generated:    generateDockerCompose(config),
			stillEmitted: "goiabada-adminconsole:",
		},
		{
			name:         "env file for native binaries",
			generated:    generateEnvFile(config),
			stillEmitted: `export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="oauth-client-secret"`,
		},
		{
			name:         "kubernetes manifests",
			generated:    generateKubernetesManifests(config),
			stillEmitted: "GOIABADA_ADMINCONSOLE_BASEURL: \"https://admin.example.com\"",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for _, removed := range removedAdminConsoleVars {
				if strings.Contains(testCase.generated, removed) {
					t.Errorf("output sets %s, which the admin console no longer reads", removed)
				}
			}
			if !strings.Contains(testCase.generated, testCase.stillEmitted) {
				t.Errorf("output does not contain %q, so the absence checks above proved nothing",
					testCase.stillEmitted)
			}
		})
	}
}
