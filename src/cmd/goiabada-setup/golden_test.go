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
// module. A golden is a whole file an operator deploys from, the description and, beside it, the
// secrets file, so a change to any generator shows up here as a diff to read rather than as a line
// a test happened not to look for (#430, #396 decision 14).
var updateGoldens = flag.Bool("update", false, "rewrite testdata/*.golden from the generators")

// goldenCase is one reachable deployment type and engine. The name is the CLI's own spelling of
// both, so a failure names the configuration an operator would ask for.
type goldenCase struct {
	name       string
	deployment deploymentType
	engine     string
	// hostile cases carry hostileConfig's values, one per generated format.
	hostile bool
	// answers, when set, changes the answers to the questions only some deployments ask from the
	// defaults goldenConfig gives them, so each answer has a golden of its own.
	answers func(config *Config)
}

func (c goldenCase) path() string {
	return filepath.Join("testdata", c.name+".golden")
}

// secretsPath is the golden of the case's secrets file, for a deployment type that writes its
// secrets apart from its description.
func (c goldenCase) secretsPath() string {
	return filepath.Join("testdata", c.name+".secrets.golden")
}

// goldenFiles are the case's goldens, each with the generated file it holds: the description, and
// the secrets file when it is a file of its own.
func (c goldenCase) goldenFiles() map[string]generatedFile {
	description, secrets := generatedConfiguration(c.config())
	files := map[string]generatedFile{c.path(): description}
	if secrets != description {
		files[c.secretsPath()] = secrets
	}
	return files
}

// descriptionOf is the generated file describing the configuration's deployment.
func descriptionOf(config *Config) string {
	description, _ := generatedConfiguration(config)
	return description.content
}

// goldenCases is every deployment type by every engine it accepts, read from the two tables: a row
// added to either asks for its goldens, and an engine a type stops accepting leaves a golden no
// case writes, which TestGoldens_EveryFileHasACase refuses. Kubernetes has no SQLite.
func goldenCases() []goldenCase {
	var cases []goldenCase
	for _, d := range deployments {
		for _, e := range d.acceptedEngines() {
			cases = append(cases, goldenCase{name: d.name + "-" + e.name, deployment: d.kind, engine: e.name})
		}
	}
	cases = append(cases, answerCases...)
	return append(cases, hostileCases...)
}

// answerCases are one configuration for each answer to a deployment's own question that differs
// from the default goldenConfig gives it.
var answerCases = []goldenCase{
	// Native binaries with no reverse proxy on the same machine (#396 decision 7).
	{name: "native-direct-postgres", deployment: deploymentNative, engine: "postgres", answers: func(c *Config) { c.LocalProxy = false }},
	// Kubernetes behind Envoy with the Local traffic policy (#396 decision 4).
	// The rate limiter is on by default under Local (#396 decision 9).
	{name: "kubernetes-local-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.GatewayTrafficPolicy = trafficPolicyLocal
		c.RateLimiter = true
	}},
	// Kubernetes with the NetworkPolicies admitting only Envoy and the admin console (#396 decision 5).
	{name: "kubernetes-network-policy-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.NetworkPolicy = true
	}},
	// The rate limiter answered against its default: off for production Compose and native
	// binaries, on for Kubernetes under the Cluster traffic policy (#396 decision 9).
	{name: "production-no-rate-limiter-postgres", deployment: deploymentProduction, engine: "postgres", answers: func(c *Config) {
		c.RateLimiter = false
	}},
	{name: "native-no-rate-limiter-postgres", deployment: deploymentNative, engine: "postgres", answers: func(c *Config) {
		c.RateLimiter = false
	}},
	{name: "kubernetes-rate-limiter-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.RateLimiter = true
	}},
	// Kubernetes exposing its metrics to a scraper that reads pod annotations, and to the Prometheus
	// Operator through a PodMonitor, with and without the labels its Prometheus selects by (#400
	// decision 7).
	{name: "kubernetes-metrics-annotations-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.Metrics = metricsAnnotations
	}},
	{name: "kubernetes-metrics-podmonitor-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.Metrics = metricsPodMonitor
	}},
	{name: "kubernetes-metrics-podmonitor-labels-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.Metrics = metricsPodMonitor
		c.PodMonitorLabels = []podMonitorLabel{{"release", "kube-prometheus-stack"}}
	}},
	// Metrics with the NetworkPolicies on, which admit the scraper's namespace, monitoring by
	// default, to the metrics port alone (#400 decision 8).
	{name: "kubernetes-metrics-network-policy-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.Metrics = metricsPodMonitor
		c.NetworkPolicy = true
		c.MetricsNamespace = "monitoring"
	}},
	// A verifying TLS mode with a CA file: native binaries name the file's absolute path, and
	// Kubernetes carries its PEM in a ConfigMap mounted into the auth server's pod (#502 decisions 7
	// and 8). verify-ca with no CA file checks against the system's roots and names no file.
	{name: "native-verify-full-postgres", deployment: deploymentNative, engine: "postgres", answers: func(c *Config) {
		c.DBTLSMode, c.DBTLSCAFile, c.DBTLSCA = "verify-full", "/etc/ssl/goiabada/db-ca.pem", goldenCA()
	}},
	{name: "kubernetes-verify-full-postgres", deployment: deploymentKubernetes, engine: "postgres", answers: func(c *Config) {
		c.DBTLSMode, c.DBTLSCAFile, c.DBTLSCA = "verify-full", "/home/operator/db-ca.pem", goldenCA()
	}},
	{name: "kubernetes-verify-ca-mysql", deployment: deploymentKubernetes, engine: "mysql", answers: func(c *Config) {
		c.DBTLSMode = "verify-ca"
	}},
}

// goldenCA is the test authority's certificate, which the CA file's goldens carry.
func goldenCA() string {
	content, err := os.ReadFile(testCAFile)
	if err != nil {
		panic(err)
	}
	return string(content)
}

// hostileCases are one configuration per format, Compose, Kubernetes and the env file, whose
// free-text answers are hostileConfig's. SQL Server's Compose service is the one whose password
// the healthcheck used to carry inside a shell-quoted YAML string.
var hostileCases = []goldenCase{
	{name: "hostile-compose", deployment: deploymentProduction, engine: "mssql", hostile: true},
	{name: "hostile-kubernetes", deployment: deploymentKubernetes, engine: "postgres", hostile: true},
	{name: "hostile-env", deployment: deploymentNative, engine: "mysql", hostile: true},
}

func (c goldenCase) config() *Config {
	config := goldenConfig(c.deployment, c.engine)
	if c.answers != nil {
		c.answers(config)
	}
	if c.hostile {
		hostileConfig(config)
	}
	return config
}

// hostileConfig sets every answer that can carry any character to a value built from the shapes
// hostileValues lists: the passwords and the database username are free text, the admin email
// passes a check that looks only for an `@` and a dot, and a URL is checked up to its host, so its
// path can hold anything. Host, port, database name and namespace are validated to safe characters
// and keep goldenConfig's values; the generated keys are hex and alphanumeric.
func hostileConfig(config *Config) {
	config.AdminPassword = "pa\"ss'$HOME`id`\\x #y: z${HOME}$$\n*- ~ yes\t\u2028end\\"
	config.AdminEmail = "a\"b$c`d\\e #f'g@example.com"
	config.AuthServerURL = "https://auth.example.com/p\"a$HOME #x: y"
	config.AdminConsoleURL = "https://admin.example.com/`id`\\q'r ${PATH}"
	if config.Engine.hasServer {
		config.DBPassword = "db: \"pw\" #1 $(id) `x` \\n \r\n{a: [b]} 0123"
	}
	if config.DBUsername != "" {
		config.DBUsername = "us\"er\\na$me #x: '"
	}
	// The CA file's path is the operator's, written by native binaries alone.
	if config.Deployment.kind == deploymentNative && config.Engine.hasServer {
		config.DBTLSMode = "verify-ca"
		config.DBTLSCAFile = "/etc/ssl/\"db\" $HOME `id` #x: ca's.pem"
	}
}

// goldenConfig is testConfig with the deployment type and the engine varied, and with every field
// main derives from those two set the way main sets it. The values are literals rather than a call
// into main's own defaults, so a later change to a default does not move a golden, and a change to
// a generator does.
func goldenConfig(kind deploymentType, engineName string) *Config {
	config := testConfig()
	config.Deployment = deployments[kind]
	config.Engine = testEngine(engineName)

	switch engineName {
	case "mysql":
		config.DBPort = "3306"
	case "postgres":
		config.DBPort = "5432"
	case "mssql":
		config.DBPort = "1433"
	case "sqlite":
		config.DBPort = ""
	}

	// The two Docker types ask for a database password and nothing else, since the database is a
	// service of the compose file; SQLite asks for nothing at all.
	if kind == deploymentLocal || kind == deploymentProduction || engineName == "sqlite" {
		config.DBHost, config.DBName, config.DBUsername = "", "", ""
	}
	if engineName == "sqlite" {
		config.DBPassword = ""
	}
	// Local testing is served on localhost whatever the operator would have typed.
	if kind == deploymentLocal {
		config.AuthServerURL = "http://localhost:9090"
		config.AdminConsoleURL = "http://localhost:9091"
	}
	// Only the Kubernetes type asks for a namespace.
	if kind != deploymentKubernetes {
		config.K8sNamespace = ""
	}
	// Only native binaries ask whether a reverse proxy on the same machine forwards to them, and
	// the default answer is yes.
	config.LocalProxy = kind == deploymentNative
	// Only Kubernetes asks which traffic policy the gateway uses, Cluster by default, and whether to
	// restrict who reaches the servers, no by default.
	config.GatewayTrafficPolicy = ""
	if kind == deploymentKubernetes {
		config.GatewayTrafficPolicy = trafficPolicyCluster
	}
	config.NetworkPolicy = false
	// Production Compose, native binaries and Kubernetes ask whether to turn the rate limiter on,
	// yes by default but for Kubernetes under the Cluster traffic policy; local testing never asks.
	config.RateLimiter = kind == deploymentProduction || kind == deploymentNative
	// Only Kubernetes asks whether to expose the metrics, none by default, and the scraper's
	// namespace only with the NetworkPolicies on.
	config.Metrics = ""
	if kind == deploymentKubernetes {
		config.Metrics = metricsNone
	}
	config.PodMonitorLabels = nil
	config.MetricsNamespace = ""
	// The two types reaching the operator's database ask its TLS mode, prefer by default, and a CA
	// file only for verify-ca and verify-full; Compose writes prefer and asks nothing (#502).
	config.DBTLSMode, config.DBTLSCAFile, config.DBTLSCA = "", "", ""
	if config.Engine.hasServer {
		config.DBTLSMode = "prefer"
	}
	return config
}

func TestGeneratedConfiguration_MatchesTheGoldens(t *testing.T) {
	for _, testCase := range goldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			for path, file := range testCase.goldenFiles() {
				content := file.content
				if *updateGoldens {
					if err := os.MkdirAll("testdata", 0o750); err != nil {
						t.Fatalf("creating testdata: %v", err)
					}
					if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
						t.Fatalf("writing %s: %v", path, err)
					}
				}

				// A missing golden is a failure, never a skip: a case whose file is gone would
				// otherwise pass having compared nothing.
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("reading %s: %v (regenerate with `go test ./... -update` from src/cmd/goiabada-setup)",
						path, err)
				}
				if content != string(want) {
					t.Errorf("%s differs from the generator's output. %s\nIf the change is intended, regenerate with "+
						"`go test ./... -update` from src/cmd/goiabada-setup and read the diff.",
						path, firstDifference(string(want), content))
				}
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
		for path := range testCase.goldenFiles() {
			expected[path] = true
		}
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
			stillEmitted: "GOIABADA_ADMINCONSOLE_BASEURL=https://admin.example.com",
		},
		{
			name:         "compose override",
			generated:    generateComposeOverride(config, deployments[deploymentProduction].defaultPaths()),
			stillEmitted: "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=oauth-client-secret",
		},
		{
			name:         "whole compose file",
			generated:    generateDockerCompose(config, deployments[deploymentProduction].defaultPaths()),
			stillEmitted: "goiabada-adminconsole:",
		},
		{
			name:         "env file for native binaries",
			generated:    generateEnvFile(config, deployments[deploymentNative].defaultPaths()),
			stillEmitted: `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="oauth-client-secret"`,
		},
		{
			name:         "kubernetes manifests",
			generated:    generateKubernetesManifests(config, deployments[deploymentKubernetes].defaultPaths()),
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
