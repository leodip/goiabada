package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
	"go.yaml.in/yaml/v3"
)

// The answers file records the answers a run generated its files from, and nothing secret, so it
// can be committed beside the description. A later run reads it back with --answers in place of
// prompts, and --keep-secrets writes the description again without touching the secrets file: an
// upgrade becomes the new release's wizard run over the answers, a review of the diff, and an apply
// (#686 section 4). Each answer is under the name of the flag that gives it, so a flag beside
// --answers replaces it. Kubernetes and both Compose types write one; native binaries keep every
// setting and every secret in one file, which no run can write again without new secrets.
const (
	answersFile   = "goiabada-setup.yaml"
	answersSuffix = "-setup"
	// answersVersion is the answers file's format. A run refuses a file of any other, rather than
	// read answers it might misunderstand.
	answersVersion = 1
	// answersFileMax bounds what an answers file is read to: its answers, with a CA bundle, are far
	// shorter.
	answersFileMax = 1 << 20
)

// answerDeploymentNames are the deployment types an answers file and --keep-secrets are for: each
// that keeps its secrets in a file of their own.
func answerDeploymentNames() []string {
	var names []string
	for _, d := range deployments {
		if d.secretsFile != "" {
			names = append(names, d.name)
		}
	}
	return names
}

// answersFileBeside is the name of the answers file beside a description --output names name: name
// with -setup before its extension.
func answersFileBeside(name string) string {
	extension := filepath.Ext(name)
	return strings.TrimSuffix(name, extension) + answersSuffix + extension
}

// refusedAnswers are the flags an answers file never holds, each with the reason a run gives for
// refusing it: how one run writes, and the secrets, which only the secrets file holds.
var refusedAnswers = map[string]string{ //nolint:gosec // G101: the keys are flag names and the values the reasons for refusing them, no credential
	"answers":                 "names an answers file, which another cannot",
	"keep-secrets":            "says how one run writes, which is not an answer: give it as a flag",
	"output":                  "says where one run writes, which is not an answer: give it as a flag",
	"o":                       "says where one run writes, which is not an answer: give it as a flag",
	"overwrite":               "says how one run writes, which is not an answer: give it as a flag",
	"no-color":                "says how one run prints, which is not an answer: give it as a flag",
	"skip-db-test":            "says what one run checks, which is not an answer: give it as a flag",
	"v":                       "is not an answer",
	"admin-password":          "is a secret, which an answers file never holds: give it as a flag",
	"admin-password-file":     "names a secret, which an answers file never holds: give it as a flag",
	"db-password":             "is a secret, which an answers file never holds: give it as a flag",
	"db-password-file":        "names a secret, which an answers file never holds: give it as a flag",
	"db-tls-client-cert-file": "names a secret's file, which an answers file never holds: db-tls-client-cert says one is presented",
	"db-tls-client-key-file":  "names a secret's file, which an answers file never holds: db-tls-client-cert says one is presented",
	"db-tls-ca-file":          "names a file, and the answers file holds its certificates instead, as db-tls-ca",
}

// answer is one answer an answers file holds, with the line it is on.
type answer struct {
	key, value string
	line       int
}

// loadAnswers reads the flags from the answers file at path and then from args, the command line,
// so a flag given there replaces the answer of its name. Each answer is set through its flag, and
// refused as the flag would refuse it. db-tls-ca and db-tls-client-cert stand for the CA file and
// the client certificate's files, and give way to them in turn when they are given, empty ones
// included: --db-tls-ca-file= returns to the system's roots, and empty client certificate files to
// presenting none.
func loadAnswers(args []string, path string) (*CLIFlags, error) {
	answers, err := readAnswers(path)
	if err != nil {
		return nil, err
	}
	flags := &CLIFlags{}
	fs := newFlagSet(flags, io.Discard)
	for _, a := range answers {
		where := fmt.Sprintf("%s, line %d", path, a.line)
		switch a.key {
		case "db-tls-ca":
			flags.DBTLSCA = pemCertificates([]byte(a.value))
			if flags.DBTLSCA == "" {
				return nil, errs.Errorf("%s: db-tls-ca holds no PEM certificate", where)
			}
		case "db-tls-client-cert":
			if flags.DBTLSClientCertKept, err = strconv.ParseBool(a.value); err != nil {
				return nil, errs.Errorf("%s: db-tls-client-cert is %q, which is neither true nor false", where, a.value)
			}
		default:
			if err := fs.Set(a.key, a.value); err != nil {
				return nil, errs.Errorf("%s: invalid %s %q: %v", where, a.key, a.value, err)
			}
		}
	}
	if flags.DeploymentType == "" {
		return nil, errs.Errorf("%s has no type: an answers file names the deployment type it answers for", path)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	// The flags the command line gives, which fs cannot tell from those the answers set.
	given := map[string]bool{}
	commandLine := newFlagSet(&CLIFlags{}, io.Discard)
	if err := commandLine.Parse(args); err != nil {
		return nil, err
	}
	commandLine.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if given["db-tls-ca-file"] {
		flags.DBTLSCA = ""
	}
	if given["db-tls-client-cert-file"] || given["db-tls-client-key-file"] {
		flags.DBTLSClientCertKept = false
	}
	return flags, nil
}

// readAnswers reads the answers file at path: one YAML mapping of single values, its format's
// version among them, and each other key an answer the wizard knows, given once.
func readAnswers(path string) ([]answer, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the operator names the answers file to read
	if err != nil {
		return nil, errs.Wrap(err, "unable to read --answers")
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, answersFileMax+1))
	if err != nil {
		return nil, errs.Wrap(err, "unable to read --answers")
	}
	if len(content) > answersFileMax {
		return nil, errs.Errorf("%s holds more than %d bytes, which no answers file needs", path, answersFileMax)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return nil, errs.Errorf("%s is not YAML the wizard can read: %v", path, err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errs.Errorf("%s is not an answers file: it holds no mapping of answers", path)
	}
	fields := document.Content[0].Content
	known := newFlagSet(&CLIFlags{}, io.Discard)
	seen := map[string]int{}
	var answers []answer
	version := ""
	for i := 0; i+1 < len(fields); i += 2 {
		key, value := fields[i], fields[i+1]
		where := fmt.Sprintf("%s, line %d", path, key.Line)
		if key.Kind != yaml.ScalarNode {
			return nil, errs.Errorf("%s: a key is not a name", where)
		}
		if line, twice := seen[key.Value]; twice {
			return nil, errs.Errorf("%s: %s is answered twice, first on line %d", where, key.Value, line)
		}
		seen[key.Value] = key.Line
		if value.Kind != yaml.ScalarNode {
			return nil, errs.Errorf("%s: %s is not a single value", where, key.Value)
		}
		switch reason, refused := refusedAnswers[key.Value]; {
		case key.Value == "version":
			version = value.Value
			continue
		case refused:
			return nil, errs.Errorf("%s: %s %s", where, key.Value, reason)
		case key.Value != "db-tls-ca" && key.Value != "db-tls-client-cert" && known.Lookup(key.Value) == nil:
			return nil, errs.Errorf("%s: %s is no answer the wizard knows", where, key.Value)
		}
		answers = append(answers, answer{key: key.Value, value: value.Value, line: key.Line})
	}
	if version == "" {
		return nil, errs.Errorf("%s has no version: an answers file starts with version: %d", path, answersVersion)
	}
	if version != strconv.Itoa(answersVersion) {
		return nil, errs.Errorf("%s is version %s, and this wizard reads version %d alone: run the release that wrote it, or a later one", path, version, answersVersion)
	}
	return answers, nil
}

// generateAnswers writes the answers the configuration was generated from, in the order the wizard
// asks them, each one the questions answered before it lead to, defaults included: a later release
// whose default changed then still writes what this deployment runs, and a question it adds shows
// in the diff with the answer it took. Every value the operator gave is quoted, as in every file the
// wizard writes (#430); the CA's certificates are a literal block, whose lines PEM never starts with
// anything YAML reads.
func generateAnswers(config *Config, paths outputPaths) string {
	var sb strings.Builder
	description := filepath.Base(paths.description)
	sb.WriteString("# Generated by goiabada-setup: the answers " + description + " was generated from.\n")
	sb.WriteString("# It holds no secret, and can be committed beside it.\n")
	sb.WriteString("#\n")
	fmt.Fprintf(&sb, "# To generate %s again, from a new release of the wizard or a changed answer,\n", description)
	fmt.Fprintf(&sb, "# leaving %s as it is, run the setup wizard from the directory holding\n", filepath.Base(paths.secrets))
	sb.WriteString("# them, with these flags:\n")
	fmt.Fprintf(&sb, "#   %s\n", regenerateFlags(config.Deployment, paths))
	sb.WriteString("# A flag given beside --answers replaces the answer of its name.\n")
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "version: %d\n", answersVersion)

	text := func(key, value string) { fmt.Fprintf(&sb, "%s: %s\n", key, yamlQuote(value)) }
	boolean := func(key string, value bool) { fmt.Fprintf(&sb, "%s: %t\n", key, value) }
	number := func(key string, value int) { fmt.Fprintf(&sb, "%s: %d\n", key, value) }

	d := config.Deployment
	text("type", d.name)
	text("db", config.Engine.name)
	if d.asksURLs {
		text("auth-url", config.AuthServerURL)
		text("admin-url", config.AdminConsoleURL)
	}
	if d.asksNamespace {
		text("namespace", config.K8sNamespace)
		boolean("create-namespace", !config.NamespaceExists)
	}
	if d.asksRouting {
		text("routing", string(config.Routing))
		switch config.Routing {
		case routingGateway:
			text("gateway-class", config.GatewayClass)
		case routingExistingGateway:
			text("gateway-name", config.GatewayName)
			text("gateway-namespace", config.GatewayNamespace)
			text("auth-listener", config.AuthListener)
			text("admin-listener", config.AdminListener)
		case routingIngress:
			text("ingress-class", config.IngressClass)
		}
		if config.asksTLS() {
			text("tls", string(config.TLS))
			if config.issuesWithCertManager() {
				text("tls-issuer", config.TLSIssuer)
			}
			if config.TLS == tlsSecrets {
				text("auth-tls-secret", config.TLSSecretAuth)
				text("admin-tls-secret", config.TLSSecretAdmin)
			}
		}
		if config.Routing == routingGateway {
			number("gateway-http-port", config.GatewayHTTPPort)
			if config.endsTLS() {
				number("gateway-https-port", config.GatewayHTTPSPort)
			}
		}
		if config.servedByEnvoyGateway() {
			text("gateway-traffic-policy", strings.ToLower(string(config.GatewayTrafficPolicy)))
		}
		boolean("network-policy", config.NetworkPolicy)
		if config.NetworkPolicy {
			text("proxy-namespace", config.ProxyNamespace)
			text("mesh-ports", joinPorts(config.MeshPorts))
		}
	}
	if d.kind == deploymentKubernetes {
		number("authserver-replicas", config.AuthServerReplicas)
	}
	if d.asksRateLimiter {
		boolean("rate-limiter", config.RateLimiter)
	}
	if d.asksMetrics {
		text("metrics", string(config.Metrics))
		if config.Metrics == metricsPodMonitor {
			text("podmonitor-labels", joinPairs(config.PodMonitorLabels))
		}
		if config.admitsMetricsScraper() {
			text("metrics-namespace", config.MetricsNamespace)
		}
	}
	if d.asksImages {
		text("image-repository", config.ImageRepository)
		boolean("image-digest", config.ImageDigest)
		if d.kind == deploymentKubernetes {
			text("image-pull-secret", config.ImagePullSecret)
		}
	}
	if d.kind == deploymentKubernetes {
		text("labels", joinPairs(config.Labels))
		text("annotations", joinPairs(config.Annotations))
	}
	text("admin-email", config.AdminEmail)
	if config.Engine.hasServer && d.externalDatabase {
		text("db-host", config.DBHost)
		text("db-port", config.DBPort)
		text("db-name", config.DBName)
		text("db-user", config.DBUsername)
		text("db-tls-mode", config.DBTLSMode)
		if config.DBTLSCA != "" {
			sb.WriteString("db-tls-ca: |\n")
			for _, line := range strings.Split(strings.TrimSuffix(config.DBTLSCA, "\n"), "\n") {
				fmt.Fprintf(&sb, "  %s\n", line)
			}
		}
		if config.presentsClientCertificate() {
			boolean("db-tls-client-cert", true)
		}
		if config.DBTLSServerName != "" {
			text("db-tls-server-name", config.DBTLSServerName)
		}
	}
	return sb.String()
}

// writeGeneratedFrom is the first line of a description an answers file is written beside, naming
// that file, whose header has the run that writes the description again.
func writeGeneratedFrom(sb *strings.Builder, paths outputPaths) {
	fmt.Fprintf(sb, "# Generated by goiabada-setup, from the answers in %s, whose header says\n", filepath.Base(paths.answers))
	sb.WriteString("# how to generate this file again.\n")
}

// regenerateFlags are the flags of the run that writes the deployment's description at paths again
// from the answers file beside it, leaving the secrets file as it is: from the directory holding
// them, so each file is one shell word under its own name, and with --output only when the files have
// names of their own, which a run given none would not write. They are the flags alone, since the
// wizard's binary is named for its platform, and wherever the operator keeps it.
func regenerateFlags(d *deployment, paths outputPaths) string {
	command := "--answers=" + shellQuote(filepath.Base(paths.answers)) + " --keep-secrets"
	if description := filepath.Base(paths.description); description != d.outputFile || filepath.Base(paths.answers) != answersFile {
		command += " --output=" + shellQuote(description)
	}
	return command
}
