package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// CLI flags for non-interactive mode
type CLIFlags struct {
	Version         bool
	Output          string
	DeploymentType  string
	DBType          string
	AuthServerURL   string
	AdminConsoleURL string
	Namespace       string
	AdminEmail      string
	AdminPassword   string
	// AdminPasswordFile and DBPasswordFile name a file holding the password, - for standard input,
	// so automation can give one with nothing secret on the command line.
	AdminPasswordFile string
	DBHost            string
	DBPort            string
	DBName            string
	DBUsername        string
	DBPassword        string
	DBPasswordFile    string
	SkipDBTest        bool
	NoColor           bool
	// LocalProxy is --local-proxy, read by native binaries alone.
	LocalProxy optionalBool
	// GatewayTrafficPolicy is --gateway-traffic-policy and NetworkPolicy --network-policy, read by
	// Kubernetes alone. The policy is empty when the flag was left out.
	GatewayTrafficPolicy trafficPolicy
	NetworkPolicy        bool
	// RateLimiter is --rate-limiter, read by production Compose, native binaries and Kubernetes.
	RateLimiter optionalBool
	// Metrics is --metrics, empty when left out, PodMonitorLabels --podmonitor-labels and
	// MetricsNamespace --metrics-namespace, read by Kubernetes alone.
	Metrics          metricsExposure
	PodMonitorLabels podMonitorLabels
	MetricsNamespace string
}

// optionalBool is a boolean flag that knows whether it was given, so one left out takes the
// default of the deployment it applies to.
type optionalBool struct {
	set, value bool
}

func (b *optionalBool) String() string {
	if b == nil || !b.set {
		return ""
	}
	return strconv.FormatBool(b.value)
}

// Set reads the value as the flag package reads a boolean flag's, so a value that is none is
// refused naming the flag.
func (b *optionalBool) Set(value string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	b.set, b.value = true, parsed
	return nil
}

// IsBoolFlag lets the flag be given alone, meaning true, as a boolean flag can.
func (b *optionalBool) IsBoolFlag() bool { return true }

// or is the value given, or defaultValue when the flag was left out.
func (b optionalBool) or(defaultValue bool) bool {
	if b.set {
		return b.value
	}
	return defaultValue
}

// String is the policy as --gateway-traffic-policy spells it, empty when the flag was left out.
func (p *trafficPolicy) String() string {
	if p == nil {
		return ""
	}
	return strings.ToLower(string(*p))
}

// Set reads cluster or local in any case, and refuses anything else, which the flag package
// reports naming the flag.
func (p *trafficPolicy) Set(value string) error {
	for _, policy := range []trafficPolicy{trafficPolicyCluster, trafficPolicyLocal} {
		if strings.EqualFold(value, string(policy)) {
			*p = policy
			return nil
		}
	}
	return errs.New("use cluster or local")
}

// parseFlags reads the command line. It returns flag.ErrHelp for -h and --help and the parse error
// for anything else it cannot read, each already reported to stderr with the usage, and leaves the
// exit to main: the flag package's own ExitOnError would have been a second exit (#430).
func parseFlags(args []string, stderr io.Writer) (*CLIFlags, error) {
	flags := &CLIFlags{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.BoolVar(&flags.Version, "version", false, "Show version and exit")
	fs.BoolVar(&flags.Version, "v", false, "Show version and exit (shorthand)")
	fs.StringVar(&flags.Output, "output", "", "Output file path (default: current directory)")
	fs.StringVar(&flags.Output, "o", "", "Output file path (shorthand)")
	fs.StringVar(&flags.DeploymentType, "type", "", "Deployment type: "+orList(deploymentNames()))
	fs.StringVar(&flags.DBType, "db", "", "Database type: "+orList(engineNames()))
	fs.StringVar(&flags.AuthServerURL, "auth-url", "", "Auth server URL (e.g., https://auth.example.com)")
	fs.StringVar(&flags.AdminConsoleURL, "admin-url", "", "Admin console URL (e.g., https://admin.example.com)")
	fs.StringVar(&flags.Namespace, "namespace", "", "Kubernetes namespace")
	fs.StringVar(&flags.AdminEmail, "admin-email", "", "Admin email address")
	fs.StringVar(&flags.AdminPassword, "admin-password", "", "Admin password")
	fs.StringVar(&flags.AdminPasswordFile, "admin-password-file", "", "Read the admin password from a file, - for standard input")
	fs.StringVar(&flags.DBHost, "db-host", "", "Database host")
	fs.StringVar(&flags.DBPort, "db-port", "", "Database port")
	fs.StringVar(&flags.DBName, "db-name", "", "Database name")
	fs.StringVar(&flags.DBUsername, "db-user", "", "Database username")
	fs.StringVar(&flags.DBPassword, "db-password", "", "Database password")
	fs.StringVar(&flags.DBPasswordFile, "db-password-file", "", "Read the database password from a file, - for standard input")
	fs.BoolVar(&flags.SkipDBTest, "skip-db-test", false, "Skip database connection test")
	fs.BoolVar(&flags.NoColor, "no-color", false, "Disable colored output")
	fs.Var(&flags.GatewayTrafficPolicy, "gateway-traffic-policy", "Kubernetes: the traffic policy of Envoy Gateway's load balancer Service: cluster or local (default: cluster)")
	fs.BoolVar(&flags.NetworkPolicy, "network-policy", false, "Kubernetes: admit only Envoy and the admin console to the servers with NetworkPolicies")
	fs.Var(&flags.Metrics, "metrics", "Kubernetes: expose Prometheus metrics to a scraper finding them by: none, annotations or podmonitor (default: none)")
	fs.Var(&flags.PodMonitorLabels, "podmonitor-labels", "Kubernetes: the labels the PodMonitor carries, key=value separated by commas")
	fs.StringVar(&flags.MetricsNamespace, "metrics-namespace", "", "Kubernetes: the namespace the NetworkPolicies admit to the metrics ports (default: monitoring)")
	fs.Var(&flags.RateLimiter, "rate-limiter", "Production, Kubernetes and native: turn on the auth server's rate limiter (default: true, but false for Kubernetes under the cluster traffic policy)")
	fs.Var(&flags.LocalProxy, "local-proxy", "A reverse proxy on this machine forwards to the native binaries (default: true)")

	fs.Usage = func() {
		name := fs.Name()
		p := func(format string, args ...any) { _, _ = fmt.Fprintf(fs.Output(), format, args...) }
		p("Goiabada Setup Wizard v%s\n", version)
		p("Generate configuration files for Goiabada authentication server.\n\n")
		p("Usage: %s [options]\n\n", name)
		p("When run without options, starts an interactive wizard.\n")
		p("Use --type to enable non-interactive mode with CLI flags.\n\n")
		p("General Options:\n")
		p("  -v, --version          Show version and exit\n")
		p("  -o, --output PATH      Output file path (default: current directory)\n")
		p("  --no-color             Disable colored output\n\n")
		p("Deployment Options:\n")
		p("  --type TYPE            Deployment type: %s\n", orList(deploymentNames()))
		p("  --db TYPE              Database: %s\n", orList(engineNames()))
		p("  --namespace NAME       Kubernetes namespace (default: goiabada)\n\n")
		p("URL Options (required for production/kubernetes/native):\n")
		p("  --auth-url URL         Auth server URL (e.g., https://auth.example.com)\n")
		p("  --admin-url URL        Admin console URL (e.g., https://admin.example.com)\n\n")
		p("Admin Credentials:\n")
		p("  --admin-email EMAIL    Admin email address\n")
		p("  --admin-password PASS  Admin password (generated if not provided; one given here\n")
		p("                         reaches shell history and the process list). At least 15\n")
		p("                         characters, at most 72 bytes, and not changeme\n")
		p("  --admin-password-file FILE\n")
		p("                         Read the admin password from FILE, - for standard input,\n")
		p("                         one trailing line break dropped\n\n")
		p("Database Options (for Kubernetes/native):\n")
		p("  --db-host HOST         Database hostname\n")
		p("  --db-port PORT         Database port (default: auto-detected)\n")
		p("  --db-name NAME         Database name (default: goiabada)\n")
		p("  --db-user USER         Database username (default: auto-detected)\n")
		p("  --db-password PASS     Database password (generated if not provided; one given here\n")
		p("                         reaches shell history and the process list)\n")
		p("  --db-password-file FILE\n")
		p("                         Read the database password from FILE, - for standard input,\n")
		p("                         one trailing line break dropped\n")
		p("  --skip-db-test         Skip database connection test\n\n")
		p("Rate Limiter Options (for production/kubernetes/native):\n")
		p("  --rate-limiter=BOOL    Turn on the auth server's built-in rate limiter (default: true, but\n")
		p("                         false for kubernetes under the cluster traffic policy, where its\n")
		p("                         per-IP limits count every client arriving through one node together)\n\n")
		p("Kubernetes Options:\n")
		p("  --gateway-traffic-policy=POLICY\n")
		p("                         The externalTrafficPolicy of Envoy Gateway's load balancer Service\n")
		p("                         (default: cluster). cluster works behind every load balancer, and\n")
		p("                         Goiabada sees a node's address for every client; local runs Envoy on\n")
		p("                         every node as a DaemonSet, and Goiabada sees the client's address\n")
		p("  --network-policy       Admit only Envoy's namespace, and the admin console to the auth\n")
		p("                         server, with NetworkPolicies (default: off, any pod can reach them)\n")
		p("  --metrics=EXPOSURE     Expose Prometheus metrics on ports %d and %d (default: none).\n", authServerMetricsPort, adminConsoleMetricsPort)
		p("                         annotations writes the prometheus.io pod annotations, which the\n")
		p("                         prometheus-community prometheus chart reads; podmonitor writes a\n")
		p("                         PodMonitor for the Prometheus Operator, kube-prometheus-stack's\n")
		p("  --podmonitor-labels=LABELS\n")
		p("                         With --metrics=podmonitor, the labels your Prometheus selects\n")
		p("                         PodMonitors by, key=value separated by commas (e.g.,\n")
		p("                         release=kube-prometheus-stack; default: none)\n")
		p("  --metrics-namespace=NAME\n")
		p("                         With metrics and --network-policy, the namespace the scraper runs\n")
		p("                         in, admitted to the metrics ports alone (default: monitoring)\n\n")
		p("Native Binaries Options:\n")
		p("  --local-proxy=BOOL     A reverse proxy on this machine forwards to Goiabada (default: true):\n")
		p("                         both servers listen on 127.0.0.1 and trust its forwarded headers.\n")
		p("                         false listens on every interface and trusts no forwarded header,\n")
		p("                         for HTTPS served by Goiabada itself\n\n")
		p("Examples:\n")
		p("  Interactive mode (recommended for first-time setup):\n")
		p("    %s\n\n", name)
		p("  Local development with MySQL:\n")
		p("    %s --type=local --db=mysql\n\n", name)
		p("  Kubernetes with PostgreSQL:\n")
		p("    %s --type=kubernetes --db=postgres \\\n", name)
		p("      --auth-url=https://auth.example.com \\\n")
		p("      --admin-email=admin@example.com \\\n")
		p("      --db-host=postgres.default.svc \\\n")
		p("      --db-password-file=/run/secrets/db-password\n\n")
		p("  Native binaries with PostgreSQL:\n")
		p("    %s --type=native --db=postgres \\\n", name)
		p("      --auth-url=https://auth.example.com \\\n")
		p("      --admin-url=https://admin.example.com \\\n")
		p("      --admin-email=admin@example.com \\\n")
		p("      --db-host=localhost --db-password-file=/run/secrets/db-password\n\n")
		p("For more information, visit: https://goiabada.dev\n")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return flags, nil
}

// checkWritable refuses, by its name, a flag whose value no generated file could carry, before a
// step reads any of them. The type and database flags are resolved against the tables and refused
// there, and the output path by checkOutput, in either mode.
func (f *CLIFlags) checkWritable() error {
	for _, entry := range []struct{ name, value string }{
		{"--auth-url", f.AuthServerURL},
		{"--admin-url", f.AdminConsoleURL},
		{"--namespace", f.Namespace},
		{"--admin-email", f.AdminEmail},
		{"--admin-password", f.AdminPassword},
		{"--db-host", f.DBHost},
		{"--db-port", f.DBPort},
		{"--db-name", f.DBName},
		{"--db-user", f.DBUsername},
		{"--db-password", f.DBPassword},
	} {
		if err := checkWritable(entry.value); err != nil {
			return errs.Wrapf(err, "%s cannot be written to the configuration", entry.name)
		}
	}
	return nil
}

// checkPasswordSources refuses a password given both as a flag and as a file, rather than letting
// one silently win, and standard input named for both passwords, which can be read only once.
func (f *CLIFlags) checkPasswordSources() error {
	for _, source := range []struct{ flag, value, fileFlag, file string }{
		{"--admin-password", f.AdminPassword, "--admin-password-file", f.AdminPasswordFile},
		{"--db-password", f.DBPassword, "--db-password-file", f.DBPasswordFile},
	} {
		if source.value != "" && source.file != "" {
			return errs.Errorf("give %s or %s, not both", source.flag, source.fileFlag)
		}
	}
	if f.AdminPasswordFile == "-" && f.DBPasswordFile == "-" {
		return errs.New("--admin-password-file and --db-password-file cannot both read standard input")
	}
	return nil
}

// passwordFileMax bounds what a password file is read to: a password is far shorter, and a name
// such as /dev/zero would otherwise be read until memory ran out.
const passwordFileMax = 4096

// readPasswordFile reads the password the flag named fileFlag gives, from path or, for -, from
// stdin. One trailing line break is dropped, since echo and most editors end a file with one. An
// empty password is refused rather than read as "generate one", which leaving the flag out says.
func readPasswordFile(fileFlag, path string, stdin io.Reader) (string, error) {
	source := stdin
	if path != "-" {
		file, err := os.Open(path) //nolint:gosec // G304: the operator names the file to read the password from
		if err != nil {
			return "", errs.Wrapf(err, "unable to read %s", fileFlag)
		}
		defer func() { _ = file.Close() }()
		source = file
	}
	content, err := io.ReadAll(io.LimitReader(source, passwordFileMax+1))
	if err != nil {
		return "", errs.Wrapf(err, "unable to read %s", fileFlag)
	}
	if len(content) > passwordFileMax {
		return "", errs.Errorf("%s holds more than %d bytes, which no password needs", fileFlag, passwordFileMax)
	}
	password := string(content)
	if strings.HasSuffix(password, "\r\n") {
		password = password[:len(password)-2]
	} else if strings.HasSuffix(password, "\n") {
		password = password[:len(password)-1]
	}
	if password == "" {
		return "", errs.Errorf("%s holds no password: leave it out to have one generated", fileFlag)
	}
	if err := checkWritable(password); err != nil {
		return "", errs.Wrapf(err, "%s cannot be written to the configuration", fileFlag)
	}
	return password, nil
}

// checkOutput refuses an --output a generated file's header could not name. Each header names the
// files beside it by the names they are written under, in a comment that ends at a line break, so
// a control character or a line separator in the name would end the comment and write the rest as
// configuration; a name that is not UTF-8 has no spelling in YAML. It applies in both modes, since
// the interactive wizard writes where --output says too.
func checkOutput(output string) error {
	if err := checkWritable(output); err != nil {
		return errs.Wrap(err, "--output cannot be written to the configuration")
	}
	if strings.ContainsFunc(output, func(r rune) bool {
		return r < 0x20 || (r >= 0x7f && r < 0xa0) || r == 0x2028 || r == 0x2029
	}) {
		return errs.New("--output cannot be written to the configuration: it contains a control character")
	}
	return nil
}
