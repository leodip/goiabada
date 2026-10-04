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
	DBHost          string
	DBPort          string
	DBName          string
	DBUsername      string
	DBPassword      string
	SkipDBTest      bool
	NoColor         bool
	// LocalProxy is --local-proxy, read by native binaries alone.
	LocalProxy optionalBool
	// GatewayTrafficPolicy is --gateway-traffic-policy and NetworkPolicy --network-policy, read by
	// Kubernetes alone. The policy is empty when the flag was left out.
	GatewayTrafficPolicy trafficPolicy
	NetworkPolicy        bool
	// RateLimiter is --rate-limiter, read by production Compose, native binaries and Kubernetes.
	RateLimiter optionalBool
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
	fs.StringVar(&flags.DBHost, "db-host", "", "Database host")
	fs.StringVar(&flags.DBPort, "db-port", "", "Database port")
	fs.StringVar(&flags.DBName, "db-name", "", "Database name")
	fs.StringVar(&flags.DBUsername, "db-user", "", "Database username")
	fs.StringVar(&flags.DBPassword, "db-password", "", "Database password")
	fs.BoolVar(&flags.SkipDBTest, "skip-db-test", false, "Skip database connection test")
	fs.BoolVar(&flags.NoColor, "no-color", false, "Disable colored output")
	fs.Var(&flags.GatewayTrafficPolicy, "gateway-traffic-policy", "Kubernetes: the traffic policy of Envoy Gateway's load balancer Service: cluster or local (default: cluster)")
	fs.BoolVar(&flags.NetworkPolicy, "network-policy", false, "Kubernetes: admit only Envoy and the admin console to the servers with NetworkPolicies")
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
		p("  --admin-password PASS  Admin password (generated if not provided)\n\n")
		p("Database Options (for Kubernetes/native):\n")
		p("  --db-host HOST         Database hostname\n")
		p("  --db-port PORT         Database port (default: auto-detected)\n")
		p("  --db-name NAME         Database name (default: goiabada)\n")
		p("  --db-user USER         Database username (default: auto-detected)\n")
		p("  --db-password PASS     Database password (generated if not provided)\n")
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
		p("                         server, with NetworkPolicies (default: off, any pod can reach them)\n\n")
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
		p("      --db-password=secretpass\n\n")
		p("  Native binaries with PostgreSQL:\n")
		p("    %s --type=native --db=postgres \\\n", name)
		p("      --auth-url=https://auth.example.com \\\n")
		p("      --admin-url=https://admin.example.com \\\n")
		p("      --admin-email=admin@example.com \\\n")
		p("      --db-host=localhost --db-password=secretpass\n\n")
		p("For more information, visit: https://goiabada.dev\n")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return flags, nil
}

// checkWritable refuses, by its name, a flag whose value no generated file could carry, before a
// step reads any of them. The type and database flags are resolved against the tables and refused
// there, and the output path is never written into a file.
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
