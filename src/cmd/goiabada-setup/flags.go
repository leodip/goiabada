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
	// DBTLSMode is --db-tls-mode and DBTLSCAFile --db-tls-ca-file, read by Kubernetes and native
	// binaries alone, as --db-host is.
	// DBTLSClientCertFile is --db-tls-client-cert-file and DBTLSClientKeyFile
	// --db-tls-client-key-file, the pair the connection presents to the database, and DBTLSServerName
	// --db-tls-server-name, the host name verify-full checks the certificate against when the address
	// dialed is not the name certified (#546).
	DBTLSMode           string
	DBTLSCAFile         string
	DBTLSClientCertFile string
	DBTLSClientKeyFile  string
	DBTLSServerName     string
	SkipDBTest          bool
	NoColor             bool
	Overwrite           bool
	// Answers is --answers, the answers file read in place of prompts, and KeepSecrets
	// --keep-secrets, which writes every file but the secrets file and generates no secret
	// (#686 section 4). DBTLSCA and DBTLSClientCertKept are no flag's: an answers file's db-tls-ca,
	// the certificates themselves, and db-tls-client-cert, which says a client certificate is
	// presented without naming its files.
	Answers             string
	KeepSecrets         bool
	DBTLSCA             string
	DBTLSClientCertKept bool
	// LocalProxy is --local-proxy, read by native binaries alone.
	LocalProxy optionalBool
	// Routing is --routing, empty when left out, and the flags below it its modes' answers, each read
	// by the modes that ask it alone; a port left out is 0. Kubernetes alone reads them (#686 section 3).
	Routing          routing
	GatewayClass     string
	GatewayHTTPPort  int
	GatewayHTTPSPort int
	GatewayName      string
	GatewayNamespace string
	AuthListener     string
	AdminListener    string
	IngressClass     string
	TLS              tlsSource
	TLSIssuer        string
	TLSSecretAuth    string
	TLSSecretAdmin   string
	// GatewayTrafficPolicy is --gateway-traffic-policy, read by the envoy-gateway mode alone, empty
	// when left out; NetworkPolicy is --network-policy and ProxyNamespace --proxy-namespace, read by
	// Kubernetes alone.
	GatewayTrafficPolicy trafficPolicy
	NetworkPolicy        bool
	ProxyNamespace       string
	// CreateNamespace is --create-namespace, read by Kubernetes alone.
	CreateNamespace optionalBool
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
func (b *optionalBool) or(defaultValue bool) bool {
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

// String is the mode as --routing spells it, empty when the flag was left out.
func (r *routing) String() string {
	if r == nil {
		return ""
	}
	return string(*r)
}

// Set reads one of the modes, and refuses anything else, which the flag package reports naming the
// flag.
func (r *routing) Set(value string) error {
	for _, mode := range routings {
		if value == string(mode) {
			*r = mode
			return nil
		}
	}
	return errs.Errorf("use %s", orList(routingNames()))
}

// routingNames is every mode as --routing spells it, in the wizard's order.
func routingNames() []string {
	names := make([]string, len(routings))
	for i, mode := range routings {
		names[i] = string(mode)
	}
	return names
}

// String is the source as --tls spells it, empty when the flag was left out.
func (t *tlsSource) String() string {
	if t == nil {
		return ""
	}
	return string(*t)
}

// Set reads one of the sources, and refuses anything else, which the flag package reports naming
// the flag.
func (t *tlsSource) Set(value string) error {
	for _, source := range tlsSources {
		if value == string(source) {
			*t = source
			return nil
		}
	}
	return errs.Errorf("use %s", orList(tlsSourceNames()))
}

// tlsSourceNames is every source as --tls spells it, in the wizard's order.
func tlsSourceNames() []string {
	names := make([]string, len(tlsSources))
	for i, source := range tlsSources {
		names[i] = string(source)
	}
	return names
}

// parseFlags reads the command line. It returns flag.ErrHelp for -h and --help and the parse error
// for anything else it cannot read, each already reported to stderr with the usage, and leaves the
// exit to main: the flag package's own ExitOnError would have been a second exit (#430).
func parseFlags(args []string, stderr io.Writer) (*CLIFlags, error) {
	flags := &CLIFlags{}
	if err := newFlagSet(flags, stderr).Parse(args); err != nil {
		return nil, err
	}
	return flags, nil
}

// newFlagSet declares every flag the wizard reads, each writing into flags, with the usage text -h
// prints. The usage text and the setup wizard's docs page each list the same flags, and a test holds
// each to them.
func newFlagSet(flags *CLIFlags, stderr io.Writer) *flag.FlagSet {
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
	fs.StringVar(&flags.DBTLSMode, "db-tls-mode", "", "Database TLS mode: "+orList(tlsModeNames())+" (default: prefer)")
	fs.StringVar(&flags.DBTLSCAFile, "db-tls-ca-file", "", "With verify-ca or verify-full, the PEM file of the authorities the database's certificate is checked against (default: the system's roots)")
	fs.StringVar(&flags.DBTLSClientCertFile, "db-tls-client-cert-file", "", "With require, verify-ca or verify-full, the PEM file of the client certificate the connection presents to the database, with --db-tls-client-key-file beside it; not for SQL Server (default: none)")
	fs.StringVar(&flags.DBTLSClientKeyFile, "db-tls-client-key-file", "", "The PEM file of the client certificate's private key, beside --db-tls-client-cert-file (default: none)")
	fs.StringVar(&flags.DBTLSServerName, "db-tls-server-name", "", "With verify-full, the host name the database's certificate is checked against when the address dialed is not the name certified (default: the host dialed)")
	fs.BoolVar(&flags.SkipDBTest, "skip-db-test", false, "Skip database connection test")
	fs.BoolVar(&flags.NoColor, "no-color", false, "Disable colored output")
	fs.BoolVar(&flags.Overwrite, "overwrite", false, "Overwrite output files that already exist, and the secrets in them")
	fs.StringVar(&flags.Answers, "answers", "", "Read the answers from an answers file a run wrote, asking for none")
	fs.BoolVar(&flags.KeepSecrets, "keep-secrets", false, "Write every file but the secrets file, which is left as it is, and generate no secret")
	fs.Var(&flags.CreateNamespace, "create-namespace", "Kubernetes: declare the namespace in both files, so applying them creates it; false for one that already exists (default: true)")
	fs.Var(&flags.Routing, "routing", "Kubernetes: how traffic reaches the servers: "+orList(routingNames())+" (default: envoy-gateway)")
	fs.StringVar(&flags.GatewayClass, "gateway-class", "", "Kubernetes, --routing=gateway: the GatewayClass of the Gateway the manifest creates")
	fs.IntVar(&flags.GatewayHTTPPort, "gateway-http-port", 0, "Kubernetes, --routing=gateway: the Gateway's HTTP listener port (default: 80)")
	fs.IntVar(&flags.GatewayHTTPSPort, "gateway-https-port", 0, "Kubernetes, --routing=gateway: the Gateway's HTTPS listener port (default: 443)")
	fs.StringVar(&flags.GatewayName, "gateway-name", "", "Kubernetes, --routing=existing-gateway: the Gateway the routes attach to")
	fs.StringVar(&flags.GatewayNamespace, "gateway-namespace", "", "Kubernetes, --routing=existing-gateway: the namespace of that Gateway")
	fs.StringVar(&flags.AuthListener, "auth-listener", "", "Kubernetes, --routing=existing-gateway: the Gateway's HTTPS listener for the auth server's host")
	fs.StringVar(&flags.AdminListener, "admin-listener", "", "Kubernetes, --routing=existing-gateway: the Gateway's HTTPS listener for the admin console's host (default: --auth-listener)")
	fs.StringVar(&flags.IngressClass, "ingress-class", "", "Kubernetes, --routing=ingress: the Ingresses' class (default: the cluster's default class)")
	fs.Var(&flags.TLS, "tls", "Kubernetes, --routing=gateway or ingress: where the certificates come from: "+orList(tlsSourceNames())+" (default: cluster-issuer)")
	fs.StringVar(&flags.TLSIssuer, "tls-issuer", "", "Kubernetes, --tls=cluster-issuer or issuer: the cert-manager ClusterIssuer or Issuer")
	fs.StringVar(&flags.TLSSecretAuth, "auth-tls-secret", "", "Kubernetes, --tls=secrets: the TLS Secret holding the auth server's certificate (default: "+authCertificateSecret+")")
	fs.StringVar(&flags.TLSSecretAdmin, "admin-tls-secret", "", "Kubernetes, --tls=secrets: the TLS Secret holding the admin console's certificate (default: "+adminCertificateSecret+")")
	fs.Var(&flags.GatewayTrafficPolicy, "gateway-traffic-policy", "Kubernetes, --routing=envoy-gateway: the traffic policy of Envoy Gateway's load balancer Service: cluster or local (default: cluster)")
	fs.BoolVar(&flags.NetworkPolicy, "network-policy", false, "Kubernetes: admit only the routing layer and the admin console to the servers with NetworkPolicies")
	fs.StringVar(&flags.ProxyNamespace, "proxy-namespace", "", "Kubernetes, with --network-policy: the namespace the routing layer's proxies run in (default: envoy-gateway-system for --routing=envoy-gateway, required otherwise)")
	fs.Var(&flags.Metrics, "metrics", "Kubernetes: expose Prometheus metrics to a scraper finding them by: none, annotations or podmonitor (default: none)")
	fs.Var(&flags.PodMonitorLabels, "podmonitor-labels", "Kubernetes: the labels the PodMonitor carries, key=value separated by commas")
	fs.StringVar(&flags.MetricsNamespace, "metrics-namespace", "", "Kubernetes: the namespace the NetworkPolicies admit to the metrics ports (default: monitoring)")
	fs.Var(&flags.RateLimiter, "rate-limiter", "Production, Kubernetes and native: turn on the auth server's rate limiter (default: true, but false for Kubernetes unless --routing=envoy-gateway with the local traffic policy)")
	fs.Var(&flags.LocalProxy, "local-proxy", "A reverse proxy on this machine forwards to the native binaries (default: true)")

	fs.Usage = func() {
		name := fs.Name()
		p := func(format string, args ...any) { _, _ = fmt.Fprintf(fs.Output(), format, args...) }
		p("Goiabada Setup Wizard v%s\n", version)
		p("Generate configuration files for Goiabada authentication server.\n\n")
		p("Usage: %s [options]\n\n", name)
		p("When run without options, starts an interactive wizard.\n")
		p("Use --type, or --answers, to enable non-interactive mode with CLI flags.\n\n")
		p("General Options:\n")
		p("  -v, --version          Show version and exit\n")
		p("  -o, --output PATH      Output file path (default: current directory)\n")
		p("  --no-color             Disable colored output\n")
		p("  --overwrite            Overwrite output files that already exist, and the secrets in them\n")
		p("  --answers FILE         Read the answers from FILE, an answers file a run wrote, asking for\n")
		p("                         none; a flag given beside it replaces the answer of its name.\n")
		p("                         For kubernetes, local and production\n")
		p("  --keep-secrets         Write every file but the secrets file, which is left as it is, and\n")
		p("                         generate no secret: regenerates a deployment's configuration from\n")
		p("                         its answers. For kubernetes, local and production\n\n")
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
		p("                         characters and at most 72 bytes\n")
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
		p("  --db-tls-mode MODE     How the auth server protects its database connection: %s\n", strings.Join(tlsModeNames(), ", "))
		p("                         (default: prefer, which checks no certificate)\n")
		p("  --db-tls-ca-file FILE  With verify-ca or verify-full, the PEM file of the authorities the\n")
		p("                         database's certificate is checked against (default: the system's roots)\n")
		p("  --db-tls-client-cert-file FILE\n")
		p("                         With require, verify-ca or verify-full, the PEM file of the client\n")
		p("                         certificate the connection presents to the database, with\n")
		p("                         --db-tls-client-key-file beside it; not for SQL Server (default: none)\n")
		p("  --db-tls-client-key-file FILE\n")
		p("                         The PEM file of the client certificate's private key, beside\n")
		p("                         --db-tls-client-cert-file (default: none)\n")
		p("  --db-tls-server-name NAME\n")
		p("                         With verify-full, the host name the database's certificate is\n")
		p("                         checked against when the address dialed is not the name\n")
		p("                         certified (default: the host dialed)\n")
		p("  --skip-db-test         Skip database connection test\n\n")
		p("Rate Limiter Options (for production/kubernetes/native):\n")
		p("  --rate-limiter=BOOL    Turn on the auth server's built-in rate limiter (default: true, but\n")
		p("                         false for kubernetes unless under Envoy Gateway's local traffic\n")
		p("                         policy, since its per-IP limits count together every client that\n")
		p("                         reaches Goiabada from one address, such as a node's)\n\n")
		p("Kubernetes Options:\n")
		p("  --create-namespace=BOOL\n")
		p("                         Declare the namespace in both files, so applying them creates it\n")
		p("                         (default: true). false, for a namespace that already exists,\n")
		p("                         declares it in neither, and applying them needs rights inside it alone\n")
		p("  --routing=MODE         How traffic from outside the cluster reaches the servers\n")
		p("                         (default: envoy-gateway): envoy-gateway, a Gateway of class eg for\n")
		p("                         the Envoy Gateway the wizard's steps install; gateway, a Gateway of\n")
		p("                         a class your cluster has; existing-gateway, routes attached to a\n")
		p("                         Gateway someone else runs; ingress, an Ingress per host; none, the\n")
		p("                         Services alone, which you route\n")
		p("  --gateway-class=NAME   With gateway, the GatewayClass (required)\n")
		p("  --gateway-http-port=PORT\n")
		p("                         With gateway, the HTTP listener's port (default: 80)\n")
		p("  --gateway-https-port=PORT\n")
		p("                         With gateway, the HTTPS listeners' port (default: 443). Some\n")
		p("                         implementations take only their proxy's own ports: Traefik's Gateway\n")
		p("                         takes 8000 and 8443\n")
		p("  --gateway-name=NAME    With existing-gateway, the Gateway the routes attach to (required)\n")
		p("  --gateway-namespace=NAME\n")
		p("                         With existing-gateway, that Gateway's namespace (required)\n")
		p("  --auth-listener=NAME   With existing-gateway, its HTTPS listener for the auth server's host\n")
		p("                         (required)\n")
		p("  --admin-listener=NAME  With existing-gateway, its HTTPS listener for the admin console's\n")
		p("                         host (default: --auth-listener's)\n")
		p("  --ingress-class=NAME   With ingress, the IngressClass (default: the cluster's default)\n")
		p("  --tls=SOURCE           With gateway or ingress, where the certificates come from\n")
		p("                         (default: cluster-issuer): cluster-issuer or issuer, the cert-manager\n")
		p("                         ClusterIssuer or Issuer --tls-issuer names; secrets, TLS Secrets\n")
		p("                         you supply; external, TLS ended in front, at a load balancer or CDN\n")
		p("  --tls-issuer=NAME      With cluster-issuer or issuer, the issuer (required)\n")
		p("  --auth-tls-secret=NAME With secrets, the auth server's TLS Secret (default: %s)\n", authCertificateSecret)
		p("  --admin-tls-secret=NAME\n")
		p("                         With secrets, the admin console's TLS Secret (default:\n")
		p("                         %s)\n", adminCertificateSecret)
		p("  --gateway-traffic-policy=POLICY\n")
		p("                         With envoy-gateway, the externalTrafficPolicy of Envoy Gateway's\n")
		p("                         load balancer Service (default: cluster). cluster works behind every\n")
		p("                         load balancer, and Goiabada sees a node's address for every client;\n")
		p("                         local runs Envoy on every node as a DaemonSet, and Goiabada sees the\n")
		p("                         client's address\n")
		p("  --network-policy       Admit only the routing layer's namespace, and the admin console to\n")
		p("                         the auth server, with NetworkPolicies (default: off, any pod can\n")
		p("                         reach them)\n")
		p("  --proxy-namespace=NAME With --network-policy, the namespace the routing layer's proxies run\n")
		p("                         in (default: envoy-gateway-system with envoy-gateway, required\n")
		p("                         otherwise)\n")
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
		p("  Regenerate a deployment's configuration, keeping its secrets, from the directory\n")
		p("  holding its answers file:\n")
		p("    %s --answers=%s --keep-secrets\n\n", name, answersFile)
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
	return fs
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
		{"--db-tls-ca-file", f.DBTLSCAFile},
		{"--db-tls-client-cert-file", f.DBTLSClientCertFile},
		{"--db-tls-client-key-file", f.DBTLSClientKeyFile},
		{"--db-tls-server-name", f.DBTLSServerName},
		{"--gateway-class", f.GatewayClass},
		{"--gateway-name", f.GatewayName},
		{"--gateway-namespace", f.GatewayNamespace},
		{"--auth-listener", f.AuthListener},
		{"--admin-listener", f.AdminListener},
		{"--ingress-class", f.IngressClass},
		{"--tls-issuer", f.TLSIssuer},
		{"--auth-tls-secret", f.TLSSecretAuth},
		{"--admin-tls-secret", f.TLSSecretAdmin},
		{"--proxy-namespace", f.ProxyNamespace},
	} {
		if err := checkWritable(entry.value); err != nil {
			return errs.Wrapf(err, "%s cannot be written to the configuration", entry.name)
		}
	}
	return nil
}

// clientCertificateSecretDocsURL is the page that creates the client certificate's Secret by hand.
const clientCertificateSecretDocsURL = "https://goiabada.dev/deploy/kubernetes/secrets/#from-your-terminal" //nolint:gosec // G101: a docs URL, no credential

// checkKeptSecrets refuses a secret given beside --keep-secrets, which writes none: a password
// would be dropped without a word, and a client certificate pair would be mounted from a Secret the
// secrets file doesn't hold, or leave the old pair in use. Empty client certificate files, which
// present none, are not refused.
func (f *CLIFlags) checkKeptSecrets() error {
	if !f.KeepSecrets {
		return nil
	}
	for _, given := range []struct{ flag, value string }{
		{"--admin-password", f.AdminPassword},
		{"--admin-password-file", f.AdminPasswordFile},
		{"--db-password", f.DBPassword},
		{"--db-password-file", f.DBPasswordFile},
	} {
		if given.value != "" {
			return errs.Errorf("%s is given with --keep-secrets, which writes no secret: leave it out", given.flag)
		}
	}
	for _, given := range []struct{ flag, value string }{
		{"--db-tls-client-cert-file", f.DBTLSClientCertFile},
		{"--db-tls-client-key-file", f.DBTLSClientKeyFile},
	} {
		if given.value != "" {
			return errs.Errorf("%s is given with --keep-secrets, which writes no secret: create or replace the %s Secret from the pair, as %s shows, and answer db-tls-client-cert: true in the answers file", given.flag, dbClientTLSSecret, clientCertificateSecretDocsURL)
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
