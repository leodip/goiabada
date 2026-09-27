package main

import (
	"flag"
	"fmt"
	"io"
	"os"
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
