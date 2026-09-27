package main

import (
	"flag"
	"fmt"
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

func parseFlags() *CLIFlags {
	flags := &CLIFlags{}

	flag.BoolVar(&flags.Version, "version", false, "Show version and exit")
	flag.BoolVar(&flags.Version, "v", false, "Show version and exit (shorthand)")
	flag.StringVar(&flags.Output, "output", "", "Output file path (default: current directory)")
	flag.StringVar(&flags.Output, "o", "", "Output file path (shorthand)")
	flag.StringVar(&flags.DeploymentType, "type", "", "Deployment type: "+orList(deploymentNames()))
	flag.StringVar(&flags.DBType, "db", "", "Database type: "+orList(engineNames()))
	flag.StringVar(&flags.AuthServerURL, "auth-url", "", "Auth server URL (e.g., https://auth.example.com)")
	flag.StringVar(&flags.AdminConsoleURL, "admin-url", "", "Admin console URL (e.g., https://admin.example.com)")
	flag.StringVar(&flags.Namespace, "namespace", "", "Kubernetes namespace")
	flag.StringVar(&flags.AdminEmail, "admin-email", "", "Admin email address")
	flag.StringVar(&flags.AdminPassword, "admin-password", "", "Admin password")
	flag.StringVar(&flags.DBHost, "db-host", "", "Database host")
	flag.StringVar(&flags.DBPort, "db-port", "", "Database port")
	flag.StringVar(&flags.DBName, "db-name", "", "Database name")
	flag.StringVar(&flags.DBUsername, "db-user", "", "Database username")
	flag.StringVar(&flags.DBPassword, "db-password", "", "Database password")
	flag.BoolVar(&flags.SkipDBTest, "skip-db-test", false, "Skip database connection test")
	flag.BoolVar(&flags.NoColor, "no-color", false, "Disable colored output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Goiabada Setup Wizard v%s\n", version)
		fmt.Fprintf(os.Stderr, "Generate configuration files for Goiabada authentication server.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "When run without options, starts an interactive wizard.\n")
		fmt.Fprintf(os.Stderr, "Use --type to enable non-interactive mode with CLI flags.\n\n")
		fmt.Fprintf(os.Stderr, "General Options:\n")
		fmt.Fprintf(os.Stderr, "  -v, --version          Show version and exit\n")
		fmt.Fprintf(os.Stderr, "  -o, --output PATH      Output file path (default: current directory)\n")
		fmt.Fprintf(os.Stderr, "  --no-color             Disable colored output\n\n")
		fmt.Fprintf(os.Stderr, "Deployment Options:\n")
		fmt.Fprintf(os.Stderr, "  --type TYPE            Deployment type: %s\n", orList(deploymentNames()))
		fmt.Fprintf(os.Stderr, "  --db TYPE              Database: %s\n", orList(engineNames()))
		fmt.Fprintf(os.Stderr, "  --namespace NAME       Kubernetes namespace (default: goiabada)\n\n")
		fmt.Fprintf(os.Stderr, "URL Options (required for production/kubernetes/native):\n")
		fmt.Fprintf(os.Stderr, "  --auth-url URL         Auth server URL (e.g., https://auth.example.com)\n")
		fmt.Fprintf(os.Stderr, "  --admin-url URL        Admin console URL (e.g., https://admin.example.com)\n\n")
		fmt.Fprintf(os.Stderr, "Admin Credentials:\n")
		fmt.Fprintf(os.Stderr, "  --admin-email EMAIL    Admin email address\n")
		fmt.Fprintf(os.Stderr, "  --admin-password PASS  Admin password (generated if not provided)\n\n")
		fmt.Fprintf(os.Stderr, "Database Options (for Kubernetes/native):\n")
		fmt.Fprintf(os.Stderr, "  --db-host HOST         Database hostname\n")
		fmt.Fprintf(os.Stderr, "  --db-port PORT         Database port (default: auto-detected)\n")
		fmt.Fprintf(os.Stderr, "  --db-name NAME         Database name (default: goiabada)\n")
		fmt.Fprintf(os.Stderr, "  --db-user USER         Database username (default: auto-detected)\n")
		fmt.Fprintf(os.Stderr, "  --db-password PASS     Database password (generated if not provided)\n")
		fmt.Fprintf(os.Stderr, "  --skip-db-test         Skip database connection test\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  Interactive mode (recommended for first-time setup):\n")
		fmt.Fprintf(os.Stderr, "    %s\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Local development with MySQL:\n")
		fmt.Fprintf(os.Stderr, "    %s --type=local --db=mysql\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Kubernetes with PostgreSQL:\n")
		fmt.Fprintf(os.Stderr, "    %s --type=kubernetes --db=postgres \\\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "      --auth-url=https://auth.example.com \\\n")
		fmt.Fprintf(os.Stderr, "      --admin-email=admin@example.com \\\n")
		fmt.Fprintf(os.Stderr, "      --db-host=postgres.default.svc \\\n")
		fmt.Fprintf(os.Stderr, "      --db-password=secretpass\n\n")
		fmt.Fprintf(os.Stderr, "  Native binaries with PostgreSQL:\n")
		fmt.Fprintf(os.Stderr, "    %s --type=native --db=postgres \\\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "      --auth-url=https://auth.example.com \\\n")
		fmt.Fprintf(os.Stderr, "      --admin-url=https://admin.example.com \\\n")
		fmt.Fprintf(os.Stderr, "      --admin-email=admin@example.com \\\n")
		fmt.Fprintf(os.Stderr, "      --db-host=localhost --db-password=secretpass\n\n")
		fmt.Fprintf(os.Stderr, "For more information, visit: https://goiabada.dev\n")
	}

	flag.Parse()
	return flags
}
