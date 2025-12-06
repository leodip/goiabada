package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/chzyer/readline"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/microsoft/go-mssqldb"
)

const version = "1.0.0"

// ANSI color codes
var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
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
	flag.StringVar(&flags.DeploymentType, "type", "", "Deployment type: local, production, kubernetes, or native")
	flag.StringVar(&flags.DBType, "db", "", "Database type: mysql, postgres, mssql, or sqlite")
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
		fmt.Fprintf(os.Stderr, "  --type TYPE            Deployment type: local, production, kubernetes, or native\n")
		fmt.Fprintf(os.Stderr, "  --db TYPE              Database: mysql, postgres, mssql, or sqlite\n")
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

func main() {
	flags := parseFlags()

	// Handle --version flag
	if flags.Version {
		fmt.Printf("goiabada-setup version %s\n", version)
		os.Exit(0)
	}

	// Disable colors if requested or if not a terminal
	useColors := !flags.NoColor && isTerminal()
	if !useColors {
		disableColors()
	}

	printBanner()

	// Create readline instance for interactive input
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
	})
	if err != nil {
		printError("Failed to initialize readline: %v", err)
		os.Exit(1)
	}
	defer rl.Close()

	// Determine if we're in non-interactive mode
	nonInteractive := flags.DeploymentType != ""

	// Step 1: Deployment type
	var deploymentType string
	if nonInteractive {
		switch strings.ToLower(flags.DeploymentType) {
		case "local", "1":
			deploymentType = "1"
		case "production", "2":
			deploymentType = "2"
		case "kubernetes", "k8s", "3":
			deploymentType = "3"
		case "native", "binaries", "4":
			deploymentType = "4"
		default:
			printError("Invalid deployment type: %s (use: local, production, kubernetes, or native)", flags.DeploymentType)
			os.Exit(1)
		}
		printInfo("Deployment type: %s", getDeploymentTypeName(deploymentType))
	} else {
		fmt.Println("STEP 1: Deployment type")
		fmt.Println("------------------------")
		fmt.Println("1. Local testing (HTTP only) - for development/testing")
		fmt.Println("2. Production with reverse proxy (Cloudflare/Nginx)")
		fmt.Println("3. Kubernetes cluster")
		fmt.Println("4. Native binaries")
		fmt.Println()
		deploymentType = promptChoice(rl, "Select deployment type [1-4]", []string{"1", "2", "3", "4"}, "1")
	}

	// Step 2: Database
	var dbType, dbImage, dbPort string
	if nonInteractive {
		switch strings.ToLower(flags.DBType) {
		case "mysql", "1":
			dbType = "mysql"
		case "postgres", "postgresql", "2":
			dbType = "postgres"
		case "mssql", "sqlserver", "3":
			dbType = "mssql"
		case "sqlite", "4":
			if deploymentType == "3" {
				printError("SQLite is not supported for Kubernetes deployments")
				os.Exit(1)
			}
			if deploymentType == "4" {
				printWarning("SQLite is fine for single-instance native deployments, but consider a proper database for production.")
			}
			dbType = "sqlite"
		default:
			printError("Invalid database type: %s (use: mysql, postgres, mssql, or sqlite)", flags.DBType)
			os.Exit(1)
		}
		printInfo("Database type: %s", dbType)
	} else {
		fmt.Println()
		fmt.Println("STEP 2: Database type")
		fmt.Println("-----------------")
		if deploymentType == "3" {
			fmt.Println("1. MySQL")
			fmt.Println("2. PostgreSQL")
			fmt.Println("3. SQL Server")
			fmt.Println()
			fmt.Println("Note: For Kubernetes, you'll need to provide your own database.")
			fmt.Println("      SQLite is not recommended for Kubernetes deployments.")
			fmt.Println()
		} else {
			fmt.Println("1. MySQL")
			fmt.Println("2. PostgreSQL")
			fmt.Println("3. SQL Server")
			fmt.Println("4. SQLite")
			fmt.Println()
		}

		var validDBChoices []string
		if deploymentType == "3" {
			validDBChoices = []string{"1", "2", "3"}
		} else {
			validDBChoices = []string{"1", "2", "3", "4"}
		}
		dbChoice := promptChoice(rl, fmt.Sprintf("Select database [1-%d]", len(validDBChoices)), validDBChoices, "1")

		switch dbChoice {
		case "1":
			dbType = "mysql"
		case "2":
			dbType = "postgres"
		case "3":
			dbType = "mssql"
		case "4":
			dbType = "sqlite"
		}
	}

	// Set database defaults
	switch dbType {
	case "mysql":
		dbImage = "mysql:latest"
		dbPort = "3306"
	case "postgres":
		dbImage = "postgres:latest"
		dbPort = "5432"
	case "mssql":
		dbImage = "mcr.microsoft.com/mssql/server:2022-latest"
		dbPort = "1433"
	case "sqlite":
		dbImage = ""
		dbPort = ""
	}

	// Step 3: Domain names (for production, Kubernetes, and native binaries)
	var authServerURL, adminConsoleURL string
	var baseDomain string
	if deploymentType == "2" || deploymentType == "3" || deploymentType == "4" {
		if nonInteractive {
			authServerURL = flags.AuthServerURL
			adminConsoleURL = flags.AdminConsoleURL
			if authServerURL == "" {
				printError("--auth-url is required for production/kubernetes/native deployments")
				os.Exit(1)
			}
			if err := validateURL(authServerURL); err != nil {
				printError("Invalid auth URL: %s", err)
				os.Exit(1)
			}
			// Check for HTTP in production
			if strings.HasPrefix(authServerURL, "http://") {
				printWarning("Using HTTP for production is not recommended. Consider using HTTPS.")
			}
			baseDomain = extractDomainFromURL(authServerURL)
			if adminConsoleURL == "" {
				adminConsoleURL = fmt.Sprintf("https://admin.%s", baseDomain)
			}
			if err := validateURL(adminConsoleURL); err != nil {
				printError("Invalid admin URL: %s", err)
				os.Exit(1)
			}
			if strings.HasPrefix(adminConsoleURL, "http://") {
				printWarning("Using HTTP for production is not recommended. Consider using HTTPS.")
			}
			// Check domain mismatch
			authDomain := extractDomainFromURL(authServerURL)
			adminDomain := extractDomainFromURL(adminConsoleURL)
			if authDomain != adminDomain {
				printWarning("Domain mismatch: auth=%s, admin=%s", authDomain, adminDomain)
			}
			printInfo("Auth server URL: %s", authServerURL)
			printInfo("Admin console URL: %s", adminConsoleURL)
		} else {
			fmt.Println()
			fmt.Println("STEP 3: Domain names")
			fmt.Println("---------------------")
			authServerURL = promptURL(rl, "Auth server URL (e.g., https://auth.example.com)", "https://auth.example.com")

			// Check for HTTP in production
			if strings.HasPrefix(authServerURL, "http://") && !strings.HasPrefix(authServerURL, "http://localhost") {
				printWarning("Using HTTP for production is not recommended. Consider using HTTPS.")
				if !promptYesNo(rl, "Continue with HTTP?", false) {
					authServerURL = promptURL(rl, "Auth server URL", "https://auth.example.com")
				}
			}

			baseDomain = extractDomainFromURL(authServerURL)
			defaultAdminURL := fmt.Sprintf("https://admin.%s", baseDomain)
			adminConsoleURL = promptURL(rl, "Admin console URL (e.g., https://admin.example.com)", defaultAdminURL)

			// Check for HTTP in production
			if strings.HasPrefix(adminConsoleURL, "http://") && !strings.HasPrefix(adminConsoleURL, "http://localhost") {
				printWarning("Using HTTP for production is not recommended. Consider using HTTPS.")
				if !promptYesNo(rl, "Continue with HTTP?", false) {
					adminConsoleURL = promptURL(rl, "Admin console URL", defaultAdminURL)
				}
			}

			// Validate domain suffixes match
			authDomain := extractDomainFromURL(authServerURL)
			adminDomain := extractDomainFromURL(adminConsoleURL)
			if authDomain != adminDomain {
				fmt.Println()
				printWarning("Domain mismatch detected!")
				fmt.Printf("   Auth server domain:    %s\n", authDomain)
				fmt.Printf("   Admin console domain:  %s\n", adminDomain)
				fmt.Println()
				if !promptYesNo(rl, "Continue with different domains?", false) {
					fmt.Println()
					fmt.Println("Please re-enter the URLs:")
					authServerURL = promptURL(rl, "Auth server URL", authServerURL)
					baseDomain = extractDomainFromURL(authServerURL)
					defaultAdminURL = fmt.Sprintf("https://admin.%s", baseDomain)
					adminConsoleURL = promptURL(rl, "Admin console URL", defaultAdminURL)
				}
			}
		}
	} else {
		authServerURL = "http://localhost:9090"
		adminConsoleURL = "http://localhost:9091"
	}

	// Step 4: Kubernetes namespace (only for Kubernetes)
	var k8sNamespace string
	if deploymentType == "3" {
		if nonInteractive {
			k8sNamespace = flags.Namespace
			if k8sNamespace == "" {
				k8sNamespace = "goiabada"
			}
			if err := validateNamespace(k8sNamespace); err != nil {
				printError("Invalid namespace: %s", err)
				os.Exit(1)
			}
			printInfo("Kubernetes namespace: %s", k8sNamespace)
		} else {
			fmt.Println()
			fmt.Println("STEP 4: Kubernetes namespace")
			fmt.Println("-----------------------------")
			k8sNamespace = promptNamespace(rl, "Namespace", "goiabada")
		}
	}

	// Step 5: Admin credentials
	var adminEmail, adminPassword string
	defaultAdminEmail := "admin@example.com"
	if baseDomain != "" && baseDomain != "example.com" {
		defaultAdminEmail = fmt.Sprintf("admin@%s", baseDomain)
	}

	if nonInteractive {
		adminEmail = flags.AdminEmail
		if adminEmail == "" {
			adminEmail = defaultAdminEmail
		}
		if err := validateEmail(adminEmail); err != nil {
			printError("Invalid admin email: %s", err)
			os.Exit(1)
		}
		adminPassword = flags.AdminPassword
		if adminPassword == "" {
			adminPassword = generateRandomString(16)
			printInfo("Generated admin password: %s", adminPassword)
		}
		// Check password strength
		if issues := checkPasswordStrength(adminPassword); len(issues) > 0 {
			printWarning("Weak password: %s", strings.Join(issues, ", "))
		}
		printInfo("Admin email: %s", adminEmail)
	} else {
		fmt.Println()
		switch deploymentType {
		case "3":
			fmt.Println("STEP 5: Admin credentials")
		case "4":
			fmt.Println("STEP 4: Admin credentials")
		default:
			fmt.Println("STEP 4: Admin credentials")
		}
		fmt.Println("--------------------------")
		adminEmail = promptEmail(rl, "Admin email", defaultAdminEmail)
		adminPassword = promptPassword(rl, "Admin password", "changeme")
	}

	// Step 6: Database connection
	var dbHost, dbName, dbUsername, dbPassword string
	if dbType != "sqlite" {
		if deploymentType == "3" || deploymentType == "4" {
			// Kubernetes and native binaries need full database details
			if nonInteractive {
				dbHost = flags.DBHost
				if dbHost == "" {
					printError("--db-host is required for Kubernetes/native deployments")
					os.Exit(1)
				}
				if err := validateHostname(dbHost); err != nil {
					printError("Invalid database host: %s", err)
					os.Exit(1)
				}
				dbPort = flags.DBPort
				if dbPort == "" {
					switch dbType {
					case "mysql":
						dbPort = "3306"
					case "postgres":
						dbPort = "5432"
					case "mssql":
						dbPort = "1433"
					}
				}
				if err := validatePort(dbPort); err != nil {
					printError("Invalid database port: %s", err)
					os.Exit(1)
				}
				dbName = flags.DBName
				if dbName == "" {
					dbName = "goiabada"
				}
				if err := validateDatabaseName(dbName); err != nil {
					printError("Invalid database name: %s", err)
					os.Exit(1)
				}
				dbUsername = flags.DBUsername
				if dbUsername == "" {
					switch dbType {
					case "mysql":
						dbUsername = "root"
					case "postgres":
						dbUsername = "postgres"
					case "mssql":
						dbUsername = "sa"
					}
				}
				dbPassword = flags.DBPassword
				if dbPassword == "" {
					dbPassword = generateRandomString(16)
					printInfo("Generated database password: %s", dbPassword)
				}
				printInfo("Database host: %s:%s", dbHost, dbPort)
				printInfo("Database name: %s", dbName)
				printInfo("Database user: %s", dbUsername)
			} else {
				fmt.Println()
				if deploymentType == "3" {
					fmt.Println("STEP 6: Database connection")
				} else {
					fmt.Println("STEP 5: Database connection")
				}
				fmt.Println("----------------------------")
				fmt.Println("Enter your database connection details.")
				fmt.Println()
				if deploymentType == "3" {
					fmt.Printf("%sTip:%s If using a managed database service (Supabase, PlanetScale, Neon, etc.),\n", colorYellow, colorReset)
					fmt.Println("     use the connection pooler endpoint for better compatibility.")
					fmt.Println("     Direct connections may use IPv6 which some clusters don't support.")
					fmt.Println()
				}

				var defaultHost string
				if deploymentType == "4" {
					defaultHost = "localhost"
				} else {
					switch dbType {
					case "mysql":
						defaultHost = "mysql-service"
					case "postgres":
						defaultHost = "postgres-service"
					case "mssql":
						defaultHost = "mssql-service"
					}
				}

				// Loop to allow re-entering database details on connection failure
				for {
					dbHost = promptHostname(rl, "Database host", defaultHost)
					dbPort = promptPort(rl, "Database port", dbPort)
					dbName = promptDatabaseName(rl, "Database name", "goiabada")

					var defaultUsername string
					switch dbType {
					case "mysql":
						defaultUsername = "root"
					case "postgres":
						defaultUsername = "postgres"
					case "mssql":
						defaultUsername = "sa"
					}
					dbUsername = promptNonEmpty(rl, "Database username", defaultUsername)
					dbPassword = promptNonEmpty(rl, "Database password", generateRandomString(16))

					// Test database connection
					fmt.Println()
					if !promptYesNo(rl, "Test database connection?", true) {
						break // User chose to skip test
					}

					if testDatabaseConnection(dbType, dbHost, dbPort, dbName, dbUsername, dbPassword) {
						break // Connection successful
					}

					// Connection failed - offer options
					fmt.Println()
					fmt.Println("What would you like to do?")
					fmt.Println("1. Re-enter database details")
					fmt.Println("2. Continue anyway (configuration will be generated)")
					fmt.Println("3. Abort setup")
					fmt.Println()
					choice := promptChoice(rl, "Select option [1-3]", []string{"1", "2", "3"}, "1")

					switch choice {
					case "1":
						fmt.Println()
						fmt.Println("Re-enter database connection details:")
						fmt.Println()
						continue // Loop back to re-enter details
					case "2":
						printWarning("Continuing without successful database connection test.")
						fmt.Println("Make sure the database is running and accessible before deployment.")
					case "3":
						fmt.Println("Aborted.")
						os.Exit(0)
					}
					break
				}
			}

			// Test database connection in non-interactive mode
			if !flags.SkipDBTest && nonInteractive {
				if !testDatabaseConnection(dbType, dbHost, dbPort, dbName, dbUsername, dbPassword) {
					printWarning("Database connection test failed. Configuration will still be generated.")
				}
			}
		} else {
			// Docker only needs password
			if nonInteractive {
				dbPassword = flags.DBPassword
				if dbPassword == "" {
					dbPassword = generateRandomString(16)
				}
				printInfo("Database password: %s", dbPassword)
			} else {
				fmt.Println()
				fmt.Println("STEP 5: Database password")
				fmt.Println("--------------------------")
				dbPassword = promptNonEmpty(rl, "Database password", generateRandomString(16))
			}
		}
	}

	// Generate credentials
	fmt.Println()
	if deploymentType == "3" {
		fmt.Println("STEP 7: Generating credentials")
	} else if deploymentType == "4" && dbType != "sqlite" {
		fmt.Println("STEP 6: Generating credentials")
	} else {
		fmt.Println("STEP 5: Generating credentials")
	}
	fmt.Println("-------------------------------")

	authSessionAuthKey := generateHexKey(64)
	authSessionEncKey := generateHexKey(32)
	adminSessionAuthKey := generateHexKey(64)
	adminSessionEncKey := generateHexKey(32)
	oauthClientSecret := generateRandomString(60)

	printSuccess("Auth server session keys generated")
	printSuccess("Admin console session keys generated")
	printSuccess("OAuth client secret generated")

	// Build config
	config := &Config{
		DeploymentType:      deploymentType,
		DBType:              dbType,
		DBImage:             dbImage,
		DBPort:              dbPort,
		DBHost:              dbHost,
		DBName:              dbName,
		DBUsername:          dbUsername,
		DBPassword:          dbPassword,
		AuthServerURL:       authServerURL,
		AdminConsoleURL:     adminConsoleURL,
		AdminEmail:          adminEmail,
		AdminPassword:       adminPassword,
		AuthSessionAuthKey:  authSessionAuthKey,
		AuthSessionEncKey:   authSessionEncKey,
		AdminSessionAuthKey: adminSessionAuthKey,
		AdminSessionEncKey:  adminSessionEncKey,
		OAuthClientID:       "admin-console-client",
		OAuthClientSecret:   oauthClientSecret,
		K8sNamespace:        k8sNamespace,
	}

	// Show summary and confirm (interactive mode only)
	if !nonInteractive {
		fmt.Println()
		printSummary(config)
		fmt.Println()
		if !promptYesNo(rl, "Generate configuration files?", true) {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}

	// Determine output directory
	outputDir, _ := os.Getwd()
	if flags.Output != "" {
		// Check if it's a directory or file path
		info, err := os.Stat(flags.Output)
		if err == nil && info.IsDir() {
			outputDir = flags.Output
		} else {
			outputDir = filepath.Dir(flags.Output)
		}
	}

	// Generate configuration files
	fmt.Println()
	if deploymentType == "3" {
		fmt.Println("STEP 8: Generating configuration")
	} else if deploymentType == "4" && dbType != "sqlite" {
		fmt.Println("STEP 7: Generating configuration")
	} else {
		fmt.Println("STEP 6: Generating configuration")
	}
	fmt.Println("----------------------------------")

	switch deploymentType {
	case "3":
		// Generate Kubernetes manifests
		k8sManifest := generateKubernetesManifests(config)
		filename := "goiabada-k8s.yaml"
		if flags.Output != "" && !isDirectory(flags.Output) {
			filename = filepath.Base(flags.Output)
		}
		k8sPath := filepath.Join(outputDir, filename)
		err := os.WriteFile(k8sPath, []byte(k8sManifest), 0644)
		if err != nil {
			printError("Error writing %s: %v", filename, err)
			os.Exit(1)
		}
		printSuccess("Created: %s", k8sPath)

		// Done message for Kubernetes
		printCompletionMessage(config, k8sPath)
	case "4":
		// Generate environment file for native binaries
		envFile := generateEnvFile(config)
		filename := "goiabada.env"
		if flags.Output != "" && !isDirectory(flags.Output) {
			filename = filepath.Base(flags.Output)
		}
		envPath := filepath.Join(outputDir, filename)
		err := os.WriteFile(envPath, []byte(envFile), 0644)
		if err != nil {
			printError("Error writing %s: %v", filename, err)
			os.Exit(1)
		}
		printSuccess("Created: %s", envPath)

		// Done message for native binaries
		printCompletionMessage(config, envPath)
	default:
		// Generate docker-compose.yml
		dockerCompose := generateDockerCompose(config)
		filename := "docker-compose.yml"
		if flags.Output != "" && !isDirectory(flags.Output) {
			filename = filepath.Base(flags.Output)
		}
		dockerComposePath := filepath.Join(outputDir, filename)
		err := os.WriteFile(dockerComposePath, []byte(dockerCompose), 0644)
		if err != nil {
			printError("Error writing %s: %v", filename, err)
			os.Exit(1)
		}
		printSuccess("Created: %s", dockerComposePath)

		// Done message for Docker
		printCompletionMessage(config, dockerComposePath)
	}
}

// Config holds all configuration values
type Config struct {
	DeploymentType      string
	DBType              string
	DBImage             string
	DBPort              string
	DBHost              string
	DBName              string
	DBUsername          string
	DBPassword          string
	AuthServerURL       string
	AdminConsoleURL     string
	AdminEmail          string
	AdminPassword       string
	AuthSessionAuthKey  string
	AuthSessionEncKey   string
	AdminSessionAuthKey string
	AdminSessionEncKey  string
	OAuthClientID       string
	OAuthClientSecret   string
	K8sNamespace        string
}

// ============================================================================
// Color and output functions
// ============================================================================

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func disableColors() {
	colorReset = ""
	colorRed = ""
	colorGreen = ""
	colorYellow = ""
	colorCyan = ""
	colorBold = ""
}

func printBanner() {
	fmt.Printf("%s================================================================================\n", colorCyan)
	fmt.Printf("                         GOIABADA SETUP WIZARD v%s\n", version)
	fmt.Printf("================================================================================%s\n", colorReset)
	fmt.Println()
	fmt.Println("This wizard will help you set up Goiabada by generating configuration files")
	fmt.Println("with all credentials pre-configured.")
	fmt.Println()
}

func printSuccess(format string, args ...interface{}) {
	fmt.Printf("%s✓%s %s\n", colorGreen, colorReset, fmt.Sprintf(format, args...))
}

func printWarning(format string, args ...interface{}) {
	fmt.Printf("%s⚠️  Warning:%s %s\n", colorYellow, colorReset, fmt.Sprintf(format, args...))
}

func printError(format string, args ...interface{}) {
	fmt.Printf("%s✗ Error:%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
}

func printInfo(format string, args ...interface{}) {
	fmt.Printf("%s→%s %s\n", colorCyan, colorReset, fmt.Sprintf(format, args...))
}

func printSummary(config *Config) {
	fmt.Printf("%s%s================== Configuration Summary ==================%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("  Deployment:       %s\n", getDeploymentTypeName(config.DeploymentType))
	fmt.Printf("  Database:         %s\n", config.DBType)
	fmt.Printf("  Auth Server URL:  %s\n", config.AuthServerURL)
	fmt.Printf("  Admin Console:    %s\n", config.AdminConsoleURL)
	if config.K8sNamespace != "" {
		fmt.Printf("  K8s Namespace:    %s\n", config.K8sNamespace)
	}
	fmt.Printf("  Admin Email:      %s\n", config.AdminEmail)
	fmt.Printf("  Admin Password:   %s\n", maskPassword(config.AdminPassword))
	if config.DBHost != "" {
		fmt.Printf("  DB Host:          %s:%s\n", config.DBHost, config.DBPort)
		fmt.Printf("  DB Name:          %s\n", config.DBName)
		fmt.Printf("  DB Username:      %s\n", config.DBUsername)
	}
	fmt.Println()
	fmt.Printf("%s%s==========================================================%s\n", colorBold, colorCyan, colorReset)
}

func printCompletionMessage(config *Config, outputPath string) {
	fmt.Println()
	fmt.Printf("%s%s================================================================================\n", colorBold, colorGreen)
	fmt.Printf("                            SETUP COMPLETE!\n")
	fmt.Printf("================================================================================%s\n", colorReset)
	fmt.Println()

	switch config.DeploymentType {
	case "3":
		fmt.Println("To deploy Goiabada to Kubernetes:")
		fmt.Println()
		fmt.Printf("    %skubectl apply -f %s%s\n", colorCyan, filepath.Base(outputPath), colorReset)
		fmt.Println()

		fmt.Printf("%s%sPREREQUISITES%s\n", colorBold, colorYellow, colorReset)
		fmt.Println()
		fmt.Println("Before deploying, ensure you have:")
		fmt.Println()
		fmt.Println("  1. ingress-nginx installed (with externalTrafficPolicy: Cluster for better compatibility):")
		fmt.Printf("     %scurl -s https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.14.0/deploy/static/provider/cloud/deploy.yaml | sed 's/externalTrafficPolicy: Local/externalTrafficPolicy: Cluster/' | kubectl apply -f -%s\n", colorCyan, colorReset)
		fmt.Println("     (Check https://github.com/kubernetes/ingress-nginx/releases for latest version)")
		fmt.Println()
		fmt.Println("     Wait for it to be ready:")
		fmt.Printf("     %skubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=120s%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("  2. cert-manager for automatic TLS certificates:")
		fmt.Printf("     %skubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.1/cert-manager.yaml%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("     Wait for it to be ready:")
		fmt.Printf("     %skubectl wait --namespace cert-manager --for=condition=ready pod --selector=app.kubernetes.io/instance=cert-manager --timeout=120s%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("     Then create a ClusterIssuer (save as letsencrypt-issuer.yaml):")
		fmt.Println("     ---")
		fmt.Println("     apiVersion: cert-manager.io/v1")
		fmt.Println("     kind: ClusterIssuer")
		fmt.Println("     metadata:")
		fmt.Println("       name: letsencrypt-prod")
		fmt.Println("     spec:")
		fmt.Println("       acme:")
		fmt.Println("         server: https://acme-v02.api.letsencrypt.org/directory")
		fmt.Println("         email: <your-email>")
		fmt.Println("         privateKeySecretRef:")
		fmt.Println("           name: letsencrypt-prod")
		fmt.Println("         solvers:")
		fmt.Println("         - http01:")
		fmt.Println("             ingress:")
		fmt.Println("               class: nginx")
		fmt.Println()
		fmt.Printf("     %skubectl apply -f letsencrypt-issuer.yaml%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("  3. DNS records pointing to your LoadBalancer IP:")
		fmt.Println("     After deploying, get the LoadBalancer IP:")
		fmt.Printf("     %skubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'%s\n", colorCyan, colorReset)
		fmt.Printf("     %s<auth-host>  -> <LoadBalancer-IP>%s\n", colorCyan, colorReset)
		fmt.Printf("     %s<admin-host> -> <LoadBalancer-IP>%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("     The generated manifest already has cert-manager annotation enabled.")
		fmt.Println("     Remove it if you prefer to manage TLS certificates manually.")
		fmt.Println()

		fmt.Printf("%s%sIMPORTANT NOTES%s\n", colorBold, colorYellow, colorReset)
		fmt.Println()
		fmt.Println("  • The database must be empty for a fresh deployment. Goiabada will")
		fmt.Println("    automatically seed the database with initial data including the")
		fmt.Println("    admin user and OAuth clients configured with the URLs above.")
		fmt.Println("    If redeploying with different URLs, use a fresh database.")
		fmt.Println()
		fmt.Println("  • If using a managed database service (Supabase, PlanetScale, etc.),")
		fmt.Println("    use the connection pooler endpoint for better compatibility (IPv4).")
		fmt.Println()

		fmt.Printf("%s%sTROUBLESHOOTING TIPS%s\n", colorBold, colorYellow, colorReset)
		fmt.Println()
		fmt.Println("  • If cert-manager HTTP-01 challenges fail or timeout:")
		fmt.Println("    - Verify DNS records point to the LoadBalancer IP")
		fmt.Println("    - Ensure port 80 is accessible from the internet")
		fmt.Println("    - If you didn't use the install command above (with sed), patch the service:")
		fmt.Printf("      %skubectl patch svc ingress-nginx-controller -n ingress-nginx -p '{\"spec\":{\"externalTrafficPolicy\":\"Cluster\"}}'%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("  • Check Ingress status:")
		fmt.Printf("      %skubectl get ingress -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
		fmt.Printf("      %skubectl describe ingress -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
		fmt.Println()
		fmt.Println("  • Check certificates:")
		fmt.Printf("      %skubectl get certificates -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
		fmt.Println()
		fmt.Println("  • Verify pods are running:")
		fmt.Printf("      %skubectl get pods -n %s%s\n", colorCyan, config.K8sNamespace, colorReset)
		fmt.Println()
		fmt.Println("  • Check pod logs for errors:")
		fmt.Printf("      %skubectl logs -n %s deployment/goiabada-authserver%s\n", colorCyan, config.K8sNamespace, colorReset)
		fmt.Println()
	case "4":
		fmt.Println("To run Goiabada with native binaries:")
		fmt.Println()
		fmt.Printf("%s%s1. DOWNLOAD BINARIES%s\n", colorBold, colorYellow, colorReset)
		fmt.Println()
		fmt.Println("  Download the pre-built binaries for your platform from:")
		fmt.Printf("  %shttps://github.com/leodip/goiabada/releases%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("  Extract the binaries:")
		fmt.Printf("  %star -xzf goiabada-<version>-<os>-<arch>.tar.gz%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Printf("%s%s2. START THE SERVERS%s\n", colorBold, colorYellow, colorReset)
		fmt.Println()
		fmt.Println("  Load the environment and start both servers (in separate terminals):")
		fmt.Println()
		fmt.Println("  Auth server:")
		fmt.Printf("  %ssource %s && ./goiabada-authserver%s\n", colorCyan, filepath.Base(outputPath), colorReset)
		fmt.Println()
		fmt.Println("  Admin console:")
		fmt.Printf("  %ssource %s && ./goiabada-adminconsole%s\n", colorCyan, filepath.Base(outputPath), colorReset)
		fmt.Println()
		fmt.Printf("%s%sIMPORTANT NOTES%s\n", colorBold, colorYellow, colorReset)
		fmt.Println()
		fmt.Println("  • The environment file contains sensitive secrets. Keep it secure!")
		fmt.Println()
		fmt.Println("  • The database must be empty for a fresh deployment. Goiabada will")
		fmt.Println("    automatically seed the database with initial data including the")
		fmt.Println("    admin user and OAuth clients configured with the URLs above.")
		fmt.Println()
		fmt.Println("  • For production, consider using a process manager like systemd")
		fmt.Println("    to keep the services running and restart them on failure.")
		fmt.Println()
	default:
		fmt.Println("To start Goiabada, run:")
		fmt.Println()
		fmt.Printf("    %sdocker compose up -d%s\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Println("Then access:")
	}

	fmt.Println()
	fmt.Println("URLs:")
	fmt.Printf("    Auth Server:   %s%s%s\n", colorCyan, config.AuthServerURL, colorReset)
	fmt.Printf("    Admin Console: %s%s%s\n", colorCyan, config.AdminConsoleURL, colorReset)
	fmt.Println()
	fmt.Printf("Login with: %s%s%s / %s\n", colorBold, config.AdminEmail, colorReset, config.AdminPassword)
	fmt.Println()
	if config.AdminPassword == "changeme" || len(config.AdminPassword) < 8 {
		printWarning("Change the default password after first login!")
		fmt.Println()
	}
}

func getDeploymentTypeName(t string) string {
	switch t {
	case "1":
		return "Local testing (Docker)"
	case "2":
		return "Production with reverse proxy"
	case "3":
		return "Kubernetes"
	case "4":
		return "Native binaries"
	}
	return "Unknown"
}

func maskPassword(password string) string {
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}

// ============================================================================
// Prompt functions
// ============================================================================

func promptString(rl *readline.Instance, prompt, defaultValue string) string {
	var promptStr string
	if defaultValue != "" {
		promptStr = fmt.Sprintf("%s [%s]: ", prompt, defaultValue)
	} else {
		promptStr = fmt.Sprintf("%s: ", prompt)
	}
	rl.SetPrompt(promptStr)
	input, err := rl.Readline()
	if err != nil {
		if err == io.EOF || err == readline.ErrInterrupt {
			fmt.Println("\nAborted.")
			os.Exit(0)
		}
		return defaultValue
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

func promptChoice(rl *readline.Instance, prompt string, validChoices []string, defaultValue string) string {
	for {
		promptStr := fmt.Sprintf("%s [%s]: ", prompt, defaultValue)
		rl.SetPrompt(promptStr)
		input, err := rl.Readline()
		if err != nil {
			if err == io.EOF || err == readline.ErrInterrupt {
				fmt.Println("\nAborted.")
				os.Exit(0)
			}
			return defaultValue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return defaultValue
		}
		for _, valid := range validChoices {
			if input == valid {
				return input
			}
		}
		fmt.Println("Invalid choice. Please try again.")
	}
}

func promptYesNo(rl *readline.Instance, prompt string, defaultYes bool) bool {
	defaultStr := "Y/n"
	if !defaultYes {
		defaultStr = "y/N"
	}
	for {
		promptStr := fmt.Sprintf("%s [%s]: ", prompt, defaultStr)
		rl.SetPrompt(promptStr)
		input, err := rl.Readline()
		if err != nil {
			if err == io.EOF || err == readline.ErrInterrupt {
				fmt.Println("\nAborted.")
				os.Exit(0)
			}
			return defaultYes
		}
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "" {
			return defaultYes
		}
		if input == "y" || input == "yes" {
			return true
		}
		if input == "n" || input == "no" {
			return false
		}
		fmt.Println("Please enter 'y' or 'n'.")
	}
}

func promptURL(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateURL(value); err != nil {
			fmt.Printf("Invalid URL: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptEmail(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateEmail(value); err != nil {
			fmt.Printf("Invalid email: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptHostname(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateHostname(value); err != nil {
			fmt.Printf("Invalid hostname: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptPort(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validatePort(value); err != nil {
			fmt.Printf("Invalid port: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptNonEmpty(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if value == "" {
			fmt.Println("This field cannot be empty. Please try again.")
			continue
		}
		return value
	}
}

func promptNamespace(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateNamespace(value); err != nil {
			fmt.Printf("Invalid namespace: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptDatabaseName(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateDatabaseName(value); err != nil {
			fmt.Printf("Invalid database name: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptPassword(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if value == "" {
			fmt.Println("Password cannot be empty. Please try again.")
			continue
		}
		// Check password strength
		issues := checkPasswordStrength(value)
		if len(issues) > 0 {
			printWarning("Weak password: %s", strings.Join(issues, ", "))
			if !promptYesNo(rl, "Use this password anyway?", false) {
				continue
			}
		}
		return value
	}
}

// ============================================================================
// Validation functions
// ============================================================================

func validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}
	hostname := strings.TrimPrefix(urlStr, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	return validateHostname(hostname)
}

func validateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}
	for i, c := range hostname {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return fmt.Errorf("invalid character '%c' at position %d (only a-z, 0-9, '-', '.' allowed)", c, i)
		}
	}
	if hostname[0] == '-' || hostname[0] == '.' {
		return fmt.Errorf("hostname cannot start with '%c'", hostname[0])
	}
	if hostname[len(hostname)-1] == '-' || hostname[len(hostname)-1] == '.' {
		return fmt.Errorf("hostname cannot end with '%c'", hostname[len(hostname)-1])
	}
	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	atIndex := strings.Index(email, "@")
	if atIndex == -1 {
		return fmt.Errorf("email must contain '@'")
	}
	if atIndex == 0 {
		return fmt.Errorf("email must have text before '@'")
	}
	if atIndex == len(email)-1 {
		return fmt.Errorf("email must have text after '@'")
	}
	if strings.Count(email, "@") > 1 {
		return fmt.Errorf("email must contain only one '@'")
	}
	domain := email[atIndex+1:]
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("email domain must contain '.'")
	}
	return nil
}

func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}
	portNum := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return fmt.Errorf("port must be a number")
		}
		portNum = portNum*10 + int(c-'0')
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func validateNamespace(ns string) error {
	if ns == "" {
		return fmt.Errorf("namespace cannot be empty")
	}
	if len(ns) > 63 {
		return fmt.Errorf("namespace too long (max 63 characters)")
	}
	for i, c := range ns {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return fmt.Errorf("invalid character '%c' at position %d (only lowercase a-z, 0-9, '-' allowed)", c, i)
		}
	}
	if ns[0] >= '0' && ns[0] <= '9' {
		return fmt.Errorf("namespace must start with a letter")
	}
	if ns[0] == '-' {
		return fmt.Errorf("namespace cannot start with '-'")
	}
	if ns[len(ns)-1] == '-' {
		return fmt.Errorf("namespace cannot end with '-'")
	}
	return nil
}

func validateDatabaseName(name string) error {
	if name == "" {
		return fmt.Errorf("database name cannot be empty")
	}
	if len(name) > 63 {
		return fmt.Errorf("database name too long (max 63 characters)")
	}
	for i, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return fmt.Errorf("invalid character '%c' at position %d (only a-z, A-Z, 0-9, '_' allowed)", c, i)
		}
	}
	if name[0] >= '0' && name[0] <= '9' {
		return fmt.Errorf("database name must start with a letter")
	}
	return nil
}

func checkPasswordStrength(password string) []string {
	var issues []string
	if len(password) < 8 {
		issues = append(issues, "less than 8 characters")
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, c := range password {
		if unicode.IsUpper(c) {
			hasUpper = true
		} else if unicode.IsLower(c) {
			hasLower = true
		} else if unicode.IsDigit(c) {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}
	if !hasUpper {
		issues = append(issues, "no uppercase letter")
	}
	if !hasLower {
		issues = append(issues, "no lowercase letter")
	}
	if !hasDigit {
		issues = append(issues, "no digit")
	}
	if !hasSpecial {
		issues = append(issues, "no special character")
	}
	return issues
}

// ============================================================================
// Helper functions
// ============================================================================

func extractDomainFromURL(urlStr string) string {
	hostname := strings.TrimPrefix(urlStr, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}

func generateHexKey(bytes int) string {
	key := make([]byte, bytes)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(key)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// ============================================================================
// Database connection test
// ============================================================================

// testDatabaseConnection returns true if connection succeeded, false otherwise
func testDatabaseConnection(dbType, host, port, name, user, password string) bool {
	fmt.Print("Testing database connection... ")

	var dsn string
	var driver string

	switch dbType {
	case "mysql":
		driver = "mysql"
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?timeout=5s", user, password, host, port, name)
	case "postgres":
		driver = "postgres"
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require connect_timeout=5", host, port, user, password, name)
	case "mssql":
		driver = "sqlserver"
		dsn = fmt.Sprintf("sqlserver://%s:%s@%s:%s?database=%s&connection+timeout=5", user, password, host, port, name)
	default:
		printWarning("Database connection test not supported for %s", dbType)
		return true // Skip unsupported databases
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		printError("Failed to open connection: %v", err)
		return false
	}
	defer db.Close()

	db.SetConnMaxLifetime(5 * time.Second)

	err = db.Ping()
	if err != nil {
		printError("Connection failed: %v", err)
		return false
	}

	printSuccess("Connection successful!")

	// Check if database has Goiabada tables (indicating it's not empty)
	checkDatabaseEmpty(db, dbType)

	return true
}

// checkDatabaseEmpty checks if the database already has Goiabada tables
// and warns the user if it does
func checkDatabaseEmpty(db *sql.DB, dbType string) {
	fmt.Print("Checking if database is empty... ")

	var query string
	switch dbType {
	case "mysql":
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'"
	case "postgres":
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'"
	case "mssql":
		query = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users'"
	default:
		fmt.Println("skipped")
		return
	}

	var count int
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		// If we can't check, just skip
		fmt.Println("skipped")
		return
	}

	if count > 0 {
		fmt.Println()
		printWarning("Database already contains Goiabada tables!")
		fmt.Println()
		fmt.Printf("  %sThe 'users' table exists, indicating this database was used before.%s\n", colorYellow, colorReset)
		fmt.Printf("  %sIf you're deploying with different URLs than before, the OAuth client%s\n", colorYellow, colorReset)
		fmt.Printf("  %sconfiguration will not match and authentication will fail.%s\n", colorYellow, colorReset)
		fmt.Println()
		fmt.Printf("  %sOptions:%s\n", colorBold, colorReset)
		fmt.Println("    1. Use the same URLs as the previous deployment")
		fmt.Println("    2. Use a fresh/empty database")
		fmt.Println("    3. Manually update the OAuth client redirect URIs in the database")
		fmt.Println()
	} else {
		printSuccess("Database is empty (ready for fresh deployment)")
	}
}

// ============================================================================
// Docker Compose generation
// ============================================================================

func generateDockerCompose(config *Config) string {
	var sb strings.Builder

	sb.WriteString("# Generated by goiabada-setup\n")
	sb.WriteString("# Run: docker compose up -d\n\n")
	sb.WriteString("services:\n\n")

	if config.DBType != "sqlite" {
		sb.WriteString(generateDBService(config))
	}

	sb.WriteString(generateAuthServerService(config))
	sb.WriteString(generateAdminConsoleService(config))

	sb.WriteString("\nvolumes:\n")
	switch config.DBType {
	case "mysql":
		sb.WriteString("  mysql-data:\n")
	case "postgres":
		sb.WriteString("  postgres-data:\n")
	case "mssql":
		sb.WriteString("  mssql-data:\n")
	case "sqlite":
		sb.WriteString("  sqlite-data:\n")
	}

	sb.WriteString("\nnetworks:\n")
	sb.WriteString("  goiabada-network:\n")

	return sb.String()
}

func generateDBService(config *Config) string {
	var sb strings.Builder

	switch config.DBType {
	case "mysql":
		sb.WriteString("  mysql-server:\n")
		sb.WriteString("    image: mysql:latest\n")
		sb.WriteString("    restart: unless-stopped\n")
		sb.WriteString("    volumes:\n")
		sb.WriteString("      - mysql-data:/var/lib/mysql\n")
		sb.WriteString("    environment:\n")
		sb.WriteString(fmt.Sprintf("      MYSQL_ROOT_PASSWORD: %s\n", config.DBPassword))
		sb.WriteString("    healthcheck:\n")
		sb.WriteString(fmt.Sprintf("      test: [\"CMD\", \"mysqladmin\", \"ping\", \"-uroot\", \"-p%s\", \"--protocol\", \"tcp\"]\n", config.DBPassword))
		sb.WriteString("      interval: 1s\n")
		sb.WriteString("      timeout: 2s\n")
		sb.WriteString("      retries: 20\n")
		sb.WriteString("    networks:\n")
		sb.WriteString("      - goiabada-network\n\n")

	case "postgres":
		sb.WriteString("  postgres-server:\n")
		sb.WriteString("    image: postgres:latest\n")
		sb.WriteString("    restart: unless-stopped\n")
		sb.WriteString("    volumes:\n")
		sb.WriteString("      - postgres-data:/var/lib/postgresql\n")
		sb.WriteString("    environment:\n")
		sb.WriteString(fmt.Sprintf("      POSTGRES_PASSWORD: %s\n", config.DBPassword))
		sb.WriteString("      POSTGRES_DB: goiabada\n")
		sb.WriteString("    healthcheck:\n")
		sb.WriteString("      test: [\"CMD-SHELL\", \"pg_isready -U postgres\"]\n")
		sb.WriteString("      interval: 1s\n")
		sb.WriteString("      timeout: 2s\n")
		sb.WriteString("      retries: 20\n")
		sb.WriteString("    networks:\n")
		sb.WriteString("      - goiabada-network\n\n")

	case "mssql":
		sb.WriteString("  mssql-server:\n")
		sb.WriteString("    image: mcr.microsoft.com/mssql/server:2022-latest\n")
		sb.WriteString("    restart: unless-stopped\n")
		sb.WriteString("    volumes:\n")
		sb.WriteString("      - mssql-data:/var/opt/mssql\n")
		sb.WriteString("    environment:\n")
		sb.WriteString("      ACCEPT_EULA: Y\n")
		sb.WriteString(fmt.Sprintf("      MSSQL_SA_PASSWORD: %s\n", config.DBPassword))
		sb.WriteString("    healthcheck:\n")
		sb.WriteString(fmt.Sprintf("      test: [\"CMD-SHELL\", \"/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P '%s' -C -Q 'SELECT 1' || exit 1\"]\n", config.DBPassword))
		sb.WriteString("      interval: 10s\n")
		sb.WriteString("      timeout: 5s\n")
		sb.WriteString("      retries: 20\n")
		sb.WriteString("    networks:\n")
		sb.WriteString("      - goiabada-network\n\n")
	}

	return sb.String()
}

func generateAuthServerService(config *Config) string {
	var sb strings.Builder

	isProduction := config.DeploymentType == "2"
	setCookieSecure := "false"
	trustProxyHeaders := "false"
	if isProduction {
		setCookieSecure = "true"
		trustProxyHeaders = "true"
	}

	authInternalURL := "http://goiabada-authserver:9090"

	sb.WriteString("  goiabada-authserver:\n")
	sb.WriteString("    image: leodip/goiabada:authserver-1.4.1\n")
	sb.WriteString("    restart: unless-stopped\n")

	if config.DBType != "sqlite" {
		var dbServiceName string
		switch config.DBType {
		case "mysql":
			dbServiceName = "mysql-server"
		case "postgres":
			dbServiceName = "postgres-server"
		case "mssql":
			dbServiceName = "mssql-server"
		}
		sb.WriteString("    depends_on:\n")
		sb.WriteString(fmt.Sprintf("      %s:\n", dbServiceName))
		sb.WriteString("        condition: service_healthy\n")
	}

	// Always expose ports - for local testing expose to all interfaces,
	// for production bind to localhost only (nginx access)
	sb.WriteString("    ports:\n")
	if isProduction {
		sb.WriteString("      - 127.0.0.1:9090:9090\n")
	} else {
		sb.WriteString("      - 9090:9090\n")
	}

	sb.WriteString("    networks:\n")
	sb.WriteString("      - goiabada-network\n")
	sb.WriteString("    healthcheck:\n")
	sb.WriteString("      test: [\"CMD\", \"wget\", \"--spider\", \"http://localhost:9090/health\"]\n")
	sb.WriteString("      interval: 10s\n")
	sb.WriteString("      timeout: 5s\n")
	sb.WriteString("      retries: 3\n")
	sb.WriteString("      start_period: 10s\n")

	if config.DBType == "sqlite" {
		sb.WriteString("    volumes:\n")
		sb.WriteString("      - sqlite-data:/data\n")
	}

	sb.WriteString("    environment:\n")
	sb.WriteString("      - TZ=UTC\n")
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMIN_EMAIL=%s\n", config.AdminEmail))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMIN_PASSWORD=%s\n", config.AdminPassword))
	sb.WriteString("      - GOIABADA_APPNAME=Goiabada\n")
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_BASEURL=%s\n", config.AuthServerURL))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_INTERNALBASEURL=%s\n", authInternalURL))
	sb.WriteString("      - GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP=0.0.0.0\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=9090\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS=\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS=\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_CERTFILE=\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_KEYFILE=\n")
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS=%s\n", trustProxyHeaders))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_SET_COOKIE_SECURE=%s\n", setCookieSecure))
	sb.WriteString("      - GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS=true\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_LOG_SQL=false\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE=true\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_STATICDIR=\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_TEMPLATEDIR=\n")
	sb.WriteString("      - GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS=false\n")
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=%s\n", config.AuthSessionAuthKey))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=%s\n", config.AuthSessionEncKey))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=%s\n", config.OAuthClientSecret))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_DB_TYPE=%s\n", config.DBType))

	switch config.DBType {
	case "mysql":
		sb.WriteString("      - GOIABADA_DB_USERNAME=root\n")
		sb.WriteString(fmt.Sprintf("      - GOIABADA_DB_PASSWORD=%s\n", config.DBPassword))
		sb.WriteString("      - GOIABADA_DB_HOST=mysql-server\n")
		sb.WriteString("      - GOIABADA_DB_PORT=3306\n")
		sb.WriteString("      - GOIABADA_DB_NAME=goiabada\n")
	case "postgres":
		sb.WriteString("      - GOIABADA_DB_USERNAME=postgres\n")
		sb.WriteString(fmt.Sprintf("      - GOIABADA_DB_PASSWORD=%s\n", config.DBPassword))
		sb.WriteString("      - GOIABADA_DB_HOST=postgres-server\n")
		sb.WriteString("      - GOIABADA_DB_PORT=5432\n")
		sb.WriteString("      - GOIABADA_DB_NAME=goiabada\n")
	case "mssql":
		sb.WriteString("      - GOIABADA_DB_USERNAME=sa\n")
		sb.WriteString(fmt.Sprintf("      - GOIABADA_DB_PASSWORD=%s\n", config.DBPassword))
		sb.WriteString("      - GOIABADA_DB_HOST=mssql-server\n")
		sb.WriteString("      - GOIABADA_DB_PORT=1433\n")
		sb.WriteString("      - GOIABADA_DB_NAME=goiabada\n")
	case "sqlite":
		sb.WriteString("      - GOIABADA_DB_DSN=/data/goiabada.db\n")
	}

	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_BASEURL=%s\n", config.AdminConsoleURL))
	sb.WriteString("\n")

	return sb.String()
}

func generateAdminConsoleService(config *Config) string {
	var sb strings.Builder

	isProduction := config.DeploymentType == "2"
	setCookieSecure := "false"
	trustProxyHeaders := "false"
	if isProduction {
		setCookieSecure = "true"
		trustProxyHeaders = "true"
	}

	authInternalURL := "http://goiabada-authserver:9090"

	sb.WriteString("  goiabada-adminconsole:\n")
	sb.WriteString("    image: leodip/goiabada:adminconsole-1.4.1\n")
	sb.WriteString("    restart: unless-stopped\n")
	sb.WriteString("    depends_on:\n")
	sb.WriteString("      goiabada-authserver:\n")
	sb.WriteString("        condition: service_healthy\n")

	// Always expose ports - for local testing expose to all interfaces,
	// for production bind to localhost only (nginx access)
	sb.WriteString("    ports:\n")
	if isProduction {
		sb.WriteString("      - 127.0.0.1:9091:9091\n")
	} else {
		sb.WriteString("      - 9091:9091\n")
	}

	sb.WriteString("    networks:\n")
	sb.WriteString("      - goiabada-network\n")
	sb.WriteString("    environment:\n")
	sb.WriteString("      - TZ=UTC\n")
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID=%s\n", config.OAuthClientID))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=%s\n", config.OAuthClientSecret))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=%s\n", config.AdminSessionAuthKey))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=%s\n", config.AdminSessionEncKey))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_BASEURL=%s\n", config.AdminConsoleURL))
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=0.0.0.0\n")
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=9091\n")
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS=\n")
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS=\n")
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_CERTFILE=\n")
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_KEYFILE=\n")
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=%s\n", trustProxyHeaders))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE=%s\n", setCookieSecure))
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS=true\n")
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_STATICDIR=\n")
	sb.WriteString("      - GOIABADA_ADMINCONSOLE_TEMPLATEDIR=\n")
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_BASEURL=%s\n", config.AuthServerURL))
	sb.WriteString(fmt.Sprintf("      - GOIABADA_AUTHSERVER_INTERNALBASEURL=%s\n", authInternalURL))
	sb.WriteString("\n")

	return sb.String()
}

// ============================================================================
// Environment file generation (for native binaries)
// ============================================================================

func generateEnvFile(config *Config) string {
	var sb strings.Builder

	sb.WriteString("# Generated by goiabada-setup\n")
	sb.WriteString("# Environment file for native binary deployment\n")
	sb.WriteString("#\n")
	sb.WriteString("# Usage:\n")
	sb.WriteString("#   source goiabada.env && ./goiabada-authserver\n")
	sb.WriteString("#   source goiabada.env && ./goiabada-adminconsole\n")
	sb.WriteString("#\n")
	sb.WriteString("# Or with systemd, add EnvironmentFile=/path/to/goiabada.env\n")
	sb.WriteString("#\n")
	sb.WriteString("# IMPORTANT: The database must be empty for initial deployment.\n")
	sb.WriteString("# Goiabada will seed it with OAuth clients configured for the URLs below.\n")
	sb.WriteString("\n")

	sb.WriteString("# =============================================================================\n")
	sb.WriteString("# Application settings\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString("export GOIABADA_APPNAME=\"Goiabada\"\n")
	sb.WriteString(fmt.Sprintf("export GOIABADA_ADMIN_EMAIL=\"%s\"\n", config.AdminEmail))
	sb.WriteString(fmt.Sprintf("export GOIABADA_ADMIN_PASSWORD=\"%s\"\n", config.AdminPassword))
	sb.WriteString("\n")

	sb.WriteString("# =============================================================================\n")
	sb.WriteString("# Database settings\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString(fmt.Sprintf("export GOIABADA_DB_TYPE=\"%s\"\n", config.DBType))
	if config.DBType == "sqlite" {
		sb.WriteString("export GOIABADA_DB_DSN=\"./goiabada.db\"\n")
	} else {
		sb.WriteString(fmt.Sprintf("export GOIABADA_DB_HOST=\"%s\"\n", config.DBHost))
		sb.WriteString(fmt.Sprintf("export GOIABADA_DB_PORT=\"%s\"\n", config.DBPort))
		sb.WriteString(fmt.Sprintf("export GOIABADA_DB_NAME=\"%s\"\n", config.DBName))
		sb.WriteString(fmt.Sprintf("export GOIABADA_DB_USERNAME=\"%s\"\n", config.DBUsername))
		sb.WriteString(fmt.Sprintf("export GOIABADA_DB_PASSWORD=\"%s\"\n", config.DBPassword))
	}
	sb.WriteString("\n")

	sb.WriteString("# =============================================================================\n")
	sb.WriteString("# Auth server settings\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString(fmt.Sprintf("export GOIABADA_AUTHSERVER_BASEURL=\"%s\"\n", config.AuthServerURL))
	sb.WriteString("export GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP=\"0.0.0.0\"\n")
	sb.WriteString("export GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=\"9090\"\n")
	sb.WriteString(fmt.Sprintf("export GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=\"%s\"\n", config.AuthSessionAuthKey))
	sb.WriteString(fmt.Sprintf("export GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=\"%s\"\n", config.AuthSessionEncKey))
	sb.WriteString("export GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS=\"true\"\n")
	sb.WriteString("export GOIABADA_AUTHSERVER_SET_COOKIE_SECURE=\"true\"\n")
	sb.WriteString("export GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS=\"true\"\n")
	sb.WriteString("\n")

	sb.WriteString("# =============================================================================\n")
	sb.WriteString("# Admin console settings\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString(fmt.Sprintf("export GOIABADA_ADMINCONSOLE_BASEURL=\"%s\"\n", config.AdminConsoleURL))
	sb.WriteString("export GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP=\"0.0.0.0\"\n")
	sb.WriteString("export GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=\"9091\"\n")
	sb.WriteString(fmt.Sprintf("export GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=\"%s\"\n", config.AdminSessionAuthKey))
	sb.WriteString(fmt.Sprintf("export GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=\"%s\"\n", config.AdminSessionEncKey))
	sb.WriteString("export GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=\"true\"\n")
	sb.WriteString("export GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE=\"true\"\n")
	sb.WriteString("export GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS=\"true\"\n")
	sb.WriteString("\n")

	sb.WriteString("# =============================================================================\n")
	sb.WriteString("# OAuth client for admin console\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString(fmt.Sprintf("export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID=\"%s\"\n", config.OAuthClientID))
	sb.WriteString(fmt.Sprintf("export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=\"%s\"\n", config.OAuthClientSecret))
	sb.WriteString(fmt.Sprintf("export GOIABADA_AUTHSERVER_INTERNALBASEURL=\"%s\"\n", config.AuthServerURL))
	sb.WriteString("\n")

	return sb.String()
}

// ============================================================================
// Kubernetes manifest generation
// ============================================================================

func generateKubernetesManifests(config *Config) string {
	var sb strings.Builder

	ns := config.K8sNamespace

	sb.WriteString("# Generated by goiabada-setup\n")
	sb.WriteString("# Apply with: kubectl apply -f goiabada-k8s.yaml\n")
	sb.WriteString("#\n")
	sb.WriteString("# IMPORTANT: The database must be empty for initial deployment.\n")
	sb.WriteString("# Goiabada will seed it with OAuth clients configured for the URLs below.\n")
	sb.WriteString("# If redeploying with different URLs, use a fresh database.\n")
	sb.WriteString("\n")

	// Namespace
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: Namespace\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", ns))
	sb.WriteString("\n")

	// Secret
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: Secret\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-secrets\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("type: Opaque\n")
	sb.WriteString("data:\n")
	sb.WriteString(fmt.Sprintf("  db-password: %s\n", base64Encode(config.DBPassword)))
	sb.WriteString(fmt.Sprintf("  admin-password: %s\n", base64Encode(config.AdminPassword)))
	sb.WriteString(fmt.Sprintf("  auth-session-auth-key: %s\n", base64Encode(config.AuthSessionAuthKey)))
	sb.WriteString(fmt.Sprintf("  auth-session-enc-key: %s\n", base64Encode(config.AuthSessionEncKey)))
	sb.WriteString(fmt.Sprintf("  admin-session-auth-key: %s\n", base64Encode(config.AdminSessionAuthKey)))
	sb.WriteString(fmt.Sprintf("  admin-session-enc-key: %s\n", base64Encode(config.AdminSessionEncKey)))
	sb.WriteString(fmt.Sprintf("  oauth-client-secret: %s\n", base64Encode(config.OAuthClientSecret)))
	sb.WriteString("\n")

	// ConfigMap
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: ConfigMap\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-config\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("data:\n")
	sb.WriteString("  GOIABADA_APPNAME: \"Goiabada\"\n")
	sb.WriteString(fmt.Sprintf("  GOIABADA_ADMIN_EMAIL: \"%s\"\n", config.AdminEmail))
	sb.WriteString(fmt.Sprintf("  GOIABADA_AUTHSERVER_BASEURL: \"%s\"\n", config.AuthServerURL))
	sb.WriteString("  GOIABADA_AUTHSERVER_INTERNALBASEURL: \"http://goiabada-authserver:9090\"\n")
	sb.WriteString(fmt.Sprintf("  GOIABADA_ADMINCONSOLE_BASEURL: \"%s\"\n", config.AdminConsoleURL))
	sb.WriteString("  GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS: \"true\"\n")
	sb.WriteString("  GOIABADA_AUTHSERVER_SET_COOKIE_SECURE: \"true\"\n")
	sb.WriteString("  GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS: \"true\"\n")
	sb.WriteString("  GOIABADA_ADMINCONSOLE_SET_COOKIE_SECURE: \"true\"\n")
	sb.WriteString(fmt.Sprintf("  GOIABADA_DB_TYPE: \"%s\"\n", config.DBType))
	sb.WriteString(fmt.Sprintf("  GOIABADA_DB_HOST: \"%s\"\n", config.DBHost))
	sb.WriteString(fmt.Sprintf("  GOIABADA_DB_PORT: \"%s\"\n", config.DBPort))
	sb.WriteString(fmt.Sprintf("  GOIABADA_DB_NAME: \"%s\"\n", config.DBName))
	sb.WriteString(fmt.Sprintf("  GOIABADA_DB_USERNAME: \"%s\"\n", config.DBUsername))
	sb.WriteString("  GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID: \"admin-console-client\"\n")
	sb.WriteString("\n")

	// Auth Server Deployment
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: apps/v1\n")
	sb.WriteString("kind: Deployment\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-authserver\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("spec:\n")
	sb.WriteString("  replicas: 1\n")
	sb.WriteString("  selector:\n")
	sb.WriteString("    matchLabels:\n")
	sb.WriteString("      app: goiabada-authserver\n")
	sb.WriteString("  template:\n")
	sb.WriteString("    metadata:\n")
	sb.WriteString("      labels:\n")
	sb.WriteString("        app: goiabada-authserver\n")
	sb.WriteString("    spec:\n")
	sb.WriteString("      containers:\n")
	sb.WriteString("      - name: authserver\n")
	sb.WriteString("        image: leodip/goiabada:authserver-1.4.1\n")
	sb.WriteString("        ports:\n")
	sb.WriteString("        - containerPort: 9090\n")
	sb.WriteString("        envFrom:\n")
	sb.WriteString("        - configMapRef:\n")
	sb.WriteString("            name: goiabada-config\n")
	sb.WriteString("        env:\n")
	sb.WriteString("        - name: GOIABADA_ADMIN_PASSWORD\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: admin-password\n")
	sb.WriteString("        - name: GOIABADA_DB_PASSWORD\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: db-password\n")
	sb.WriteString("        - name: GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: auth-session-auth-key\n")
	sb.WriteString("        - name: GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: auth-session-enc-key\n")
	sb.WriteString("        - name: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: oauth-client-secret\n")
	sb.WriteString("        livenessProbe:\n")
	sb.WriteString("          httpGet:\n")
	sb.WriteString("            path: /health\n")
	sb.WriteString("            port: 9090\n")
	sb.WriteString("          initialDelaySeconds: 10\n")
	sb.WriteString("          periodSeconds: 10\n")
	sb.WriteString("        readinessProbe:\n")
	sb.WriteString("          httpGet:\n")
	sb.WriteString("            path: /health\n")
	sb.WriteString("            port: 9090\n")
	sb.WriteString("          initialDelaySeconds: 5\n")
	sb.WriteString("          periodSeconds: 5\n")
	sb.WriteString("        resources:\n")
	sb.WriteString("          requests:\n")
	sb.WriteString("            memory: \"128Mi\"\n")
	sb.WriteString("            cpu: \"100m\"\n")
	sb.WriteString("          limits:\n")
	sb.WriteString("            memory: \"512Mi\"\n")
	sb.WriteString("            cpu: \"500m\"\n")
	sb.WriteString("\n")

	// Admin Console Deployment
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: apps/v1\n")
	sb.WriteString("kind: Deployment\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-adminconsole\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("spec:\n")
	sb.WriteString("  replicas: 1\n")
	sb.WriteString("  selector:\n")
	sb.WriteString("    matchLabels:\n")
	sb.WriteString("      app: goiabada-adminconsole\n")
	sb.WriteString("  template:\n")
	sb.WriteString("    metadata:\n")
	sb.WriteString("      labels:\n")
	sb.WriteString("        app: goiabada-adminconsole\n")
	sb.WriteString("    spec:\n")
	sb.WriteString("      containers:\n")
	sb.WriteString("      - name: adminconsole\n")
	sb.WriteString("        image: leodip/goiabada:adminconsole-1.4.1\n")
	sb.WriteString("        ports:\n")
	sb.WriteString("        - containerPort: 9091\n")
	sb.WriteString("        envFrom:\n")
	sb.WriteString("        - configMapRef:\n")
	sb.WriteString("            name: goiabada-config\n")
	sb.WriteString("        env:\n")
	sb.WriteString("        - name: GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: oauth-client-secret\n")
	sb.WriteString("        - name: GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: admin-session-auth-key\n")
	sb.WriteString("        - name: GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY\n")
	sb.WriteString("          valueFrom:\n")
	sb.WriteString("            secretKeyRef:\n")
	sb.WriteString("              name: goiabada-secrets\n")
	sb.WriteString("              key: admin-session-enc-key\n")
	sb.WriteString("        livenessProbe:\n")
	sb.WriteString("          httpGet:\n")
	sb.WriteString("            path: /health\n")
	sb.WriteString("            port: 9091\n")
	sb.WriteString("          initialDelaySeconds: 10\n")
	sb.WriteString("          periodSeconds: 10\n")
	sb.WriteString("        readinessProbe:\n")
	sb.WriteString("          httpGet:\n")
	sb.WriteString("            path: /health\n")
	sb.WriteString("            port: 9091\n")
	sb.WriteString("          initialDelaySeconds: 5\n")
	sb.WriteString("          periodSeconds: 5\n")
	sb.WriteString("        resources:\n")
	sb.WriteString("          requests:\n")
	sb.WriteString("            memory: \"128Mi\"\n")
	sb.WriteString("            cpu: \"100m\"\n")
	sb.WriteString("          limits:\n")
	sb.WriteString("            memory: \"512Mi\"\n")
	sb.WriteString("            cpu: \"500m\"\n")
	sb.WriteString("\n")

	// Services
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: Service\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-authserver\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("spec:\n")
	sb.WriteString("  selector:\n")
	sb.WriteString("    app: goiabada-authserver\n")
	sb.WriteString("  ports:\n")
	sb.WriteString("  - port: 9090\n")
	sb.WriteString("    targetPort: 9090\n")
	sb.WriteString("\n")

	sb.WriteString("---\n")
	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: Service\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-adminconsole\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("spec:\n")
	sb.WriteString("  selector:\n")
	sb.WriteString("    app: goiabada-adminconsole\n")
	sb.WriteString("  ports:\n")
	sb.WriteString("  - port: 9091\n")
	sb.WriteString("    targetPort: 9091\n")
	sb.WriteString("\n")

	// Ingress resources
	authHost := strings.TrimPrefix(strings.TrimPrefix(config.AuthServerURL, "https://"), "http://")
	adminHost := strings.TrimPrefix(strings.TrimPrefix(config.AdminConsoleURL, "https://"), "http://")

	// Ingress for auth server
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: networking.k8s.io/v1\n")
	sb.WriteString("kind: Ingress\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-authserver\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("  annotations:\n")
	sb.WriteString("    cert-manager.io/cluster-issuer: \"letsencrypt-prod\"\n")
	sb.WriteString("    nginx.ingress.kubernetes.io/proxy-buffer-size: \"128k\"\n")
	sb.WriteString("spec:\n")
	sb.WriteString("  ingressClassName: nginx\n")
	sb.WriteString("  tls:\n")
	sb.WriteString("  - hosts:\n")
	sb.WriteString(fmt.Sprintf("    - %s\n", authHost))
	sb.WriteString("    secretName: goiabada-tls-auth\n")
	sb.WriteString("  rules:\n")
	sb.WriteString(fmt.Sprintf("  - host: %s\n", authHost))
	sb.WriteString("    http:\n")
	sb.WriteString("      paths:\n")
	sb.WriteString("      - path: /\n")
	sb.WriteString("        pathType: Prefix\n")
	sb.WriteString("        backend:\n")
	sb.WriteString("          service:\n")
	sb.WriteString("            name: goiabada-authserver\n")
	sb.WriteString("            port:\n")
	sb.WriteString("              number: 9090\n")
	sb.WriteString("\n")

	// Ingress for admin console
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: networking.k8s.io/v1\n")
	sb.WriteString("kind: Ingress\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-adminconsole\n")
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("  annotations:\n")
	sb.WriteString("    cert-manager.io/cluster-issuer: \"letsencrypt-prod\"\n")
	sb.WriteString("    nginx.ingress.kubernetes.io/proxy-buffer-size: \"128k\"\n")
	sb.WriteString("spec:\n")
	sb.WriteString("  ingressClassName: nginx\n")
	sb.WriteString("  tls:\n")
	sb.WriteString("  - hosts:\n")
	sb.WriteString(fmt.Sprintf("    - %s\n", adminHost))
	sb.WriteString("    secretName: goiabada-tls-admin\n")
	sb.WriteString("  rules:\n")
	sb.WriteString(fmt.Sprintf("  - host: %s\n", adminHost))
	sb.WriteString("    http:\n")
	sb.WriteString("      paths:\n")
	sb.WriteString("      - path: /\n")
	sb.WriteString("        pathType: Prefix\n")
	sb.WriteString("        backend:\n")
	sb.WriteString("          service:\n")
	sb.WriteString("            name: goiabada-adminconsole\n")
	sb.WriteString("            port:\n")
	sb.WriteString("              number: 9091\n")

	return sb.String()
}
