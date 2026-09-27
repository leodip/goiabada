package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
)

// Injected at build time via -ldflags by build-binaries.sh, which takes the
// value from the git tag. They are vars rather than consts precisely so the
// linker can set them.
//
// The defaults are what a source build gets. "dev" identifies an unreleased
// binary, and "latest" is the right image tag for someone running the wizard
// from a checkout: it resolves to the current release rather than to whichever
// version happened to be hardcoded when the file was last edited.
var (
	version  = "dev"
	imageTag = "latest"
)

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
	defer func() { _ = rl.Close() }()

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
	aesEncryptionKey := generateHexKey(32)
	oauthClientSecret := generateRandomString(60)

	printSuccess("Auth server session keys generated")
	printSuccess("Admin console session keys generated")
	printSuccess("Auth server AES encryption key generated")
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
		AESEncryptionKey:    aesEncryptionKey,
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

	filename, content := generatedConfiguration(deploymentType, config)
	if flags.Output != "" && !isDirectory(flags.Output) {
		filename = filepath.Base(flags.Output)
	}
	outputPath := filepath.Join(outputDir, filename)
	if err := writePrivateFile(outputPath, content); err != nil {
		printError("Error writing %s: %v", filename, err)
		os.Exit(1)
	}
	printSuccess("Created: %s", outputPath)

	printCompletionMessage(config, outputPath)
}
