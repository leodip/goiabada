package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// wizard fills a Config one step at a time, from the prompts or, when --type was given, from the
// flags alone, and writes the file the deployment type is configured by.
type wizard struct {
	asker
	flags *CLIFlags
	// interactive is false when --type was given: every answer then comes from a flag and nothing
	// is read.
	interactive bool
	config      *Config
	// baseDomain is the auth server URL's domain, which the default admin console URL and admin
	// email are built from.
	baseDomain string
	outputPath string
	// testConnection dials the database the operator described and reports what it found.
	testConnection func(out *console, e *engine, host, port, name, user, password string) bool
}

func newWizard(flags *CLIFlags, in prompter, out *console) *wizard {
	return &wizard{
		asker:          asker{in: in, out: out},
		flags:          flags,
		interactive:    flags.DeploymentType == "",
		config:         &Config{},
		testConnection: testDatabaseConnection,
	}
}

// wizardStep is one step of the wizard. Steps are numbered in the order they run, counting only
// those that apply, so no deployment type and engine sees a gap or a repeat: each branch numbered
// its own headings, and three of the seven combinations printed them wrong (#430).
type wizardStep struct {
	// title is the step's heading. A step with none is not numbered and prints no heading.
	title string
	// announced steps print their heading in non-interactive mode too, where the others read no
	// input and print none.
	announced bool
	// applies is read when the step is reached, after the steps before it have filled the Config.
	// Nil applies always.
	applies func(c *Config) bool
	run     func(w *wizard) error
}

var wizardSteps = []wizardStep{
	{title: "Deployment type", run: (*wizard).chooseDeployment},
	{title: "Database type", run: (*wizard).chooseEngine},
	{
		title:   "Domain names",
		applies: func(c *Config) bool { return c.Deployment.asksURLs },
		run:     (*wizard).askURLs,
	},
	{
		title:   "Kubernetes namespace",
		applies: func(c *Config) bool { return c.Deployment.asksNamespace },
		run:     (*wizard).askNamespace,
	},
	{title: "Admin credentials", run: (*wizard).askAdmin},
	{
		title:   "Database connection",
		applies: func(c *Config) bool { return c.Engine.hasServer && c.Deployment.externalDatabase },
		run:     (*wizard).askDatabaseConnection,
	},
	{
		title:   "Database password",
		applies: func(c *Config) bool { return c.Engine.hasServer && !c.Deployment.externalDatabase },
		run:     (*wizard).askDatabasePassword,
	},
	{title: "Generating credentials", announced: true, run: (*wizard).generateCredentials},
	{run: (*wizard).confirm},
	{title: "Generating configuration", announced: true, run: (*wizard).writeConfiguration},
}

// setup runs the wizard to the end: the steps, the file, the completion message. A step's error
// ends it where it stands, and the file is written by the last step, so an error or an abort
// before it writes nothing.
func (w *wizard) setup() error {
	printBanner(w.out)
	if !w.interactive {
		if err := w.flags.checkWritable(); err != nil {
			return err
		}
	}
	number := 0
	for _, step := range wizardSteps {
		if step.applies != nil && !step.applies(w.config) {
			continue
		}
		if step.title != "" {
			number++
			if w.interactive || step.announced {
				w.heading(number, step.title)
			}
		}
		if err := step.run(w); err != nil {
			return err
		}
	}
	printCompletionMessage(w.out, w.config, w.outputPath)
	return nil
}

func (w *wizard) heading(number int, title string) {
	heading := fmt.Sprintf("STEP %d: %s", number, title)
	if number > 1 {
		w.out.println()
	}
	w.out.println(heading)
	w.out.println(strings.Repeat("-", len(heading)))
}

func (w *wizard) chooseDeployment() error {
	var target *deployment
	if w.interactive {
		var choices []string
		for _, d := range deployments {
			w.out.printf("%s. %s\n", d.number, d.menuLabel)
			choices = append(choices, d.number)
		}
		w.out.println()
		choice, err := w.choice(fmt.Sprintf("Select deployment type [1-%d]", len(choices)), choices, "1")
		if err != nil {
			return err
		}
		target, _ = resolveDeployment(choice)
	} else {
		var ok bool
		target, ok = resolveDeployment(w.flags.DeploymentType)
		if !ok {
			return errs.Errorf("invalid deployment type: %s (use: %s)", w.flags.DeploymentType, orList(deploymentNames()))
		}
		w.out.info("Deployment type: %s", target.displayName)
	}
	w.config.Deployment = target
	if !target.asksURLs {
		w.config.AuthServerURL = "http://localhost:9090"
		w.config.AdminConsoleURL = "http://localhost:9091"
	}
	return nil
}

func (w *wizard) chooseEngine() error {
	target := w.config.Deployment
	var dbEngine *engine
	if w.interactive {
		var choices []string
		for _, e := range target.acceptedEngines() {
			w.out.printf("%s. %s\n", e.number, e.label)
			choices = append(choices, e.number)
		}
		w.out.println()
		if target.kind == deploymentKubernetes {
			w.out.println("Note: For Kubernetes, you'll need to provide your own database.")
			w.out.println("      SQLite is not recommended for Kubernetes deployments.")
			w.out.println()
		}
		choice, err := w.choice(fmt.Sprintf("Select database [1-%d]", len(choices)), choices, "1")
		if err != nil {
			return err
		}
		dbEngine, _ = resolveEngine(choice)
	} else {
		var ok bool
		dbEngine, ok = resolveEngine(w.flags.DBType)
		if !ok {
			return errs.Errorf("invalid database type: %s (use: %s)", w.flags.DBType, orList(engineNames()))
		}
		if !target.accepts(dbEngine) {
			return errs.Errorf("%s is not supported for %s deployments", dbEngine.label, target.displayName)
		}
		if target.kind == deploymentNative && !dbEngine.hasServer {
			w.out.warning("SQLite is fine for single-instance native deployments, but consider a proper database for production.")
		}
		w.out.info("Database type: %s", dbEngine.name)
	}
	w.config.Engine = dbEngine
	w.config.DBPort = dbEngine.defaultPort
	return nil
}

func (w *wizard) askURLs() error {
	if !w.interactive {
		return w.urlsFromFlags()
	}
	authServerURL, err := w.url("Auth server URL (e.g., https://auth.example.com)", "https://auth.example.com")
	if err != nil {
		return err
	}
	if authServerURL, err = w.confirmHTTP(authServerURL, "Auth server URL", "https://auth.example.com"); err != nil {
		return err
	}

	w.baseDomain = extractDomainFromURL(authServerURL)
	defaultAdminURL := fmt.Sprintf("https://admin.%s", w.baseDomain)
	adminConsoleURL, err := w.url("Admin console URL (e.g., https://admin.example.com)", defaultAdminURL)
	if err != nil {
		return err
	}
	if adminConsoleURL, err = w.confirmHTTP(adminConsoleURL, "Admin console URL", defaultAdminURL); err != nil {
		return err
	}

	authDomain := extractDomainFromURL(authServerURL)
	adminDomain := extractDomainFromURL(adminConsoleURL)
	if authDomain != adminDomain {
		w.out.println()
		w.out.warning("Domain mismatch detected!")
		w.out.printf("   Auth server domain:    %s\n", authDomain)
		w.out.printf("   Admin console domain:  %s\n", adminDomain)
		w.out.println()
		keep, askErr := w.yesNo("Continue with different domains?", false)
		if askErr != nil {
			return askErr
		}
		if !keep {
			w.out.println()
			w.out.println("Please re-enter the URLs:")
			if authServerURL, err = w.url("Auth server URL", authServerURL); err != nil {
				return err
			}
			w.baseDomain = extractDomainFromURL(authServerURL)
			if adminConsoleURL, err = w.url("Admin console URL", fmt.Sprintf("https://admin.%s", w.baseDomain)); err != nil {
				return err
			}
		}
	}
	w.config.AuthServerURL = authServerURL
	w.config.AdminConsoleURL = adminConsoleURL
	return nil
}

// confirmHTTP asks once whether a plain-HTTP URL other than localhost is meant, and for another
// URL if it is not.
func (w *wizard) confirmHTTP(value, prompt, defaultValue string) (string, error) {
	if !strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "http://localhost") {
		return value, nil
	}
	w.out.warning("Using HTTP for production is not recommended. Consider using HTTPS.")
	keep, err := w.yesNo("Continue with HTTP?", false)
	if err != nil || keep {
		return value, err
	}
	return w.url(prompt, defaultValue)
}

func (w *wizard) urlsFromFlags() error {
	authServerURL := w.flags.AuthServerURL
	adminConsoleURL := w.flags.AdminConsoleURL
	if authServerURL == "" {
		return errs.New("--auth-url is required for production/kubernetes/native deployments")
	}
	if err := validateURL(authServerURL); err != nil {
		return errs.Wrap(err, "invalid auth URL")
	}
	if strings.HasPrefix(authServerURL, "http://") {
		w.out.warning("Using HTTP for production is not recommended. Consider using HTTPS.")
	}
	w.baseDomain = extractDomainFromURL(authServerURL)
	if adminConsoleURL == "" {
		adminConsoleURL = fmt.Sprintf("https://admin.%s", w.baseDomain)
	}
	if err := validateURL(adminConsoleURL); err != nil {
		return errs.Wrap(err, "invalid admin URL")
	}
	if strings.HasPrefix(adminConsoleURL, "http://") {
		w.out.warning("Using HTTP for production is not recommended. Consider using HTTPS.")
	}
	authDomain := extractDomainFromURL(authServerURL)
	adminDomain := extractDomainFromURL(adminConsoleURL)
	if authDomain != adminDomain {
		w.out.warning("Domain mismatch: auth=%s, admin=%s", authDomain, adminDomain)
	}
	w.out.info("Auth server URL: %s", authServerURL)
	w.out.info("Admin console URL: %s", adminConsoleURL)
	w.config.AuthServerURL = authServerURL
	w.config.AdminConsoleURL = adminConsoleURL
	return nil
}

func (w *wizard) askNamespace() error {
	if w.interactive {
		namespace, err := w.namespace("Namespace", "goiabada")
		w.config.K8sNamespace = namespace
		return err
	}
	namespace := w.flags.Namespace
	if namespace == "" {
		namespace = "goiabada"
	}
	if err := validateNamespace(namespace); err != nil {
		return errs.Wrap(err, "invalid namespace")
	}
	w.out.info("Kubernetes namespace: %s", namespace)
	w.config.K8sNamespace = namespace
	return nil
}

func (w *wizard) askAdmin() error {
	defaultAdminEmail := "admin@example.com"
	if w.baseDomain != "" && w.baseDomain != "example.com" {
		defaultAdminEmail = fmt.Sprintf("admin@%s", w.baseDomain)
	}

	if w.interactive {
		adminEmail, err := w.email("Admin email", defaultAdminEmail)
		if err != nil {
			return err
		}
		adminPassword, err := w.password("Admin password", "changeme")
		if err != nil {
			return err
		}
		w.config.AdminEmail = adminEmail
		w.config.AdminPassword = adminPassword
		return nil
	}

	adminEmail := w.flags.AdminEmail
	if adminEmail == "" {
		adminEmail = defaultAdminEmail
	}
	if err := validateEmail(adminEmail); err != nil {
		return errs.Wrap(err, "invalid admin email")
	}
	adminPassword := w.flags.AdminPassword
	if adminPassword == "" {
		adminPassword = generateRandomString(16)
		w.out.info("Generated admin password: %s", adminPassword)
	}
	if issues := checkPasswordStrength(adminPassword); len(issues) > 0 {
		w.out.warning("Weak password: %s", strings.Join(issues, ", "))
	}
	w.out.info("Admin email: %s", adminEmail)
	w.config.AdminEmail = adminEmail
	w.config.AdminPassword = adminPassword
	return nil
}

// askDatabaseConnection is a database the operator runs, reached by host and credentials:
// Kubernetes and native binaries.
func (w *wizard) askDatabaseConnection() error {
	c := w.config
	if !w.interactive {
		if err := w.databaseConnectionFromFlags(); err != nil {
			return err
		}
		if !w.flags.SkipDBTest && !w.testConnection(w.out, c.Engine, c.DBHost, c.DBPort, c.DBName, c.DBUsername, c.DBPassword) {
			w.out.warning("Database connection test failed. Configuration will still be generated.")
		}
		return nil
	}

	w.out.println("Enter your database connection details.")
	w.out.println()
	if c.Deployment.kind == deploymentKubernetes {
		w.out.printf("%sTip:%s If using a managed database service (Supabase, PlanetScale, Neon, etc.),\n", w.out.yellow, w.out.reset)
		w.out.println("     use the connection pooler endpoint for better compatibility.")
		w.out.println("     Direct connections may use IPv6 which some clusters don't support.")
		w.out.println()
	}

	defaultHost := c.Engine.kubernetesHost
	if c.Deployment.kind == deploymentNative {
		defaultHost = "localhost"
	}

	// Loop to allow re-entering database details on connection failure
	for {
		if err := w.databaseConnectionFromPrompts(defaultHost); err != nil {
			return err
		}

		w.out.println()
		test, err := w.yesNo("Test database connection?", true)
		if err != nil {
			return err
		}
		if !test || w.testConnection(w.out, c.Engine, c.DBHost, c.DBPort, c.DBName, c.DBUsername, c.DBPassword) {
			return nil
		}

		w.out.println()
		w.out.println("What would you like to do?")
		w.out.println("1. Re-enter database details")
		w.out.println("2. Continue anyway (configuration will be generated)")
		w.out.println("3. Abort setup")
		w.out.println()
		choice, err := w.choice("Select option [1-3]", []string{"1", "2", "3"}, "1")
		if err != nil {
			return err
		}
		switch choice {
		case "2":
			w.out.warning("Continuing without successful database connection test.")
			w.out.println("Make sure the database is running and accessible before deployment.")
			return nil
		case "3":
			return errAborted
		}
		w.out.println()
		w.out.println("Re-enter database connection details:")
		w.out.println()
	}
}

func (w *wizard) databaseConnectionFromPrompts(defaultHost string) error {
	c := w.config
	var err error
	if c.DBHost, err = w.hostname("Database host", defaultHost); err != nil {
		return err
	}
	if c.DBPort, err = w.port("Database port", c.DBPort); err != nil {
		return err
	}
	if c.DBName, err = w.databaseName("Database name", "goiabada"); err != nil {
		return err
	}
	if c.DBUsername, err = w.nonEmpty("Database username", c.Engine.defaultUser); err != nil {
		return err
	}
	c.DBPassword, err = w.nonEmpty("Database password", generateRandomString(16))
	return err
}

func (w *wizard) databaseConnectionFromFlags() error {
	c := w.config
	c.DBHost = w.flags.DBHost
	if c.DBHost == "" {
		return errs.New("--db-host is required for Kubernetes/native deployments")
	}
	if err := validateHostname(c.DBHost); err != nil {
		return errs.Wrap(err, "invalid database host")
	}
	if w.flags.DBPort != "" {
		c.DBPort = w.flags.DBPort
	}
	if err := validatePort(c.DBPort); err != nil {
		return errs.Wrap(err, "invalid database port")
	}
	c.DBName = w.flags.DBName
	if c.DBName == "" {
		c.DBName = "goiabada"
	}
	if err := validateDatabaseName(c.DBName); err != nil {
		return errs.Wrap(err, "invalid database name")
	}
	c.DBUsername = w.flags.DBUsername
	if c.DBUsername == "" {
		c.DBUsername = c.Engine.defaultUser
	}
	c.DBPassword = w.flags.DBPassword
	if c.DBPassword == "" {
		c.DBPassword = generateRandomString(16)
		w.out.info("Generated database password: %s", c.DBPassword)
	}
	w.out.info("Database host: %s:%s", c.DBHost, c.DBPort)
	w.out.info("Database name: %s", c.DBName)
	w.out.info("Database user: %s", c.DBUsername)
	return nil
}

// askDatabasePassword is a database the generated compose file runs, which needs only a password.
func (w *wizard) askDatabasePassword() error {
	if w.interactive {
		password, err := w.nonEmpty("Database password", generateRandomString(16))
		w.config.DBPassword = password
		return err
	}
	w.config.DBPassword = w.flags.DBPassword
	if w.config.DBPassword == "" {
		w.config.DBPassword = generateRandomString(16)
	}
	w.out.info("Database password: %s", w.config.DBPassword)
	return nil
}

func (w *wizard) generateCredentials() error {
	c := w.config
	c.AuthSessionAuthKey = generateHexKey(64)
	c.AuthSessionEncKey = generateHexKey(32)
	c.AdminSessionAuthKey = generateHexKey(64)
	c.AdminSessionEncKey = generateHexKey(32)
	c.AESEncryptionKey = generateHexKey(32)
	c.OAuthClientSecret = generateRandomString(60)

	w.out.success("Auth server session keys generated")
	w.out.success("Admin console session keys generated")
	w.out.success("Auth server AES encryption key generated")
	w.out.success("OAuth client secret generated")
	return nil
}

// confirm shows the summary and asks before anything is written. Non-interactive mode has
// nobody to ask.
func (w *wizard) confirm() error {
	if !w.interactive {
		return nil
	}
	w.out.println()
	printSummary(w.out, w.config)
	w.out.println()
	generate, err := w.yesNo("Generate configuration files?", true)
	if err != nil {
		return err
	}
	if !generate {
		return errAborted
	}
	return nil
}

func (w *wizard) writeConfiguration() error {
	output := w.flags.Output
	outputDir, _ := os.Getwd()
	if output != "" {
		if isDirectory(output) {
			outputDir = output
		} else {
			outputDir = filepath.Dir(output)
		}
	}

	filename, content := generatedConfiguration(w.config)
	if output != "" && !isDirectory(output) {
		filename = filepath.Base(output)
	}
	w.outputPath = filepath.Join(outputDir, filename)
	if err := writePrivateFile(w.outputPath, content); err != nil {
		return errs.Wrapf(err, "unable to write %s", filename)
	}
	w.out.success("Created: %s", w.outputPath)
	return nil
}
