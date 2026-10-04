package main

import (
	"fmt"
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
	// defaultAdminEmail is the admin email offered: admin@example.com for local testing, admin@
	// and the auth server host's parent otherwise, and none for a host without one.
	defaultAdminEmail string
	paths             outputPaths
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
	{
		title:   "Gateway traffic policy",
		applies: func(c *Config) bool { return c.Deployment.servedByEnvoyGateway },
		run:     (*wizard).askTrafficPolicy,
	},
	{
		title:   "Network policy",
		applies: func(c *Config) bool { return c.Deployment.servedByEnvoyGateway },
		run:     (*wizard).askNetworkPolicy,
	},
	{
		title:   "Reverse proxy",
		applies: func(c *Config) bool { return c.Deployment.asksLocalProxy },
		run:     (*wizard).askLocalProxy,
	},
	{
		title:   "Rate limiter",
		applies: func(c *Config) bool { return c.Deployment.asksRateLimiter },
		run:     (*wizard).askRateLimiter,
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
	printCompletionMessage(w.out, w.config, w.paths)
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
		choice, err := w.choice(fmt.Sprintf("Select deployment type [1-%d]", len(choices)), choices)
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
	// The files are placed here, before any step reports a secret, so each can say where it will be.
	w.paths = resolveOutputPaths(target, w.flags.Output)
	if !target.asksURLs {
		w.config.AuthServerURL = "http://localhost:9090"
		w.config.AdminConsoleURL = "http://localhost:9091"
		w.defaultAdminEmail = "admin@example.com"
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
		choice, err := w.choice(fmt.Sprintf("Select database [1-%d]", len(choices)), choices)
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
	authServerURL, err := w.askURL("Auth server URL (e.g., https://auth.example.com)", "https://auth.example.com")
	if err != nil {
		return err
	}
	adminConsoleURL, err := w.askAdminURL("Admin console URL (e.g., https://admin.example.com)", authServerURL)
	if err != nil {
		return err
	}

	authSite, adminSite := siteOf(authServerURL), siteOf(adminConsoleURL)
	if authSite != adminSite {
		w.out.println()
		w.out.warning("Domain mismatch detected!")
		w.out.printf("   Auth server domain:    %s\n", authSite)
		w.out.printf("   Admin console domain:  %s\n", adminSite)
		w.out.println()
		keep, askErr := w.yesNo("Continue with different domains?", false)
		if askErr != nil {
			return askErr
		}
		if !keep {
			w.out.println()
			w.out.println("Please re-enter the URLs:")
			if authServerURL, err = w.askURL("Auth server URL", authServerURL); err != nil {
				return err
			}
			if adminConsoleURL, err = w.askAdminURL("Admin console URL", authServerURL); err != nil {
				return err
			}
		}
	}
	w.config.AuthServerURL = authServerURL
	w.config.AdminConsoleURL = adminConsoleURL
	w.defaultAdminEmail = defaultAdminEmailFor(authServerURL)
	return nil
}

// checkURL is validateURL, and for a deployment that routes by host, the Kubernetes host rule on
// the URL's host as well.
func (w *wizard) checkURL(value string) error {
	if err := validateURL(value); err != nil {
		return err
	}
	if w.config.Deployment.routesByHost {
		return validateListenerHostname(hostOf(value))
	}
	return nil
}

// checkDistinctHosts refuses, for a deployment that routes by host, an admin console URL on the
// auth server's host. Two Gateway listeners on one port and hostname are indistinct, and "ALL
// indistinct Listeners must not be accepted for processing" (Gateway API v1.6.1,
// GatewaySpec.Listeners, "Handling indistinct Listeners"), so neither would be served (#430).
func (w *wizard) checkDistinctHosts(authServerURL, adminConsoleURL string) error {
	if w.config.Deployment.routesByHost && hostOf(authServerURL) == hostOf(adminConsoleURL) {
		return errs.Errorf("the admin console URL has the auth server's host, %s, and each needs a host of its own", hostOf(authServerURL))
	}
	return nil
}

// askURL asks until the answer passes checkURL, and asks again when a plain-HTTP URL other than
// localhost is not confirmed.
func (w *wizard) askURL(prompt, defaultValue string) (string, error) {
	for {
		value, err := w.validated(prompt, defaultValue, "URL", w.checkURL)
		if err != nil || !strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "http://localhost") {
			return value, err
		}
		w.out.warning("Using HTTP for production is not recommended. Consider using HTTPS.")
		keep, err := w.yesNo("Continue with HTTP?", false)
		if err != nil || keep {
			return value, err
		}
	}
}

// askAdminURL asks for the admin console URL, offering the auth server's sibling when its host
// has a parent and nothing when it has none, and asks again while checkDistinctHosts refuses it.
func (w *wizard) askAdminURL(prompt, authServerURL string) (string, error) {
	defaultURL, _ := defaultAdminURL(authServerURL)
	for {
		adminConsoleURL, err := w.askURL(prompt, defaultURL)
		if err != nil {
			return "", err
		}
		distinct := w.checkDistinctHosts(authServerURL, adminConsoleURL)
		if distinct == nil {
			return adminConsoleURL, nil
		}
		w.out.printf("Invalid URL: %s. Please try again.\n", distinct)
	}
}

func (w *wizard) urlsFromFlags() error {
	authServerURL := w.flags.AuthServerURL
	adminConsoleURL := w.flags.AdminConsoleURL
	if authServerURL == "" {
		return errs.New("--auth-url is required for production/kubernetes/native deployments")
	}
	if err := w.checkURL(authServerURL); err != nil {
		return errs.Wrap(err, "invalid auth URL")
	}
	if strings.HasPrefix(authServerURL, "http://") {
		w.out.warning("Using HTTP for production is not recommended. Consider using HTTPS.")
	}
	if adminConsoleURL == "" {
		var derived bool
		if adminConsoleURL, derived = defaultAdminURL(authServerURL); !derived {
			return errs.Errorf("--admin-url is required when the auth URL's host, %s, is an IP address or a single label, which no admin console URL can be derived from", hostOf(authServerURL))
		}
	}
	if err := w.checkURL(adminConsoleURL); err != nil {
		return errs.Wrap(err, "invalid admin URL")
	}
	if err := w.checkDistinctHosts(authServerURL, adminConsoleURL); err != nil {
		return errs.Wrap(err, "invalid admin URL")
	}
	if strings.HasPrefix(adminConsoleURL, "http://") {
		w.out.warning("Using HTTP for production is not recommended. Consider using HTTPS.")
	}
	if authSite, adminSite := siteOf(authServerURL), siteOf(adminConsoleURL); authSite != adminSite {
		w.out.warning("Domain mismatch: auth=%s, admin=%s", authSite, adminSite)
	}
	w.out.info("Auth server URL: %s", authServerURL)
	w.out.info("Admin console URL: %s", adminConsoleURL)
	w.config.AuthServerURL = authServerURL
	w.config.AdminConsoleURL = adminConsoleURL
	w.defaultAdminEmail = defaultAdminEmailFor(authServerURL)
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

// askTrafficPolicy asks which externalTrafficPolicy Envoy Gateway's load balancer Service uses,
// Cluster by default, which decides the EnvoyProxy the completion message prints and the address the
// servers see (#396 decision 4).
func (w *wizard) askTrafficPolicy() error {
	if !w.interactive {
		w.config.GatewayTrafficPolicy = w.flags.GatewayTrafficPolicy
		if w.config.GatewayTrafficPolicy == "" {
			w.config.GatewayTrafficPolicy = trafficPolicyCluster
		}
		w.out.info("Gateway traffic policy: %s", w.config.GatewayTrafficPolicy)
		return nil
	}
	w.out.println("Envoy Gateway's load balancer Service has a traffic policy, which decides the address")
	w.out.println("Goiabada sees for each client, and so what it rate limits and audits:")
	w.out.println("  1. Cluster: works behind every load balancer. Goiabada sees a node's address for")
	w.out.println("     every client, not the client's own.")
	w.out.println("  2. Local, with Envoy on every node as a DaemonSet: Goiabada sees the client's address,")
	w.out.println("     at the cost of an Envoy pod on every node.")
	w.out.println("The EnvoyProxy and GatewayClass that set it are cluster-wide: on a cluster that already")
	w.out.println("runs Envoy Gateway, the choice belongs to whoever runs it.")
	w.out.println()
	choice, err := w.choice("Select traffic policy [1-2]", []string{"1", "2"})
	w.config.GatewayTrafficPolicy = trafficPolicyCluster
	if choice == "2" {
		w.config.GatewayTrafficPolicy = trafficPolicyLocal
	}
	return err
}

// askNetworkPolicy asks whether NetworkPolicies admit only Envoy's namespace to both servers, and
// the admin console to the auth server, no by default (#396 decision 5).
func (w *wizard) askNetworkPolicy() error {
	if !w.interactive {
		w.config.NetworkPolicy = w.flags.NetworkPolicy
		answer := "no"
		if w.config.NetworkPolicy {
			answer = "yes, admitting only Envoy and the admin console"
		}
		w.out.info("NetworkPolicies: %s", answer)
		return nil
	}
	w.out.println("NetworkPolicies can admit only Envoy's namespace (envoy-gateway-system) to both servers,")
	w.out.println("and the admin console to the auth server.")
	w.out.println("  Yes: on a CNI that enforces NetworkPolicy, every other pod is refused, including a")
	w.out.println("       workload in another namespace that calls the auth server's Service, for /certs")
	w.out.println("       or /userinfo, until you admit its namespace as the policy's comment shows.")
	w.out.println("  No:  any pod in the cluster can reach both servers, and can choose the address it is")
	w.out.println("       rate limited and audited under by sending its own X-Forwarded-For.")
	w.out.println()
	restrict, err := w.yesNo("Restrict who can reach Goiabada with NetworkPolicies?", false)
	w.config.NetworkPolicy = restrict
	return err
}

// askLocalProxy asks whether a reverse proxy on the same machine forwards to the native binaries,
// yes by default: they then listen on 127.0.0.1 alone and trust forwarded headers from 127.0.0.1
// alone, and otherwise listen on every interface and trust none (#396 decision 7).
func (w *wizard) askLocalProxy() error {
	if !w.interactive {
		w.config.LocalProxy = w.flags.LocalProxy.or(true)
		answer := "no, Goiabada serves HTTPS itself"
		if w.config.LocalProxy {
			answer = "yes"
		}
		w.out.info("A reverse proxy on this machine forwards to Goiabada: %s", answer)
		return nil
	}
	w.out.println("A reverse proxy on this machine (nginx, Caddy, Apache) can serve HTTPS and forward to")
	w.out.println("Goiabada at http://127.0.0.1:9090 and :9091.")
	w.out.println("  Yes: both servers listen on 127.0.0.1 alone, and trust the forwarded headers of a")
	w.out.println("       connection from 127.0.0.1 alone, so the proxy is the only way in.")
	w.out.println("  No:  both servers listen on every interface and trust no forwarded header; set up")
	w.out.println("       their HTTPS listeners in the generated file before going live.")
	w.out.println()
	localProxy, err := w.yesNo("Does a reverse proxy on this machine forward to Goiabada?", true)
	w.config.LocalProxy = localProxy
	return err
}

// askRateLimiter asks whether to turn the auth server's rate limiter on, yes by default but for
// Kubernetes under the Cluster traffic policy, after which the question comes, since it decides
// that default (#396 decision 9).
func (w *wizard) askRateLimiter() error {
	defaultOn := w.config.rateLimiterDefault()
	if !w.interactive {
		w.config.RateLimiter = w.flags.RateLimiter.or(defaultOn)
		answer := "off"
		if w.config.RateLimiter {
			answer = "on"
		}
		if !w.flags.RateLimiter.set && !defaultOn {
			answer += " (the default under the Cluster traffic policy; --rate-limiter turns it on)"
		}
		w.out.info("Rate limiter: %s", answer)
		return nil
	}
	w.out.println("The auth server's built-in rate limiter caps sign-ins, password resets,")
	w.out.println("self-registrations and client registrations per client address, and failed")
	w.out.println("passwords and codes per account.")
	if w.config.Deployment.servedByEnvoyGateway {
		w.out.println("Its limits on failed passwords and codes are keyed on the email or the user and counted")
		w.out.println("in the database every pod shares, so they hold under either traffic policy.")
		if defaultOn {
			w.out.println("Under the Local traffic policy Goiabada sees each client's address, so the per-IP")
			w.out.println("limits count each client alone.")
		} else {
			w.out.println("Its per-IP limits do not: under the Cluster traffic policy Goiabada sees a node's")
			w.out.println("address, so they count every user the load balancer sends through one node together")
			w.out.println("(30 password posts a minute and 20 forgot-password requests per 5 minutes per node,")
			w.out.println("for example), which throttles sign-ins on a busy site. That is why it is off by")
			w.out.println("default here.")
		}
	}
	w.out.printf("The limits are listed at %s\n", rateLimitsDocsURL)
	w.out.println()
	rateLimiter, err := w.yesNo("Turn on the rate limiter?", defaultOn)
	w.config.RateLimiter = rateLimiter
	return err
}

func (w *wizard) askAdmin() error {
	if w.interactive {
		adminEmail, err := w.email("Admin email", w.defaultAdminEmail)
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
		if w.defaultAdminEmail == "" {
			return errs.Errorf("--admin-email is required when the auth URL's host, %s, is an IP address or a single label, which no admin email can be derived from", hostOf(w.config.AuthServerURL))
		}
		adminEmail = w.defaultAdminEmail
	}
	if err := validateEmail(adminEmail); err != nil {
		return errs.Wrap(err, "invalid admin email")
	}
	// Only a password the operator chose is judged: a generated one holds the classes SQL Server
	// asks for and no symbol, and was warned about as weak (#430).
	adminPassword := w.flags.AdminPassword
	generated := adminPassword == ""
	if generated {
		adminPassword = generatePassword()
	} else if issues := checkPasswordStrength(adminPassword); len(issues) > 0 {
		w.out.warning("Weak password: %s", strings.Join(issues, ", "))
	}
	w.reportPassword("Admin password", generated)
	w.out.info("Admin email: %s", adminEmail)
	w.config.AdminEmail = adminEmail
	w.config.AdminPassword = adminPassword
	w.config.AdminPasswordGenerated = generated
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
		choice, err := w.choice("Select option [1-3]", []string{"1", "2", "3"})
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
	if c.DBHost, err = w.databaseHost("Database host", defaultHost); err != nil {
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
	return w.databasePasswordFromPrompt()
}

func (w *wizard) databaseConnectionFromFlags() error {
	c := w.config
	c.DBHost = w.flags.DBHost
	if c.DBHost == "" {
		return errs.New("--db-host is required for Kubernetes/native deployments")
	}
	if err := validateDatabaseHost(c.DBHost); err != nil {
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
	w.databasePasswordFromFlags()
	w.out.info("Database host: %s:%s", c.DBHost, c.DBPort)
	w.out.info("Database name: %s", c.DBName)
	w.out.info("Database user: %s", c.DBUsername)
	return nil
}

// askDatabasePassword is a database the generated compose file runs, which needs only a password.
func (w *wizard) askDatabasePassword() error {
	if w.interactive {
		return w.databasePasswordFromPrompt()
	}
	w.databasePasswordFromFlags()
	return nil
}

// databasePasswordFromPrompt reads the database password hidden, offering a generated one, which is
// taken when the answer is empty and is never shown.
func (w *wizard) databasePasswordFromPrompt() error {
	generated := generatePassword()
	password, err := w.generatedPassword("Database password", generated)
	w.config.DBPassword = password
	w.config.DBPasswordGenerated = password == generated
	return err
}

// databasePasswordFromFlags takes --db-password, or generates one, and reports which.
func (w *wizard) databasePasswordFromFlags() {
	c := w.config
	c.DBPassword = w.flags.DBPassword
	c.DBPasswordGenerated = c.DBPassword == ""
	if c.DBPasswordGenerated {
		c.DBPassword = generatePassword()
	}
	w.reportPassword("Database password", c.DBPasswordGenerated)
}

// reportPassword says whether a password was generated or set, and where it is stored, and never
// what it is: the terminal's output reaches scrollback, recordings and the log of every CI job that
// runs the wizard, and every secret is in a file written 0600 (#396 decision 17).
func (w *wizard) reportPassword(what string, generated bool) {
	how := "set"
	if generated {
		how = "generated"
	}
	w.out.info("%s: %s, stored in %s", what, how, w.storedIn(goiabadaSecrets))
}

// storedIn is where a secret is stored: for Kubernetes the Secret named in the secrets file, and for
// the other types the secrets file itself.
func (w *wizard) storedIn(secret string) string {
	if w.config.Deployment.kind == deploymentKubernetes {
		return fmt.Sprintf("the %s Secret in %s", secret, w.paths.secrets)
	}
	return w.paths.secrets
}

func (w *wizard) generateCredentials() error {
	c := w.config
	c.AuthSessionAuthKey = generateHexKey(64)
	c.AuthSessionEncKey = generateHexKey(32)
	c.AdminSessionAuthKey = generateHexKey(64)
	c.AdminSessionEncKey = generateHexKey(32)
	c.AESEncryptionKey = generateHexKey(32)
	c.OAuthClientSecret = generateSecret(60)

	w.out.success("Auth server session keys generated")
	w.out.success("Admin console session keys generated")
	w.out.success("Auth server AES encryption key generated")
	w.warnAboutTheAESKey()
	w.out.success("OAuth client secret generated")
	return nil
}

// warnAboutTheAESKey says, beside the AES key's generation, that it is backed up apart from the
// database, and where it is stored, without printing it: it is the one secret whose loss loses
// data, and this is the moment at which a backup can still be made (#396 decision 16).
func (w *wizard) warnAboutTheAESKey() {
	stored := w.storedIn(encryptionKeySecret)
	w.out.warning("Back up the AES encryption key separately from the database: without it, the client")
	w.out.println("   secrets, SMTP credentials, OTP seeds and signing keys the database holds cannot be")
	w.out.printf("   recovered. It is stored in %s.\n", stored)
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

// writeConfiguration writes the description and, beside it, the secrets file, each 0600 through
// writePrivateFile whatever it holds, so no file's mode depends on its content and a later change
// that moves a secret back into the description cannot leak it (#426, #396 decision 14).
func (w *wizard) writeConfiguration() error {
	description, secrets := generatedConfiguration(w.config)
	files := []struct{ path, content string }{{w.paths.description, description.content}}
	if w.paths.separate() {
		files = append(files, struct{ path, content string }{w.paths.secrets, secrets.content})
	}
	for _, file := range files {
		if err := writePrivateFile(file.path, file.content); err != nil {
			return errs.Wrapf(err, "unable to write %s", filepath.Base(file.path))
		}
		w.out.success("Created: %s", file.path)
	}
	return nil
}
