package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/adminpassword"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/issuerlength"
)

// wizard fills a Config one step at a time, from the prompts or, when --type was given, from the
// flags alone, and writes the file the deployment type is configured by.
type wizard struct {
	asker
	flags *CLIFlags
	// interactive is false when --type was given: every answer then comes from a flag and nothing
	// is read but a password file named -.
	interactive bool
	// stdin is what a password file named - is read from.
	stdin  io.Reader
	config *Config
	// defaultAdminEmail is the admin email offered: admin@example.com for local testing, admin@
	// and the auth server host's parent otherwise, and none for a host without one.
	defaultAdminEmail string
	paths             outputPaths
	// testConnection dials the database the Config describes, with its TLS mode and CA file, and
	// reports what it found.
	testConnection func(out *console, c *Config) bool
}

func newWizard(flags *CLIFlags, in prompter, out *console) *wizard {
	return &wizard{
		asker:          asker{in: in, out: out},
		flags:          flags,
		interactive:    flags.DeploymentType == "",
		stdin:          os.Stdin,
		config:         &Config{KeepSecrets: flags.KeepSecrets},
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

// wizardSteps is every step in the order the wizard runs them. The setup wizard's docs page lists the
// questions in the same order under the same titles, and a test holds the two together.
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
		title:   "Namespace creation",
		applies: func(c *Config) bool { return c.Deployment.asksNamespace },
		run:     (*wizard).askCreateNamespace,
	},
	{
		title:   "Routing",
		applies: func(c *Config) bool { return c.Deployment.asksRouting },
		run:     (*wizard).askRouting,
	},
	{
		title:   "TLS certificates",
		applies: func(c *Config) bool { return c.Deployment.asksRouting && c.asksTLS() },
		run:     (*wizard).askTLS,
	},
	{
		title:   "Gateway listeners",
		applies: func(c *Config) bool { return c.Deployment.asksRouting && c.Routing == routingGateway },
		run:     (*wizard).askGatewayListeners,
	},
	{
		title:   "Gateway traffic policy",
		applies: func(c *Config) bool { return c.servedByEnvoyGateway() },
		run:     (*wizard).askTrafficPolicy,
	},
	{
		title:   "Network policy",
		applies: func(c *Config) bool { return c.Deployment.asksRouting },
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
	{
		title:   "Metrics",
		applies: func(c *Config) bool { return c.Deployment.asksMetrics },
		run:     (*wizard).askMetrics,
	},
	{
		title:   "Container images",
		applies: func(c *Config) bool { return c.Deployment.asksImages },
		run:     (*wizard).askImages,
	},
	{
		title:   "Labels and annotations",
		applies: func(c *Config) bool { return c.Deployment.kind == deploymentKubernetes },
		run:     (*wizard).askLabels,
	},
	{title: "Admin credentials", run: (*wizard).askAdmin},
	{
		title:   "Database connection",
		applies: func(c *Config) bool { return c.Engine.hasServer && c.Deployment.externalDatabase },
		run:     (*wizard).askDatabaseConnection,
	},
	{
		title:   "Database password",
		applies: func(c *Config) bool { return c.Engine.hasServer && !c.Deployment.externalDatabase && !c.KeepSecrets },
		run:     (*wizard).askDatabasePassword,
	},
	{
		title:     "Generating credentials",
		announced: true,
		applies:   func(c *Config) bool { return !c.KeepSecrets },
		run:       (*wizard).generateCredentials,
	},
	{run: (*wizard).confirm},
	{title: "Generating configuration", announced: true, run: (*wizard).writeConfiguration},
}

// setup runs the wizard to the end: the steps, the file, the completion message. A step's error
// ends it where it stands, and the file is written by the last step, so an error or an abort
// before it writes nothing.
func (w *wizard) setup() error {
	printBanner(w.out)
	if err := checkOutput(w.flags.Output); err != nil {
		return err
	}
	if !w.interactive {
		if err := w.flags.checkWritable(); err != nil {
			return err
		}
		if err := w.flags.checkPasswordSources(); err != nil {
			return err
		}
		if err := w.flags.checkKeptSecrets(); err != nil {
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
	if target.secretsFile == "" {
		// Native binaries keep every setting and every secret in one file, so no run can write it
		// again and leave the secrets as they are, and it has no answers file to read.
		switch {
		case w.flags.KeepSecrets:
			return errs.Errorf("--keep-secrets is for %s: %s holds the native binaries' secrets with every other setting, so no file is left to write", orList(answerDeploymentNames()), target.outputFile)
		case w.flags.Answers != "":
			return errs.Errorf("an answers file is for %s: the native binaries' %s holds every setting with the secrets", orList(answerDeploymentNames()), target.outputFile)
		}
	}
	w.config.Deployment = target
	// The files are placed here, before any step reports a secret, so each can say where it will be.
	w.paths = resolveOutputPaths(target, w.flags.Output)
	if err := w.confirmOverwrite(); err != nil {
		return err
	}
	if !target.asksURLs {
		w.config.AuthServerURL = "http://localhost:9090"
		w.config.AdminConsoleURL = "http://localhost:9091"
		w.defaultAdminEmail = "admin@example.com"
	}
	return nil
}

// confirmOverwrite stops before any other question when a file this run would write already exists.
// Each holds the secrets of whatever deployment was set up from it, the AES key among them, and a
// run writes newly generated ones over them: with no other copy of the old AES key, the data it
// encrypts can never be read again, and new secrets applied to a running deployment break it at its
// next restart, which on Kubernetes passes its health checks first (#542). So it warns in bold, and
// an interactive run asks, defaulting to no; a run without prompts needs --overwrite.
func (w *wizard) confirmOverwrite() error {
	if w.config.KeepSecrets {
		// The secrets file is never written, and the description and the answers file hold no secret:
		// writing them over what a run wrote before is what --keep-secrets is for.
		return nil
	}
	var existing []string
	for _, path := range w.paths.files() {
		if _, err := os.Lstat(path); err == nil { //nolint:gosec,nolintlint // G703: the paths are the ones this run writes, under the --output the operator chose, on their own machine; nolintlint because gosec v2.29.0 finds this G703 on some runs only (securego/gosec#1712, #494)
			existing = append(existing, path)
		}
	}
	if len(existing) == 0 {
		return nil
	}
	w.out.println()
	w.out.printf("%s%s⚠️  THESE FILES ALREADY EXIST, AND THIS RUN OVERWRITES THEM:%s\n", w.out.bold, w.out.red, w.out.reset)
	for _, path := range existing {
		w.out.printf("%s%s     %s%s\n", w.out.bold, w.out.red, path, w.out.reset)
	}
	w.out.printf("%s   They hold the secrets of any deployment set up from them, its AES key among them,%s\n", w.out.bold, w.out.reset)
	w.out.printf("%s   and this run writes newly generated ones. Without another copy of the old AES key,%s\n", w.out.bold, w.out.reset)
	w.out.printf("%s   the data it encrypts can never be read again. Back the files up first, or write%s\n", w.out.bold, w.out.reset)
	w.out.printf("%s   elsewhere with --output, and never apply the new secrets to a running deployment.%s\n", w.out.bold, w.out.reset)
	w.out.println()
	if !w.interactive {
		if w.flags.Overwrite {
			w.out.warning("--overwrite was given, so they are overwritten.")
			return nil
		}
		return errs.New("the output files already exist: back them up and move them, choose another --output, or pass --overwrite")
	}
	overwrite, err := w.yesNo("Overwrite them?", false)
	if err != nil {
		return err
	}
	if !overwrite {
		return errs.New("stopped before writing anything: back the files up and move them, or choose another --output")
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
	// The URLs given, when they are asked again, are offered.
	offered := "https://auth.example.com"
	if w.config.AuthServerURL != "" {
		offered = w.config.AuthServerURL
	}
	authServerURL, err := w.askURL("Auth server URL (e.g., https://auth.example.com)", offered, w.checkAuthURL)
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
			if authServerURL, err = w.askURL("Auth server URL", authServerURL, w.checkAuthURL); err != nil {
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

// checkAuthURL is checkURL, and the issuer's length as well: the first start seeds the auth server
// URL as the issuer, and the auth server refuses to start on one longer than the issuer allows, so
// the wizard writes none (#615).
func (w *wizard) checkAuthURL(value string) error {
	if err := w.checkURL(value); err != nil {
		return err
	}
	return issuerlength.Check(value)
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

// askURL asks until the answer passes check, and asks again when a plain-HTTP URL other than
// localhost is not confirmed.
func (w *wizard) askURL(prompt, defaultValue string, check func(string) error) (string, error) {
	for {
		value, err := w.validated(prompt, defaultValue, "URL", check)
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
	defaultURL, _ := defaultAdminURL(authServerURL, w.config.Deployment.routesByHost)
	for {
		adminConsoleURL, err := w.askURL(prompt, defaultURL, w.checkURL)
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
	if err := w.checkAuthURL(authServerURL); err != nil {
		return errs.Wrap(err, "invalid auth URL")
	}
	if strings.HasPrefix(authServerURL, "http://") {
		w.out.warning("Using HTTP for production is not recommended. Consider using HTTPS.")
	}
	if adminConsoleURL == "" {
		var derived bool
		if adminConsoleURL, derived = defaultAdminURL(authServerURL, w.config.Deployment.routesByHost); !derived {
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

// askCreateNamespace asks whether the files declare the namespace, so applying them creates it, yes
// by default. No is for one that already exists, which a platform team provides with its own labels,
// quotas and access: applying a Namespace there is refused, or resets what its owner set (#686
// section 2).
func (w *wizard) askCreateNamespace() error {
	ns := w.config.K8sNamespace
	if !w.interactive {
		w.config.NamespaceExists = !w.flags.CreateNamespace.or(true)
		answer := "created by the files"
		if w.config.NamespaceExists {
			answer = "already exists, declared in neither file"
		}
		w.out.info("Namespace %s: %s", ns, answer)
		return nil
	}
	w.out.printf("Both files can declare the namespace %s, so applying either creates it, labelled to\n", ns)
	w.out.println("warn about any pod that breaks the restricted Pod Security Standard.")
	w.out.println("  Yes: for a cluster you run. Applying the files needs the right to create and patch")
	w.out.println("       the namespace.")
	w.out.println("  No:  for a namespace that already exists, such as one a platform team provides with")
	w.out.println("       its own labels, quotas and access. Neither file declares it, so applying them")
	w.out.println("       needs rights inside the namespace alone.")
	w.out.println()
	create, err := w.yesNo("Create the namespace?", true)
	w.config.NamespaceExists = !create
	return err
}

// askRouting asks how traffic from outside the cluster reaches the servers, the tested Envoy Gateway
// recipe by default, and what the mode chosen attaches to: a Gateway's class, another's Gateway and
// listeners, or an IngressClass. The questions are about what the cluster has, never which vendor
// runs it (#686 section 3).
func (w *wizard) askRouting() error {
	if !w.interactive {
		return w.routingFromFlags()
	}
	c := w.config
	w.out.println("How does traffic from outside the cluster reach Goiabada?")
	w.out.println("  1. Envoy Gateway, as the steps after this wizard install it: a Gateway of class eg,")
	w.out.println("     with certificates from Let's Encrypt through cert-manager. The tested recipe.")
	w.out.println("  2. A Gateway of Goiabada's own, of a GatewayClass your cluster already has.")
	w.out.println("  3. A Gateway someone else runs, such as a platform team's shared one, which Goiabada's")
	w.out.println("     routes attach to.")
	w.out.println("  4. An Ingress per host, for an Ingress controller your cluster runs.")
	w.out.println("  5. None: the manifest has the Services alone, and you route them yourself.")
	w.out.println()
	choice, err := w.choice("Select routing [1-5]", []string{"1", "2", "3", "4", "5"})
	if err != nil {
		return err
	}
	c.Routing = routings[choice[0]-'1']
	switch c.Routing {
	case routingEnvoyGateway:
		c.useEnvoyGatewayRecipe()
		err = w.redirectPortsAgree()
	case routingGateway:
		w.out.println()
		c.GatewayClass, err = w.validated("GatewayClass of the Gateway", "", "name", validateObjectName)
	case routingExistingGateway:
		w.out.println()
		w.out.printf("The Gateway's owner must admit routes from the namespace %s on the listeners they\n", c.K8sNamespace)
		w.out.println("attach to (their allowedRoutes). Name the HTTPS listener for each host, the same one")
		w.out.println("for both when it's a wildcard listener: a route naming none would also attach to a")
		w.out.println("plain HTTP listener and serve Goiabada over HTTP.")
		if c.GatewayName, err = w.validated("Gateway name", "", "name", validateObjectName); err != nil {
			return err
		}
		if c.GatewayNamespace, err = w.namespace("Gateway namespace", ""); err != nil {
			return err
		}
		if c.AuthListener, err = w.validated("HTTPS listener for "+hostOf(c.AuthServerURL), "", "name", validateObjectName); err != nil {
			return err
		}
		c.AdminListener, err = w.validated("HTTPS listener for "+hostOf(c.AdminConsoleURL), c.AuthListener, "name", validateObjectName)
	case routingIngress:
		w.out.println()
		c.IngressClass, err = w.validated("IngressClass, blank for the cluster's default class", "", "name", optional(validateObjectName))
	}
	return err
}

// routingFromFlags is askRouting answered by --routing, envoy-gateway when left out, and the flags
// of the mode it names, each required where the mode has nothing to offer for it.
func (w *wizard) routingFromFlags() error {
	c, f := w.config, w.flags
	c.Routing = f.Routing
	if c.Routing == "" {
		c.Routing = routingEnvoyGateway
	}
	switch c.Routing {
	case routingEnvoyGateway:
		c.useEnvoyGatewayRecipe()
		if err := c.checkRedirectPort(); err != nil {
			return err
		}
		w.out.info("Routing: %s, a Gateway of class %s", c.Routing, envoyGatewayClass)
	case routingGateway:
		if err := requiredName("--gateway-class", f.GatewayClass, "--routing=gateway"); err != nil {
			return err
		}
		c.GatewayClass = f.GatewayClass
		w.out.info("Routing: %s, a Gateway of class %s", c.Routing, c.GatewayClass)
	case routingExistingGateway:
		for _, flag := range []struct{ name, value string }{
			{"--gateway-name", f.GatewayName},
			{"--gateway-namespace", f.GatewayNamespace},
			{"--auth-listener", f.AuthListener},
		} {
			if err := requiredName(flag.name, flag.value, "--routing=existing-gateway"); err != nil {
				return err
			}
		}
		if err := validateNamespace(f.GatewayNamespace); err != nil {
			return errs.Wrap(err, "invalid --gateway-namespace")
		}
		c.GatewayName, c.GatewayNamespace, c.AuthListener = f.GatewayName, f.GatewayNamespace, f.AuthListener
		c.AdminListener = f.AdminListener
		if c.AdminListener == "" {
			c.AdminListener = c.AuthListener
		} else if err := validateObjectName(c.AdminListener); err != nil {
			return errs.Wrap(err, "invalid --admin-listener")
		}
		w.out.info("Routing: %s, the Gateway %s in %s, %s", c.Routing, c.GatewayName, c.GatewayNamespace, c.listenersAnswer())
	case routingIngress:
		if f.IngressClass != "" {
			if err := validateObjectName(f.IngressClass); err != nil {
				return errs.Wrap(err, "invalid --ingress-class")
			}
		}
		c.IngressClass = f.IngressClass
		w.out.info("Routing: %s, of class %s", c.Routing, c.ingressClassAnswer())
	case routingNone:
		w.out.info("Routing: none, the Services alone")
	}
	return nil
}

// redirectPortsAgree is checkRedirectPort. Asked interactively, it has the URLs entered again,
// every check askURLs makes applying to them, offering the auth server URL given and an admin
// console URL on its HTTPS port, which agrees, rather than end the wizard (#686 section 3).
func (w *wizard) redirectPortsAgree() error {
	for {
		err := w.config.checkRedirectPort()
		if err == nil || !w.interactive {
			return err
		}
		w.out.println()
		w.out.printf("These URLs cannot be routed: %s.\n", err)
		w.out.println("Please re-enter the URLs:")
		if err := w.askURLs(); err != nil {
			return err
		}
	}
}

// requiredName refuses a name flag the mode needs and was left out, or one no Kubernetes object can
// be named.
func requiredName(flag, value, mode string) error {
	if value == "" {
		return errs.Errorf("%s is required with %s", flag, mode)
	}
	if err := validateObjectName(value); err != nil {
		return errs.Wrapf(err, "invalid %s", flag)
	}
	return nil
}

// optional is validate for a non-empty answer, and accepts an empty one.
func optional(validate func(string) error) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		return validate(value)
	}
}

// askTLS asks where the certificates of the Gateway or Ingresses the manifest creates come from: a
// cert-manager ClusterIssuer by default, an Issuer, TLS Secrets the platform supplies, or TLS ended
// in front of them, which leaves them plain HTTP (#686 section 3).
func (w *wizard) askTLS() error {
	c := w.config
	if !w.interactive {
		return w.tlsFromFlags()
	}
	ns := c.K8sNamespace
	w.out.printf("Where do the certificates for %s and %s come from?\n", hostOf(c.AuthServerURL), hostOf(c.AdminConsoleURL))
	w.out.println("  1. A cert-manager ClusterIssuer your cluster has.")
	w.out.printf("  2. A cert-manager Issuer in the namespace %s.\n", ns)
	w.out.printf("  3. TLS Secrets you supply in the namespace %s, one per host or one for both.\n", ns)
	w.out.println("  4. TLS ends in front of the cluster, at a load balancer or a CDN that forwards plain")
	w.out.println("     HTTP: the routing layer serves HTTP alone, and redirects nothing.")
	w.out.println()
	choice, err := w.choice("Select certificates [1-4]", []string{"1", "2", "3", "4"})
	if err != nil {
		return err
	}
	c.TLS = tlsSources[choice[0]-'1']
	c.TLSSecretAuth, c.TLSSecretAdmin = authCertificateSecret, adminCertificateSecret
	switch c.TLS {
	case tlsClusterIssuer:
		c.TLSIssuer, err = w.validated("ClusterIssuer name", "", "name", validateObjectName)
	case tlsIssuer:
		c.TLSIssuer, err = w.validated("Issuer name", "", "name", validateObjectName)
	case tlsSecrets:
		if c.TLSSecretAuth, err = w.validated("TLS Secret for "+hostOf(c.AuthServerURL), authCertificateSecret, "name", validateObjectName); err != nil {
			return err
		}
		c.TLSSecretAdmin, err = w.validated("TLS Secret for "+hostOf(c.AdminConsoleURL), adminCertificateSecret, "name", validateObjectName)
	}
	return err
}

// tlsFromFlags is askTLS answered by --tls, cluster-issuer when left out, with --tls-issuer required
// for an issuer, and --auth-tls-secret and --admin-tls-secret read for Secrets alone.
func (w *wizard) tlsFromFlags() error {
	c, f := w.config, w.flags
	c.TLS = f.TLS
	if c.TLS == "" {
		c.TLS = tlsClusterIssuer
	}
	c.TLSSecretAuth, c.TLSSecretAdmin = authCertificateSecret, adminCertificateSecret
	switch c.TLS {
	case tlsClusterIssuer, tlsIssuer:
		if err := requiredName("--tls-issuer", f.TLSIssuer, "--tls="+string(c.TLS)); err != nil {
			return err
		}
		c.TLSIssuer = f.TLSIssuer
	case tlsSecrets:
		for _, secret := range []struct {
			flag  string
			value string
			into  *string
		}{{"--auth-tls-secret", f.TLSSecretAuth, &c.TLSSecretAuth}, {"--admin-tls-secret", f.TLSSecretAdmin, &c.TLSSecretAdmin}} {
			if secret.value == "" {
				continue
			}
			if err := validateObjectName(secret.value); err != nil {
				return errs.Wrapf(err, "invalid %s", secret.flag)
			}
			*secret.into = secret.value
		}
	}
	w.out.info("TLS certificates: %s", c.tlsAnswer())
	return nil
}

// askGatewayListeners asks the ports of the listeners of a Gateway of the cluster's own class, 80
// and 443 by default, the HTTPS one only when the Gateway ends TLS: some implementations accept only
// their own proxy's ports (#686 section 3).
func (w *wizard) askGatewayListeners() error {
	c := w.config
	if !w.interactive {
		return w.gatewayListenersFromFlags()
	}
	w.out.println("Most Gateway implementations take the well-known ports 80 and 443 for the listeners.")
	w.out.println("Some take only their own proxy's ports: Traefik's Gateway takes 8000 and 8443, and")
	w.out.println("refuses 80. The GatewayClass's documentation says which.")
	w.out.println()
	for {
		httpPort, err := w.port("HTTP listener port", "80")
		if err != nil {
			return err
		}
		c.GatewayHTTPPort, _ = strconv.Atoi(httpPort)
		if !c.endsTLS() {
			return nil
		}
		httpsPort, err := w.port("HTTPS listener port", "443")
		if err != nil {
			return err
		}
		c.GatewayHTTPSPort, _ = strconv.Atoi(httpsPort)
		if c.GatewayHTTPPort != c.GatewayHTTPSPort {
			return w.redirectPortsAgree()
		}
		w.out.println("The two listeners need ports of their own. Please try again.")
	}
}

// gatewayListenersFromFlags is askGatewayListeners answered by --gateway-http-port and
// --gateway-https-port, 80 and 443 when left out.
func (w *wizard) gatewayListenersFromFlags() error {
	c, f := w.config, w.flags
	c.GatewayHTTPPort, c.GatewayHTTPSPort = 80, 443
	for _, port := range []struct {
		flag  string
		value int
		into  *int
	}{{"--gateway-http-port", f.GatewayHTTPPort, &c.GatewayHTTPPort}, {"--gateway-https-port", f.GatewayHTTPSPort, &c.GatewayHTTPSPort}} {
		if port.value == 0 {
			continue
		}
		if err := validatePort(strconv.Itoa(port.value)); err != nil {
			return errs.Wrapf(err, "invalid %s", port.flag)
		}
		*port.into = port.value
	}
	if !c.endsTLS() {
		c.GatewayHTTPSPort = 0
		w.out.info("Gateway listener: HTTP on %d", c.GatewayHTTPPort)
		return nil
	}
	if c.GatewayHTTPPort == c.GatewayHTTPSPort {
		return errs.Errorf("--gateway-http-port and --gateway-https-port are both %d, and each listener needs a port of its own", c.GatewayHTTPPort)
	}
	if err := c.checkRedirectPort(); err != nil {
		return err
	}
	w.out.info("Gateway listeners: HTTP on %d, HTTPS on %d", c.GatewayHTTPPort, c.GatewayHTTPSPort)
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
	w.out.println("     at the cost of an Envoy pod on every node, when the load balancer passes each")
	w.out.println("     connection through. One that proxies connections, as some do, shows Goiabada its")
	w.out.println("     own address under either policy.")
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

// askNetworkPolicy asks whether NetworkPolicies admit only the routing layer's namespace to both
// servers, and the admin console to the auth server, no by default (#396 decision 5), and with them,
// that namespace: envoy-gateway-system by default for the Envoy Gateway recipe, and asked with
// nothing offered for any other mode, since a Gateway's proxies need not run in its namespace (#686
// section 3); and the service mesh's ports (#686 section 8).
func (w *wizard) askNetworkPolicy() error {
	c := w.config
	if !w.interactive {
		return w.networkPolicyFromFlags()
	}
	w.out.println("NetworkPolicies can admit only the namespace your routing layer's proxies run in to both")
	w.out.println("servers, and the admin console to the auth server.")
	w.out.println("  Yes: on a CNI that enforces NetworkPolicy, every other pod is refused, including a")
	w.out.println("       workload in another namespace that calls the auth server's Service, for /certs")
	w.out.println("       or /userinfo, until you admit its namespace as the policy's comment shows.")
	w.out.println("  No:  any pod in the cluster can reach both servers, and can choose the address it is")
	w.out.println("       rate limited and audited under by sending its own X-Forwarded-For.")
	w.out.println("A routing layer whose proxies are not pods in one namespace, such as a cloud load balancer")
	w.out.println("sending to pod addresses, cannot be admitted this way.")
	w.out.println()
	restrict, err := w.yesNo("Restrict who can reach Goiabada with NetworkPolicies?", false)
	if err != nil || !restrict {
		return err
	}
	c.NetworkPolicy = true
	w.out.println()
	defaultNamespace := ""
	switch {
	case c.servedByEnvoyGateway():
		w.out.printf("Envoy Gateway runs its proxies in %s unless it was told otherwise.\n", envoyProxyNamespace)
		defaultNamespace = envoyProxyNamespace
	case c.Routing == routingExistingGateway:
		w.out.printf("A Gateway's proxies may run outside its own namespace, %s: ask its owner.\n", c.GatewayNamespace)
	}
	if c.ProxyNamespace, err = w.namespace("Namespace your routing layer's proxies run in", defaultNamespace); err != nil {
		return err
	}
	return w.askMeshPorts()
}

// networkPolicyFromFlags is askNetworkPolicy answered by --network-policy, --proxy-namespace, which
// only the Envoy Gateway recipe offers a default for, and --mesh-ports.
func (w *wizard) networkPolicyFromFlags() error {
	c, f := w.config, w.flags
	c.NetworkPolicy = f.NetworkPolicy
	if !c.NetworkPolicy {
		w.out.info("NetworkPolicies: no")
		return nil
	}
	namespace := f.ProxyNamespace
	if namespace == "" {
		if !c.servedByEnvoyGateway() {
			return errs.Errorf("--proxy-namespace is required with --network-policy and --routing=%s", c.Routing)
		}
		namespace = envoyProxyNamespace
	}
	if err := validateNamespace(namespace); err != nil {
		return errs.Wrap(err, "invalid --proxy-namespace")
	}
	c.ProxyNamespace = namespace
	w.out.info("NetworkPolicies: yes, admitting only the namespace %s and the admin console", namespace)
	c.MeshPorts = f.MeshPorts
	if len(c.MeshPorts) > 0 {
		w.out.info("Service mesh ports: %s, admitted from the same sources", joinPorts(c.MeshPorts))
	}
	return nil
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
// Kubernetes, unless under Envoy Gateway's Local traffic policy, after which the question comes,
// since it decides that default (#396 decision 9, #686 section 3).
func (w *wizard) askRateLimiter() error {
	defaultOn := w.config.rateLimiterDefault()
	if !w.interactive {
		w.config.RateLimiter = w.flags.RateLimiter.or(defaultOn)
		answer := "off"
		if w.config.RateLimiter {
			answer = "on"
		}
		if !w.flags.RateLimiter.set && !defaultOn {
			if w.config.servedByEnvoyGateway() {
				answer += " (the default under the Cluster traffic policy; --rate-limiter turns it on)"
			} else {
				answer += " (the default for --routing=" + string(w.config.Routing) + "; --rate-limiter turns it on)"
			}
		}
		w.out.info("Rate limiter: %s", answer)
		return nil
	}
	w.out.println("The auth server always limits, per user, wrong one-time codes, password checks on the")
	w.out.println("Account pages, email verification codes and verification mails, and, per email, wrong")
	w.out.println("passwords (100 an hour), password-reset mails and registration notices. Its rate limiter")
	w.out.println("adds limits per client address on sign-ins, password resets, self-registrations and")
	w.out.println("client registrations, and on wrong passwords per email from one network (10 per 15")
	w.out.println("minutes).")
	if w.config.servedByEnvoyGateway() {
		if defaultOn {
			w.out.println("Under the Local traffic policy Goiabada sees each client's address, so the per-IP")
			w.out.println("limits count each client alone, when the load balancer passes connections through.")
			w.out.println("If it proxies them, every client shares the load balancer's address: check the")
			w.out.println("ip= of your own request in the auth server's log once it runs.")
		} else {
			w.out.println("Under the Cluster traffic policy Goiabada sees a node's address, so the per-address")
			w.out.println("limits count every user the load balancer sends through one node together (30 password")
			w.out.println("posts a minute and 20 forgot-password requests per 5 minutes per node, for example),")
			w.out.println("which throttles sign-ins on a busy site. That is why it is off by default here.")
			w.out.println("On, every client through a node counts as one network, so 10 wrong passwords block an")
			w.out.println("email's password sign-ins for 15 minutes for every client through a node.")
		}
	} else if w.config.Deployment.asksRouting {
		w.out.println("Goiabada sees the address each connection reached your routing layer from, which can be")
		w.out.println("a node's or a load balancer's, one for every client: the per-address limits then count")
		w.out.println("every client together, which throttles sign-ins on a busy site. That is why it is off")
		w.out.println("by default here. Once Goiabada runs, read the ip= of your own request in the auth")
		w.out.println("server's log: your own address means the limits count each client alone.")
	}
	w.out.printf("The limits are listed at %s\n", rateLimitsDocsURL)
	w.out.println()
	rateLimiter, err := w.yesNo("Turn on the rate limiter?", defaultOn)
	w.config.RateLimiter = rateLimiter
	return err
}

// askMetrics asks whether to expose the servers' Prometheus metrics, and to which kind of scraper,
// none by default; for a PodMonitor, the labels the operator's Prometheus selects it by; and, with
// the NetworkPolicies on, the namespace the scraper runs in, which they admit to the metrics ports
// alone (#400 decisions 7 and 8).
func (w *wizard) askMetrics() error {
	c := w.config
	if !w.interactive {
		return w.metricsFromFlags()
	}
	w.out.printf("Both servers can serve Prometheus metrics on a port of their own, %d on the auth server\n", authServerMetricsPort)
	w.out.printf("and %d on the admin console, which no Service or route publishes. A scraper finds the\n", adminConsoleMetricsPort)
	w.out.println("pods by one of:")
	w.out.println("  1. None: the metrics listeners stay off.")
	w.out.println("  2. Pod annotations, prometheus.io/scrape, port and path: read by the prometheus-community")
	w.out.println("     prometheus chart's default configuration. kube-prometheus-stack ignores them.")
	w.out.println("  3. A PodMonitor for the Prometheus Operator, which kube-prometheus-stack runs. On a cluster")
	w.out.println("     without the Operator's CRDs, kubectl apply exits 1 after applying everything else.")
	w.out.printf("Grafana Alloy, the OpenTelemetry Collector and other scrapers: %s\n", monitoringDocsURL)
	w.out.println()
	choice, err := w.choice("Expose Prometheus metrics? [1-3]", []string{"1", "2", "3"})
	if err != nil {
		return err
	}
	c.Metrics = map[string]metricsExposure{"1": metricsNone, "2": metricsAnnotations, "3": metricsPodMonitor}[choice]

	if c.Metrics == metricsPodMonitor {
		w.out.println()
		w.out.println("A Prometheus the Operator runs selects only the PodMonitors its podMonitorSelector")
		w.out.println("matches: kube-prometheus-stack, by default, only those labeled release: <its release name>.")
		answer, err := w.validated("Labels your Prometheus selects PodMonitors by (e.g., release=kube-prometheus-stack), blank for none",
			"", "labels", func(value string) error {
				_, invalid := parsePodMonitorLabels(value)
				return invalid
			})
		if err != nil {
			return err
		}
		c.PodMonitorLabels, _ = parsePodMonitorLabels(answer)
	}

	if c.admitsMetricsScraper() {
		w.out.println()
		w.out.println("The NetworkPolicies admit the scraper's namespace to the metrics ports, and to nothing else.")
		namespace, err := w.namespace("Namespace your metrics scraper runs in", defaultMetricsNamespace)
		if err != nil {
			return err
		}
		c.MetricsNamespace = namespace
	}
	return nil
}

// metricsFromFlags is askMetrics answered by --metrics, none when left out, --podmonitor-labels, read
// only for a PodMonitor, and --metrics-namespace, read only with the NetworkPolicies on.
func (w *wizard) metricsFromFlags() error {
	c := w.config
	c.Metrics = w.flags.Metrics
	if c.Metrics == "" {
		c.Metrics = metricsNone
	}
	if c.Metrics == metricsPodMonitor {
		c.PodMonitorLabels = w.flags.PodMonitorLabels
	}
	w.out.info("Metrics: %s", c.metricsAnswer())
	if !c.admitsMetricsScraper() {
		return nil
	}
	namespace := w.flags.MetricsNamespace
	if namespace == "" {
		namespace = defaultMetricsNamespace
	}
	if err := validateNamespace(namespace); err != nil {
		return errs.Wrap(err, "invalid --metrics-namespace")
	}
	c.MetricsNamespace = namespace
	w.out.info("Metrics scraper: namespace %s, admitted by the NetworkPolicies", namespace)
	return nil
}

func (w *wizard) askAdmin() error {
	if w.interactive {
		adminEmail, err := w.email("Admin email", w.defaultAdminEmail)
		if err != nil {
			return err
		}
		w.config.AdminEmail = adminEmail
		if w.config.KeepSecrets {
			return nil
		}
		// A generated default, where the prompt offered changeme, the password the docs and the
		// samples printed, to every operator who pressed Enter.
		generated := generatePassword()
		adminPassword, err := w.adminPassword("Admin password", generated, adminEmail)
		if err != nil {
			return err
		}
		w.config.AdminEmail = adminEmail
		w.config.AdminPassword = adminPassword
		w.config.AdminPasswordGenerated = adminPassword == generated
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
	if w.config.KeepSecrets {
		w.out.info("Admin email: %s", adminEmail)
		w.config.AdminEmail = adminEmail
		return nil
	}
	// Only a password the operator chose is judged, and only by the first administrator's rule.
	adminPassword, err := w.givenPassword(w.flags.AdminPassword, "--admin-password-file", w.flags.AdminPasswordFile)
	if err != nil {
		return err
	}
	generated := adminPassword == ""
	if generated {
		adminPassword = generatePassword()
	} else {
		// The auth server reads GOIABADA_ADMIN_PASSWORD with the whitespace around it trimmed, as the
		// prompt trims an answer, so the password judged and written is the one the first start
		// seeds, and the one the administrator signs in with (#500).
		adminPassword = strings.TrimSpace(adminPassword)
		// The first start refuses to seed what this refuses, so writing it would ship a deployment
		// that cannot start (#500). It is compared with the admin email and the app name this run
		// writes, which that start seeds beside it (#550 decision 7).
		if err := adminpassword.Check(adminPassword, adminEmail, seededAppName); err != nil {
			flag := "--admin-password"
			if w.flags.AdminPasswordFile != "" {
				flag = "--admin-password-file"
			}
			return errs.Wrapf(err, "invalid %s", flag)
		}
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
		if err := w.databaseTLSFromFlags(); err != nil {
			return err
		}
		// Under --keep-secrets the password is the secrets file's, which no step reads, so nothing
		// can be tested.
		if !w.flags.SkipDBTest && !c.KeepSecrets && !w.testConnection(w.out, c) {
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
		if c.KeepSecrets {
			return nil
		}

		w.out.println()
		// A name only the cluster's DNS answers fails here even when the pods reach it, which read as a
		// mistyped host on a real cluster, so the test is offered but not taken by default (#542).
		testByDefault := true
		if c.Deployment.kind == deploymentKubernetes && clusterInternalHost(c.DBHost) {
			testByDefault = false
			w.out.printf("%s looks like a name only the cluster resolves:\n", c.DBHost)
			w.out.println("a test from this machine fails even when the pods reach the database.")
			w.out.println("The auth server's log says if it can't connect:")
			w.out.printf("  kubectl logs -n %s deployment/goiabada-authserver\n", c.K8sNamespace)
		}
		test, err := w.yesNo("Test database connection?", testByDefault)
		if err != nil {
			return err
		}
		if !test || w.testConnection(w.out, c) {
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
	if !c.KeepSecrets {
		if err = w.databasePasswordFromPrompt(); err != nil {
			return err
		}
	}
	return w.databaseTLSFromPrompts()
}

// databaseTLSFromPrompts asks how the auth server protects its connection to the database, from a
// menu of the five modes offering the one answered before, prefer the first time, as the auth
// server does unset; then, for verify-ca and verify-full alone, the CA file, blank for the system's
// roots; then the client certificate pair, for the three modes that carry one and an engine whose
// driver reads it; then, for verify-full alone, the host name the certificate is checked against,
// blank for the host dialed. What the auth server would refuse is asked again, as its refusals
// say (#502 decision 7, #546).
func (w *wizard) databaseTLSFromPrompts() error {
	c := w.config
	w.out.println()
	w.out.println("How should the auth server protect its connection to the database?")
	choices := make([]string, 0, len(tlsModes))
	offered := ""
	for i, m := range tlsModes {
		number := strconv.Itoa(i + 1)
		choices = append(choices, number)
		if m.name == c.DBTLSMode || (offered == "" && m.name == defaultTLSMode) {
			offered = number
		}
		description := m.describedFor(c.Engine.name)
		if checksHostName(m.name) {
			description += verifyFullOverrideMenuNote
		}
		w.out.printf("  %s. %s: %s\n", number, m.name, description)
	}
	w.out.println("Only verify-full makes sure the auth server reached your database and nothing in between.")
	w.out.println()
	choice, err := w.choiceOffering(fmt.Sprintf("Select TLS mode [1-%d]", len(choices)), choices, offered)
	if err != nil {
		return err
	}
	index, _ := strconv.Atoi(choice)
	c.DBTLSMode, c.DBTLSCAFile, c.DBTLSCA = tlsModes[index-1].name, "", ""
	c.DBTLSClientCertFile, c.DBTLSClientKeyFile, c.DBTLSClientCert, c.DBTLSClientKey, c.DBTLSServerName = "", "", "", "", ""
	if !checksCertificate(c.DBTLSMode) {
		w.warnUncheckedTLS()
		if !carriesClientCertificate(c.DBTLSMode) {
			return nil
		}
	}
	if checksCertificate(c.DBTLSMode) {
		_, err = w.validated("CA file the database's certificate chains to (PEM), blank for the system's roots", "", "CA file",
			func(path string) error {
				if path == "" {
					return nil
				}
				absolute, certificates, refused := readCAFile(path)
				c.DBTLSCAFile, c.DBTLSCA = absolute, certificates
				return refused
			})
		if err != nil {
			return err
		}
	}
	if c.Engine.takesClientCertificate {
		if err = w.clientCertificateFromPrompts(); err != nil {
			return err
		}
	}
	if checksHostName(c.DBTLSMode) {
		_, err = w.validated("Host name verify-full checks the certificate against when the address dialed is not the name certified, blank for the host dialed", "", "host name",
			func(name string) error {
				if refused := checkWritable(name); refused != nil {
					return errs.Wrapf(refused, "the host name cannot be written to the configuration")
				}
				c.DBTLSServerName = name
				return nil
			})
	}
	return err
}

// clientCertificateFromPrompts asks for the pair the connection presents to the database, the
// certificate first and the key beside it, both or neither: a blank key returns to the certificate,
// since half a pair is refused, and a pair the auth server would refuse is asked again, as its
// refusals say (#546).
func (w *wizard) clientCertificateFromPrompts() error {
	c := w.config
	if c.KeepSecrets {
		// The pair is in the secrets file, which this run leaves as it is: only whether the auth
		// server presents one is asked.
		kept, err := w.yesNo(fmt.Sprintf("Does the auth server present a client certificate to the database? Its %s Secret stays as it is", dbClientTLSSecret), false)
		c.DBTLSClientCertKept = kept
		return err
	}
	for {
		// No default: a blank answer means none, the second time round as the first, rather than the
		// certificate a blank key returned from (#546).
		cert, err := w.validated("Client certificate the auth server presents to the database (PEM), blank for none", "", "client certificate",
			func(path string) error {
				if path == "" {
					c.DBTLSClientCertFile, c.DBTLSClientKeyFile, c.DBTLSClientCert, c.DBTLSClientKey = "", "", "", ""
					return nil
				}
				_, refused := os.ReadFile(path) //nolint:gosec // G304: the operator names the certificate their database reads
				if refused != nil {
					return errs.Errorf("the client certificate %s cannot be read: %s", strconv.Quote(path), cannotBeRead(refused))
				}
				if err := checkWritable(path); err != nil {
					return errs.Wrapf(err, "the client certificate %s cannot be written to the configuration", strconv.Quote(path))
				}
				c.DBTLSClientCertFile = path
				return nil
			})
		if err != nil {
			return err
		}
		if cert == "" {
			return nil
		}
		key, err := w.validated("Client certificate's private key (PEM), blank to name the certificate again", "", "client key",
			func(path string) error {
				if path == "" {
					return nil
				}
				pair, refused := readClientCertificate(c.DBTLSClientCertFile, path)
				if refused != nil {
					return refused
				}
				c.DBTLSClientCertFile, c.DBTLSClientKeyFile, c.DBTLSClientCert, c.DBTLSClientKey = pair.certFile, pair.keyFile, pair.certPEM, pair.keyPEM
				return nil
			})
		if err != nil {
			return err
		}
		if key == "" {
			continue
		}
		w.out.info("Database client certificate: %s and %s", c.DBTLSClientCertFile, c.DBTLSClientKeyFile)
		return nil
	}
}

// databaseTLSFromFlags is databaseTLSFromPrompts answered by --db-tls-mode, prefer when left out,
// and --db-tls-ca-file, refused as the auth server refuses GOIABADA_DB_TLS_CA_FILE: beside a mode
// that checks no certificate, unreadable, or holding no PEM certificate; and by
// --db-tls-client-cert-file, --db-tls-client-key-file and --db-tls-server-name, refused as the
// server refuses that pair and that override (#502 decisions 4 and 7, #546).
func (w *wizard) databaseTLSFromFlags() error {
	c := w.config
	mode := w.flags.DBTLSMode
	if mode == "" {
		mode = defaultTLSMode
	}
	if !knownTLSMode(mode) {
		return errs.Errorf("invalid --db-tls-mode %q: use %s", mode, orList(tlsModeNames()))
	}
	c.DBTLSMode = mode
	w.out.info("Database TLS mode: %s", mode)
	switch {
	case w.flags.DBTLSCAFile != "" && !checksCertificate(mode):
		described := mode
		if w.flags.DBTLSMode == "" {
			described = "left out, so " + mode
		}
		return errs.Errorf("--db-tls-ca-file is set while --db-tls-mode is %s, which checks no certificate: only verify-ca and verify-full read a CA file", described)
	case w.flags.DBTLSCA != "":
		// An answers file's certificates, which a mode that checks none would leave unread.
		if !checksCertificate(mode) {
			return errs.Errorf("db-tls-ca is answered while --db-tls-mode is %s, which checks no certificate: only verify-ca and verify-full read the CA's certificates", mode)
		}
		c.DBTLSCA = w.flags.DBTLSCA
		w.out.info("Database CA: the certificates in %s", w.flags.Answers)
	case w.flags.DBTLSCAFile == "":
		// Only a mode that checks the certificate has roots to name; disable, prefer and require
		// check none, and the warning below says so (#546).
		if checksCertificate(mode) {
			w.out.info("Database CA: the system's roots")
		}
	default:
		absolute, certificates, err := readCAFile(w.flags.DBTLSCAFile)
		if err != nil {
			return errs.Wrap(err, "invalid --db-tls-ca-file")
		}
		c.DBTLSCAFile, c.DBTLSCA = absolute, certificates
		w.out.info("Database CA file: %s", absolute)
	}
	if err := w.clientCertificateFromFlags(); err != nil {
		return err
	}
	if w.flags.DBTLSServerName != "" {
		if !checksHostName(mode) {
			described := mode
			if w.flags.DBTLSMode == "" {
				described = "left out, so " + mode
			}
			return errs.Errorf("--db-tls-server-name is set while --db-tls-mode is %s, which checks no host name: only verify-full checks the certificate's host name", described)
		}
		c.DBTLSServerName = w.flags.DBTLSServerName
		w.out.info("Database certificate host name: %s", w.flags.DBTLSServerName)
	}
	if !checksCertificate(mode) {
		w.warnUncheckedTLS()
	}
	return nil
}

// clientCertificateFromFlags is the client certificate pair answered by --db-tls-client-cert-file
// and --db-tls-client-key-file, refused as the auth server refuses the pair: half of one, one on
// SQL Server, whose driver takes none, one beside a mode that may send no TLS, and one the wizard
// cannot read. SQLite reads no pair, as the auth server reads none beside it (#546).
func (w *wizard) clientCertificateFromFlags() error {
	c := w.config
	if !c.Engine.hasServer {
		return nil
	}
	if w.flags.DBTLSClientCertFile == "" && w.flags.DBTLSClientKeyFile == "" {
		return w.keptClientCertificate()
	}
	if w.flags.DBTLSClientCertFile == "" || w.flags.DBTLSClientKeyFile == "" {
		half, other := "--db-tls-client-cert-file", "--db-tls-client-key-file"
		named := w.flags.DBTLSClientCertFile
		if named == "" {
			half, other = other, half
			named = w.flags.DBTLSClientKeyFile
		}
		return errs.Errorf("%s is %s without %s: name both or neither", half, strconv.Quote(named), other)
	}
	if !c.Engine.takesClientCertificate {
		return errs.Errorf("--db-tls-client-cert-file is set while --db is %s, whose driver takes no client certificate", c.Engine.name)
	}
	mode := w.flags.DBTLSMode
	if mode == "" {
		mode = defaultTLSMode
	}
	if !carriesClientCertificate(mode) {
		described := mode
		if w.flags.DBTLSMode == "" {
			described = "left out, so " + mode
		}
		sends := "sends no TLS"
		if mode == "prefer" {
			sends = "may send no TLS"
		}
		return errs.Errorf("--db-tls-client-cert-file is set while --db-tls-mode is %s, which %s: only require, verify-ca and verify-full carry a client certificate", described, sends)
	}
	pair, err := readClientCertificate(w.flags.DBTLSClientCertFile, w.flags.DBTLSClientKeyFile)
	if err != nil {
		return errs.Wrap(err, "invalid --db-tls-client-cert-file and --db-tls-client-key-file")
	}
	c.DBTLSClientCertFile, c.DBTLSClientKeyFile, c.DBTLSClientCert, c.DBTLSClientKey = pair.certFile, pair.keyFile, pair.certPEM, pair.keyPEM
	w.out.info("Database client certificate: %s and %s", pair.certFile, pair.keyFile)
	return nil
}

// keptClientCertificate is an answers file's db-tls-client-cert, which says the auth server
// presents a pair without naming its files: under --keep-secrets the secrets file holds it already,
// and any other run needs the files, to write the pair into the one it writes.
func (w *wizard) keptClientCertificate() error {
	c := w.config
	if !w.flags.DBTLSClientCertKept {
		return nil
	}
	if !c.KeepSecrets {
		return errs.Errorf("%s answers that the auth server presents a client certificate: name it with --db-tls-client-cert-file and --db-tls-client-key-file, or pass --keep-secrets to leave the Secret holding it as it is", w.flags.Answers)
	}
	if !c.Engine.takesClientCertificate {
		return errs.Errorf("db-tls-client-cert is answered while --db is %s, whose driver takes no client certificate", c.Engine.name)
	}
	if !carriesClientCertificate(c.DBTLSMode) {
		return errs.Errorf("db-tls-client-cert is answered while --db-tls-mode is %s: only require, verify-ca and verify-full carry a client certificate", c.DBTLSMode)
	}
	c.DBTLSClientCertKept = true
	w.out.info("Database client certificate: the one in the %s Secret, left as it is", dbClientTLSSecret)
	return nil
}

// warnUncheckedTLS is #502 decision 3's warning at the moment a mode that checks no certificate is
// chosen, for a database the operator runs, which the auth server may reach across any network.
func (w *wizard) warnUncheckedTLS() {
	w.out.warning("GOIABADA_DB_TLS_MODE is %s, which checks no certificate: the auth server cannot tell", w.config.DBTLSMode)
	w.out.println("   whether it reached your database or something in between, which could then read and")
	w.out.println("   change everything Goiabada stores. verify-full checks it.")
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
	if !c.KeepSecrets {
		if err := w.databasePasswordFromFlags(); err != nil {
			return err
		}
	}
	w.out.info("Database host: %s:%s", c.DBHost, c.DBPort)
	w.out.info("Database name: %s", c.DBName)
	w.out.info("Database user: %s", c.DBUsername)
	return nil
}

// askDatabasePassword is a database the generated compose file runs, which needs only a password.
// Its TLS mode is not asked: the Compose file writes prefer, what the auth server does unset, and
// the warning says why that is safe there (#502 decision 7).
func (w *wizard) askDatabasePassword() error {
	var err error
	if w.interactive {
		err = w.databasePasswordFromPrompt()
	} else {
		err = w.databasePasswordFromFlags()
	}
	if err != nil {
		return err
	}
	w.config.DBTLSMode = composeDBTLSMode
	w.out.warning("GOIABADA_DB_TLS_MODE is %s, which checks no certificate. The database runs on", composeDBTLSMode)
	w.out.println("   this Compose file's own network, so the connection never leaves this host. If you move")
	w.out.println("   the database off it, set GOIABADA_DB_TLS_MODE to verify-full.")
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

// databasePasswordFromFlags takes --db-password or --db-password-file, or generates one, and
// reports which.
func (w *wizard) databasePasswordFromFlags() error {
	c := w.config
	password, err := w.givenPassword(w.flags.DBPassword, "--db-password-file", w.flags.DBPasswordFile)
	if err != nil {
		return err
	}
	c.DBPassword = password
	c.DBPasswordGenerated = c.DBPassword == ""
	if c.DBPasswordGenerated {
		c.DBPassword = generatePassword()
	}
	w.reportPassword("Database password", c.DBPasswordGenerated)
	return nil
}

// givenPassword is the password given as a flag's value, or read from the file the flag named
// fileFlag names, and empty when neither was given. checkPasswordSources has refused both.
func (w *wizard) givenPassword(value, fileFlag, file string) (string, error) {
	if file == "" {
		return value, nil
	}
	return readPasswordFile(fileFlag, file, w.stdin)
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
	description, secrets := writtenConfiguration(w.config, w.paths)
	files := []struct{ path, content string }{{w.paths.description, description.content}}
	if w.paths.separate() && !w.config.KeepSecrets {
		files = append(files, struct{ path, content string }{w.paths.secrets, secrets.content})
	}
	if w.paths.answers != "" {
		files = append(files, struct{ path, content string }{w.paths.answers, generateAnswers(w.config, w.paths)})
	}
	for _, file := range files {
		if err := writePrivateFile(file.path, file.content); err != nil {
			return errs.Wrapf(err, "unable to write %s", filepath.Base(file.path))
		}
		w.out.success("Created: %s", file.path)
	}
	if w.paths.separate() && w.config.KeepSecrets {
		w.out.info("Not written: %s, which --keep-secrets leaves as it is", w.paths.secrets)
	}
	return nil
}
