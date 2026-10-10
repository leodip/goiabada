package main

import (
	"path/filepath"
	"slices"
)

func printBanner(out *console) {
	out.printf("%s================================================================================\n", out.cyan)
	out.printf("                         GOIABADA SETUP WIZARD v%s\n", version)
	out.printf("================================================================================%s\n", out.reset)
	out.println()
	out.println("This wizard will help you set up Goiabada by generating configuration files")
	out.println("with all credentials pre-configured.")
	out.println()
}

func printSummary(out *console, config *Config) {
	out.printf("%s%s================== Configuration Summary ==================%s\n", out.bold, out.cyan, out.reset)
	out.println()
	out.printf("  Deployment:       %s\n", config.Deployment.displayName)
	out.printf("  Database:         %s\n", config.Engine.name)
	out.printf("  Auth Server URL:  %s\n", config.AuthServerURL)
	out.printf("  Admin Console:    %s\n", config.AdminConsoleURL)
	if config.K8sNamespace != "" {
		out.printf("  K8s Namespace:    %s\n", config.K8sNamespace)
	}
	if config.Deployment.servedByEnvoyGateway {
		out.printf("  Traffic policy:   %s\n", config.GatewayTrafficPolicy)
		if config.NetworkPolicy {
			out.println("  NetworkPolicies:  admit only Envoy and the admin console")
		} else {
			out.println("  NetworkPolicies:  none")
		}
	}
	if config.Deployment.asksMetrics {
		out.printf("  Metrics:          %s\n", config.metricsAnswer())
		if config.admitsMetricsScraper() {
			out.printf("  Metrics scraper:  namespace %s\n", config.MetricsNamespace)
		}
	}
	if config.Deployment.asksLocalProxy {
		if config.LocalProxy {
			out.println("  Reverse proxy:    on this machine (listen on 127.0.0.1)")
		} else {
			out.println("  Reverse proxy:    none (HTTPS served by Goiabada)")
		}
	}
	if config.Deployment.asksRateLimiter {
		if config.RateLimiter {
			out.println("  Rate limiter:     on")
		} else {
			out.println("  Rate limiter:     off")
		}
	}
	out.printf("  Admin Email:      %s\n", config.AdminEmail)
	out.printf("  Admin Password:   %s\n", passwordOrigin(config.AdminPasswordGenerated))
	if config.DBHost != "" {
		out.printf("  DB Host:          %s:%s\n", config.DBHost, config.DBPort)
		out.printf("  DB Name:          %s\n", config.DBName)
		out.printf("  DB Username:      %s\n", config.DBUsername)
	}
	if config.DBPassword != "" {
		out.printf("  DB Password:      %s\n", passwordOrigin(config.DBPasswordGenerated))
	}
	out.println()
	out.printf("%s%s==========================================================%s\n", out.bold, out.cyan, out.reset)
}

func printCompletionMessage(out *console, config *Config, paths outputPaths) {
	out.println()
	out.printf("%s%s================================================================================\n", out.bold, out.green)
	out.printf("                            SETUP COMPLETE!\n")
	out.printf("================================================================================%s\n", out.reset)
	out.println()

	config.Deployment.printInstructions(out, config, paths)

	out.println()
	out.println("URLs:")
	out.printf("    Auth Server:   %s%s%s\n", out.cyan, config.AuthServerURL, out.reset)
	out.printf("    Admin Console: %s%s%s\n", out.cyan, config.AdminConsoleURL, out.reset)
	out.println()
	printWhereTheAdminPasswordIs(out, config, paths)
	out.println()
	printSecretsAdvice(out, paths)
}

// gatewayDocsURL is the page the Kubernetes completion message follows step by step.
const gatewayDocsURL = "https://goiabada.dev/deploy/kubernetes/gateway-and-certificates/"

// printKubernetesInstructions prints the steps in the order an operator takes them, the order of the
// page at gatewayDocsURL: what the cluster needs, the deploy, DNS, and only then the ClusterIssuer,
// so cert-manager looks no host name up before its record exists (#542).
func printKubernetesInstructions(out *console, config *Config, paths outputPaths) {
	out.println("To deploy Goiabada to Kubernetes, follow these steps in order. Each is explained at")
	out.printf("%s.\n", gatewayDocsURL)
	out.println()
	// A release build stamps its version as the tag; only a source build reaches here with latest
	// (#396 decision 10).
	if imageTag == "latest" {
		out.warning("The manifest follows the moving image tag \"latest\", so pods can run different releases")
		out.println("   and each start pulls whatever release it names then. Replace latest with a release")
		out.println("   version in both image lines to pin them.")
		out.println()
	}

	out.printf("%s%sSTEPS%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("Skip step 1, 2 or 3 for what your cluster already runs.")
	out.println()
	out.println("  1. Install Envoy Gateway, which brings the Gateway API CRDs, and wait for it:")
	out.printf("     %skubectl apply --server-side -f https://github.com/envoyproxy/gateway/releases/download/v1.9.1/install.yaml%s\n", out.cyan, out.reset)
	out.printf("     %skubectl wait --timeout=5m -n envoy-gateway-system deployment/envoy-gateway --for=condition=Available%s\n", out.cyan, out.reset)
	out.println("     (Check https://github.com/envoyproxy/gateway/releases for a newer version)")
	out.println()
	printEnvoyProxyPrerequisite(out, config.GatewayTrafficPolicy)
	out.println("     ---")
	out.println("     apiVersion: gateway.networking.k8s.io/v1")
	out.println("     kind: GatewayClass")
	out.println("     metadata:")
	out.println("       name: eg")
	out.println("     spec:")
	out.println("       controllerName: gateway.envoyproxy.io/gatewayclass-controller")
	out.println("       parametersRef:")
	out.println("         group: gateway.envoyproxy.io")
	out.println("         kind: EnvoyProxy")
	out.println("         name: goiabada-proxy")
	out.println("         namespace: envoy-gateway-system")
	out.println()
	out.printf("     %skubectl apply -f gatewayclass.yaml%s\n", out.cyan, out.reset)
	out.println()
	out.println("     The EnvoyProxy and the GatewayClass are cluster-wide: on a cluster that already runs")
	out.println("     Envoy Gateway, the traffic policy belongs to whoever runs it, so agree it with them")
	out.println("     rather than apply these over theirs.")
	out.println()
	out.println("  3. Install cert-manager, after Envoy Gateway since it looks for the Gateway API CRDs at")
	out.println("     startup, turn its Gateway API support on, and wait for it:")
	out.printf("     %skubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml%s\n", out.cyan, out.reset)
	out.printf("     %skubectl -n cert-manager patch deployment cert-manager --type=json -p='[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--enable-gateway-api\"}]'%s\n", out.cyan, out.reset)
	out.printf("     %skubectl -n cert-manager rollout status deployment/cert-manager --timeout=5m%s\n", out.cyan, out.reset)
	out.printf("     %skubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=5m%s\n", out.cyan, out.reset)
	out.printf("     %skubectl -n cert-manager rollout status deployment/cert-manager-cainjector --timeout=5m%s\n", out.cyan, out.reset)
	out.println()
	out.println("  4. Deploy Goiabada, the Secrets first, so no pod starts with an older copy of them:")
	out.printf("     %s%s%s\n", out.cyan, kubernetesApplyCommand(paths), out.reset)
	out.println()
	out.printf("     %sFor a deployment that already runs, apply only %s.%s %s holds\n", out.bold, filepath.Base(paths.description), out.reset, filepath.Base(paths.secrets))
	out.println("     newly generated secrets, which its database isn't under: a pod reads its Secrets")
	out.println("     only when it starts, so nothing changes until the next restart, and then the auth")
	out.println("     server and the admin console refuse to start.")
	out.println()
	out.println("  5. Point DNS at the Gateway. Read its address, which can take a minute to appear:")
	out.printf("     %skubectl get gateway goiabada -n %s -o jsonpath='{.status.addresses[0].value}'%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println("     Then create a record for each host name, an A record when the address is an IP")
	out.println("     address and a CNAME when it is a host name:")
	authHost, adminHost := hostOf(config.AuthServerURL), hostOf(config.AdminConsoleURL)
	width := max(len(authHost), len(adminHost))
	out.printf("     %s%-*s -> <the Gateway's address>%s\n", out.cyan, width, authHost, out.reset)
	out.printf("     %s%-*s -> <the Gateway's address>%s\n", out.cyan, width, adminHost, out.reset)
	out.println("     If your DNS provider can proxy traffic, leave both records unproxied (DNS only):")
	out.println("     Let's Encrypt has to reach the Gateway itself.")
	out.println()
	out.println("  6. Once both names resolve, create the ClusterIssuer the Gateway's annotation names,")
	out.println("     solving HTTP-01 through the Gateway (save as letsencrypt-issuer.yaml):")
	out.println("     ---")
	out.println("     apiVersion: cert-manager.io/v1")
	out.println("     kind: ClusterIssuer")
	out.println("     metadata:")
	out.println("       name: letsencrypt-prod")
	out.println("     spec:")
	out.println("       acme:")
	out.println("         server: https://acme-v02.api.letsencrypt.org/directory")
	out.println("         privateKeySecretRef:")
	out.println("           name: letsencrypt-prod")
	out.println("         solvers:")
	out.println("         - http01:")
	out.println("             gatewayHTTPRoute:")
	out.println("               parentRefs:")
	out.println("               - name: goiabada")
	out.printf("                 namespace: %s\n", config.K8sNamespace)
	out.println("                 kind: Gateway")
	out.println()
	out.printf("     %skubectl apply -f letsencrypt-issuer.yaml%s\n", out.cyan, out.reset)
	out.println()
	out.println("     Created any earlier, it has cert-manager look the names up before they exist, and a")
	out.println("     resolver can then remember them as missing for as long as your zone says, often 30")
	out.println("     minutes or more. Without it, cert-manager waits. Remove the Gateway's cert-manager")
	out.println("     annotation instead to manage the certificates yourself.")
	out.println()
	out.println("  7. Check it is up: both pods Running, then both certificates READY within a few minutes.")
	out.printf("     %skubectl get pods -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.printf("     %skubectl get certificates -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()

	out.printf("%s%sIMPORTANT NOTES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • The database must be empty for a fresh deployment. Goiabada will")
	out.println("    automatically seed the database with initial data including the")
	out.println("    admin user and OAuth clients configured with the URLs above.")
	out.println("    If redeploying with different URLs, use a fresh database.")
	out.println()
	out.println("  • If using a managed database service (Supabase, PlanetScale, etc.),")
	out.println("    use the connection pooler endpoint for better compatibility (IPv4).")
	out.println()
	printMetricsNotes(out, config)

	out.printf("%s%sTROUBLESHOOTING TIPS%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • If cert-manager HTTP-01 challenges fail or timeout:")
	out.println("    - Verify DNS records point to the Gateway's address")
	out.println("    - Ensure port 80 is accessible from the internet")
	out.println("    - A challenge whose reason ends in \"no such host\" once the records exist was looked")
	out.println("      up before them, and the cluster's resolver remembers the name as missing; it clears")
	out.println("      by itself within your zone's negative-caching time, often 30 minutes")
	if config.GatewayTrafficPolicy == trafficPolicyLocal {
		out.println("    - Under Local, a node with no Envoy pod drops the load balancer's traffic: check")
		out.println("      the EnvoyProxy in step 2 is applied and runs an Envoy pod on every node:")
		out.printf("      %skubectl get daemonset -n envoy-gateway-system%s\n", out.cyan, out.reset)
		out.println("    - If your load balancer still cannot reach Envoy, use the Cluster policy instead:")
		out.println("      the EnvoyProxy the wizard prints with --gateway-traffic-policy=cluster, which has")
		out.println("      no envoyDaemonSet. Goiabada then sees a node's address for every client.")
	} else {
		out.println("    - If the GatewayClass has no EnvoyProxy with externalTrafficPolicy: Cluster,")
		out.println("      apply the one in step 2 above")
	}
	out.println()
	if config.GatewayTrafficPolicy == trafficPolicyLocal {
		out.println("  • Under Local, check that Goiabada sees your own address: request any page, then read the")
		out.println("    ip= of that request in the auth server's log. The same address for every client is the")
		out.println("    load balancer's, which proxies connections, and the per-IP limits then count every")
		out.println("    client together.")
		out.printf("      %skubectl logs -n %s deployment/goiabada-authserver | grep 'http request' | tail -3%s\n", out.cyan, config.K8sNamespace, out.reset)
		out.println()
	}
	if config.NetworkPolicy {
		out.println("  • A connection a NetworkPolicy blocks either times out or is refused at once, depending on")
		out.println("    the network plugin. If a workload cannot reach a server, check what the policies admit:")
		out.printf("      %skubectl describe networkpolicy -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
		out.println()
	}
	out.println("  • Check Gateway and route status:")
	out.printf("      %skubectl get gateway,httproute -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.printf("      %skubectl describe gateway goiabada -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	out.println("  • Check certificates:")
	out.printf("      %skubectl get certificates -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	out.println("  • Verify pods are running:")
	out.printf("      %skubectl get pods -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	out.println("  • Check pod logs for errors:")
	out.printf("      %skubectl logs -n %s deployment/goiabada-authserver%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
}

// printMetricsNotes says what the metrics answer was and what it needs: with metrics off, that they
// are off and how to turn them on; with them on, where they are served and what the answer needs to
// be scraped: pod annotations only a scraper that reads them, a PodMonitor the Operator's CRDs and a
// Prometheus whose selector matches it; and, with the NetworkPolicies on, the namespace they admit
// (#400 decisions 7 and 8).
func printMetricsNotes(out *console, config *Config) {
	if !config.exposesMetrics() {
		out.println("  • Prometheus metrics are off: neither server starts its metrics listener. To expose them,")
		out.println("    generate the manifest again with --metrics=annotations or --metrics=podmonitor.")
		out.printf("    The metrics and what to alert on: %s\n", monitoringDocsURL)
		out.println()
		return
	}
	out.printf("  • Both servers serve Prometheus metrics on a container port named metrics, %d on the\n", authServerMetricsPort)
	out.printf("    auth server and %d on the admin console, which no Service or route publishes.\n", adminConsoleMetricsPort)
	if config.Metrics == metricsAnnotations {
		out.println("    The pods carry the prometheus.io/scrape, port and path annotations, which the")
		out.println("    prometheus-community prometheus chart reads by default. kube-prometheus-stack ignores")
		out.println("    them: on a cluster that runs it, generate the manifest again with --metrics=podmonitor.")
	} else {
		out.println("    The PodMonitor goiabada has the Prometheus Operator scrape them. It is one of the")
		out.println("    Operator's CRDs: on a cluster without them, kubectl apply exits 1 after applying")
		out.println("    everything else. A Prometheus the Operator runs selects only the PodMonitors its")
		out.println("    podMonitorSelector matches; read it with:")
		out.printf("      %skubectl get prometheus -A -o jsonpath='{..podMonitorSelector}'%s\n", out.cyan, out.reset)
	}
	out.printf("    The metrics and what to alert on: %s\n", monitoringDocsURL)
	out.println()
	if config.admitsMetricsScraper() {
		out.printf("  • The NetworkPolicies admit the namespace %s to the metrics ports alone. A scraper\n", config.MetricsNamespace)
		out.println("    running elsewhere cannot connect until its namespace is admitted, as the policies' comments show.")
		out.println()
	}
}

// printEnvoyProxyPrerequisite prints the opening of the completion message's second prerequisite,
// the EnvoyProxy setting the traffic policy chosen, down to the GatewayClass that follows it: under
// Cluster, Envoy stays a Deployment; under Local it runs on every node as a DaemonSet, so no node
// the load balancer sends to drops the traffic (#396 decision 4). envoyDaemonSet, envoyService and
// externalTrafficPolicy are Envoy Gateway v1.9.1's (api/v1alpha1), which admits one of
// envoyDeployment and envoyDaemonSet, and reads an empty envoyDaemonSet as every default.
func printEnvoyProxyPrerequisite(out *console, policy trafficPolicy) {
	if policy == trafficPolicyLocal {
		out.println("  2. The GatewayClass the manifest names, with externalTrafficPolicy: Local and Envoy")
		out.println("     on every node as a DaemonSet, so no node drops the load balancer's traffic and,")
		out.println("     behind a load balancer that passes connections through, Goiabada sees each client's")
		out.println("     address (save as gatewayclass.yaml):")
	} else {
		out.println("  2. The GatewayClass the manifest names, with externalTrafficPolicy: Cluster")
		out.println("     for better compatibility (save as gatewayclass.yaml):")
	}
	out.println("     ---")
	out.println("     apiVersion: gateway.envoyproxy.io/v1alpha1")
	out.println("     kind: EnvoyProxy")
	out.println("     metadata:")
	out.println("       name: goiabada-proxy")
	out.printf("       namespace: %s\n", envoyProxyNamespace)
	out.println("     spec:")
	out.println("       provider:")
	out.println("         type: Kubernetes")
	out.println("         kubernetes:")
	if policy == trafficPolicyLocal {
		out.println("           envoyDaemonSet: {}")
	}
	out.println("           envoyService:")
	out.printf("             externalTrafficPolicy: %s\n", policy)
}

// nativeReleaseArchive is the archive a release publishes for one platform, as build-binaries.sh
// names it, with the parts that vary in angle brackets.
const nativeReleaseArchive = "goiabada-<version>-<os>-<arch>.zip"

func printNativeInstructions(out *console, config *Config, paths outputPaths) {
	out.println("To run Goiabada with native binaries:")
	out.println()
	out.printf("%s%s1. DOWNLOAD BINARIES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  Download the pre-built binaries for your platform from:")
	out.printf("  %shttps://github.com/leodip/goiabada/releases%s\n", out.cyan, out.reset)
	out.println()
	out.println("  Extract the binaries:")
	out.printf("  %sunzip %s%s\n", out.cyan, nativeReleaseArchive, out.reset)
	out.println()
	out.printf("%s%s2. START THE SERVERS%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  Load the environment and start both servers (in separate terminals):")
	out.println()
	out.println("  Auth server:")
	out.printf("  %s%s%s\n", out.cyan, nativeStartCommand(paths, "goiabada-authserver"), out.reset)
	out.println()
	out.println("  Admin console:")
	out.printf("  %s%s%s\n", out.cyan, nativeStartCommand(paths, "goiabada-adminconsole"), out.reset)
	out.println()
	out.printf("%s%sIMPORTANT NOTES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • The environment file contains sensitive secrets. Keep it secure!")
	out.println()
	if config.LocalProxy {
		out.println("  • Both servers listen on 127.0.0.1 alone. Point your reverse proxy at")
		out.println("    http://127.0.0.1:9090 (auth server) and http://127.0.0.1:9091 (admin console),")
		out.println("    and have it set X-Forwarded-For and X-Forwarded-Proto.")
	} else {
		out.println("  • Both servers listen on every interface and serve plain HTTP until you set")
		out.printf("    their CERTFILE and KEYFILE in %s, as its comments say.\n", filepath.Base(paths.description))
	}
	out.println()
	out.println("  • The database must be empty for a fresh deployment. Goiabada will")
	out.println("    automatically seed the database with initial data including the")
	out.println("    admin user and OAuth clients configured with the URLs above.")
	out.println()
	out.println("  • For production, consider using a process manager like systemd")
	out.println("    to keep the services running and restart them on failure.")
	out.println()
}

func printComposeInstructions(out *console, _ *Config, paths outputPaths) {
	out.println("To start Goiabada, run:")
	out.println()
	out.printf("    %s%s%s\n", out.cyan, composeUpCommand(paths), out.reset)
	out.println()
	out.println("Then access:")
}

// composeDefaultFiles are the names docker compose looks for when given no -f, each of which takes
// the override of the same name with .override before its extension without being asked.
var composeDefaultFiles = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// composeFindsByItself says whether docker compose, given no -f, finds the Compose file and its
// override by itself: the Compose file has a name it looks for, and the override the name it takes
// with it.
func composeFindsByItself(paths outputPaths) bool {
	return slices.Contains(composeDefaultFiles, filepath.Base(paths.description))
}

// composeUpCommand starts the Compose file with its override merged in: with no -f under a name
// docker compose looks for by itself, and with both files named, the Compose file first, under any
// other, each one shell word whatever its name.
func composeUpCommand(paths outputPaths) string {
	if composeFindsByItself(paths) {
		return "docker compose up -d"
	}
	return "docker compose -f " + shellQuote(filepath.Base(paths.description)) + " -f " + shellQuote(filepath.Base(paths.secrets)) + " up -d"
}

// nativeStartCommand loads the env file into the environment and starts one of the two binaries
// with it, the file one shell word whatever its name.
func nativeStartCommand(paths outputPaths, binary string) string {
	return "set -a && . " + shellQuote("./"+filepath.Base(paths.description)) + " && set +a && ./" + binary
}

// systemdEnvironmentFileHint is the env file's header line on loading it from a unit, naming the
// file as systemd reads it rather than as a shell does (systemdPath).
func systemdEnvironmentFileHint(paths outputPaths) string {
	name, ok := systemdPath(filepath.Base(paths.description))
	if !ok {
		return "Or with systemd, add an EnvironmentFile= naming this file, renamed first: a unit file cannot name one ending in a space"
	}
	return "Or with systemd, add EnvironmentFile=/path/to/" + name
}

// printSecretsAdvice names the one file holding the secrets and says to keep it out of version
// control, and, when it is written inside a git working tree, warns and gives the line that keeps it
// out. It writes no .gitignore: that file is the operator's, and its rules may live elsewhere (#396
// decision 15).
func printSecretsAdvice(out *console, paths outputPaths) {
	secrets := filepath.Base(paths.secrets)
	out.printf("Keep %s%s%s out of version control: it holds every secret, the AES key among them.\n", out.bold, secrets, out.reset)
	if paths.separate() {
		out.printf("%s holds none, and can be committed.\n", filepath.Base(paths.description))
	}
	out.println()
	root, inTree := gitWorkingTree(filepath.Dir(paths.secrets))
	if !inTree {
		return
	}
	out.warning("%s is inside the git working tree at %s.", filepath.Dir(paths.secrets), root)
	out.printf("   Add this line to %s before you commit, so %s never is:\n", filepath.Join(root, ".gitignore"), secrets)
	out.printf("    %s%s%s\n", out.cyan, gitignorePattern(root, paths.secrets), out.reset)
	out.println()
}

// passwordOrigin is all the summary says of a password: whether it was generated or set. It showed
// the first and last two characters of the admin password (#396 decision 17).
func passwordOrigin(generated bool) string {
	if generated {
		return "(generated)"
	}
	return "(set)"
}

// printWhereTheAdminPasswordIs says whom to sign in as and where the admin password is, never what
// it is: a generated one printed here would be in the log of every CI job that runs the wizard
// (#396 decision 17). For Kubernetes it is the command that reads it back out of the cluster, since
// the secrets file may be gone by the time anyone signs in.
func printWhereTheAdminPasswordIs(out *console, config *Config, paths outputPaths) {
	if config.Deployment.kind == deploymentKubernetes {
		out.printf("Sign in as %s%s%s with the admin password, which this reads back out of the cluster:\n", out.bold, config.AdminEmail, out.reset)
		out.printf("    %s%s%s\n", out.cyan, kubernetesSecretReadCommand(goiabadaSecrets, "admin-password", config.K8sNamespace), out.reset)
		return
	}
	out.printf("Sign in as %s%s%s with the admin password, GOIABADA_ADMIN_PASSWORD in %s.\n", out.bold, config.AdminEmail, out.reset, filepath.Base(paths.secrets))
}
