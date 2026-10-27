package main

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
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
		existing := ""
		if config.NamespaceExists {
			existing = " (already exists)"
		}
		out.printf("  K8s Namespace:    %s%s\n", config.K8sNamespace, existing)
	}
	if config.Deployment.asksRouting {
		out.printf("  Routing:          %s\n", config.routingAnswer())
		if config.asksTLS() {
			out.printf("  TLS certificates: %s\n", config.tlsAnswer())
		}
		if config.Routing == routingGateway {
			if config.endsTLS() {
				out.printf("  Listeners:        HTTP on %d, HTTPS on %d\n", config.GatewayHTTPPort, config.GatewayHTTPSPort)
			} else {
				out.printf("  Listeners:        HTTP on %d\n", config.GatewayHTTPPort)
			}
		}
		if config.servedByEnvoyGateway() {
			out.printf("  Traffic policy:   %s\n", config.GatewayTrafficPolicy)
		}
		if config.NetworkPolicy {
			out.printf("  NetworkPolicies:  admit only the namespace %s and the admin console\n", config.ProxyNamespace)
			if len(config.MeshPorts) > 0 {
				out.printf("  Mesh ports:       %s\n", joinPorts(config.MeshPorts))
			}
		} else {
			out.println("  NetworkPolicies:  none")
		}
	}
	if config.Deployment.kind == deploymentKubernetes {
		out.printf("  Replicas:         auth server %d, admin console 1\n", config.AuthServerReplicas)
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
	if config.Deployment.asksImages {
		out.printf("  Images:           %s\n", config.imageAnswer())
		if config.ImagePullSecret != "" {
			out.printf("  Pull secret:      %s\n", config.ImagePullSecret)
		}
	}
	if len(config.Labels) > 0 {
		out.printf("  Labels:           %s\n", joinPairs(config.Labels))
	}
	if len(config.Annotations) > 0 {
		out.printf("  Annotations:      %s\n", joinPairs(config.Annotations))
	}
	out.printf("  Admin Email:      %s\n", config.AdminEmail)
	if config.KeepSecrets {
		out.println("  Secrets:          left as they are, none generated")
	} else {
		out.printf("  Admin Password:   %s\n", passwordOrigin(config.AdminPasswordGenerated))
	}
	if config.DBHost != "" {
		out.printf("  DB Host:          %s:%s\n", config.DBHost, config.DBPort)
		out.printf("  DB Name:          %s\n", config.DBName)
		out.printf("  DB Username:      %s\n", config.DBUsername)
	}
	if config.DBPassword != "" {
		out.printf("  DB Password:      %s\n", passwordOrigin(config.DBPasswordGenerated))
	}
	if config.DBTLSMode != "" {
		out.printf("  DB TLS mode:      %s\n", config.DBTLSMode)
	}
	if checksCertificate(config.DBTLSMode) {
		if config.DBTLSCAFile != "" {
			out.printf("  DB CA file:       %s\n", config.DBTLSCAFile)
		} else {
			out.println("  DB CA file:       none, the system's roots")
		}
	}
	if config.DBTLSClientCertFile != "" {
		out.printf("  DB client cert:   %s\n", config.DBTLSClientCertFile)
		out.printf("  DB client key:    %s\n", config.DBTLSClientKeyFile)
	} else if config.DBTLSClientCertKept {
		out.printf("  DB client cert:   the one in the %s Secret\n", dbClientTLSSecret)
	}
	if config.DBTLSServerName != "" {
		out.printf("  DB TLS host name: %s\n", config.DBTLSServerName)
	}
	out.println()
	out.printf("%s%s==========================================================%s\n", out.bold, out.cyan, out.reset)
}

func printCompletionMessage(out *console, config *Config, paths outputPaths) {
	if config.KeepSecrets {
		printRegeneratedMessage(out, config, paths)
		return
	}
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

// printRegeneratedMessage is the completion message of a run under --keep-secrets, which wrote the
// description and the answers file over a deployment's own: review them, and apply the description
// alone, since the secrets file is as it was (#686 section 4).
func printRegeneratedMessage(out *console, config *Config, paths outputPaths) {
	description, answers := filepath.Base(paths.description), filepath.Base(paths.answers)
	out.println()
	out.printf("%s%s================================================================================\n", out.bold, out.green)
	out.printf("                          CONFIGURATION REGENERATED\n")
	out.printf("================================================================================%s\n", out.reset)
	out.println()
	out.printf("%s and %s are written.\n", description, answers)
	out.printf("%s is not: the deployment keeps the secrets it has.\n", filepath.Base(paths.secrets))
	out.println()
	kubernetes := config.Deployment.kind == deploymentKubernetes
	if kubernetes && imageTag == "latest" {
		out.warning("The manifest follows the moving image tag \"latest\", so pods can run different releases")
		out.println("   and each start pulls whatever release it names then. Replace latest with a release")
		out.println("   version in both image lines to pin them.")
		out.println()
	}
	out.println("From the directory holding the files:")
	out.println()
	out.println("  1. Review what changed before you apply it:")
	if _, inTree := gitWorkingTree(filepath.Dir(paths.description)); inTree {
		out.printf("       %sgit diff -- %s %s%s\n", out.cyan, shellQuote(description), shellQuote(answers), out.reset)
	} else {
		out.println("     compare both files with the copies the deployment runs from.")
	}
	out.println()
	if !kubernetes {
		out.println("  2. Apply it. docker compose recreates the containers whose configuration changed:")
		out.printf("       %s%s%s\n", out.cyan, composeUpCommand(paths), out.reset)
		return
	}
	step := 2
	if config.ImagePullSecret != "" {
		// No secrets file holds it, so a run that adds it to the pods adds a Secret nothing has
		// created yet, which the new pods cannot pull without (#686 section 5).
		out.printf("  %d. Check the image pull secret %s exists in %s, with your credentials for\n", step, config.ImagePullSecret, config.K8sNamespace)
		out.printf("     %s: until it does, the new pods wait in ImagePullBackOff, and the old ones keep\n", config.imageRegistry())
		out.println("     serving. If it is missing, create it. For instance:")
		out.printf("       %skubectl get secret %s -n %s%s\n", out.cyan, config.ImagePullSecret, config.K8sNamespace, out.reset)
		printCreatePullSecret(out, config, "       ")
		out.println()
		step++
	}
	out.printf("  %d. ", step)
	printConnectionSum(out, config, "     ")
	out.println()
	step++
	out.printf("  %d. Apply the manifest alone: the Secrets need no applying again.\n", step)
	out.printf("       %skubectl apply -f %s%s\n", out.cyan, shellQuote(description), out.reset)
	out.println("     With a kustomization over it, such as the Internal TLS guide's, apply that instead:")
	out.printf("       %skubectl apply -k .%s\n", out.cyan, out.reset)
	out.println()
	out.printf("  %d. Wait for both servers to roll out:\n", step+1)
	out.printf("       %skubectl rollout status deployment/goiabada-authserver deployment/goiabada-adminconsole -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
}

// gatewayDocsURL is the page the Kubernetes completion message follows step by step for the Envoy
// Gateway recipe, and routingDocsURL the one it follows for every other routing mode.
const (
	gatewayDocsURL = "https://goiabada.dev/deploy/kubernetes/gateway-and-certificates/"
	routingDocsURL = "https://goiabada.dev/deploy/kubernetes/routing/"
)

// printKubernetesInstructions prints the steps of the routing mode answered: the Envoy Gateway
// recipe's, which install what the cluster needs, or those of a mode that attaches to what it
// already has (#686 section 3).
func printKubernetesInstructions(out *console, config *Config, paths outputPaths) {
	docsURL := routingDocsURL
	if config.servedByEnvoyGateway() {
		docsURL = gatewayDocsURL
	}
	out.println("To deploy Goiabada to Kubernetes, follow these steps in order. Each is explained at")
	out.printf("%s.\n", docsURL)
	out.println()
	// A release build stamps its version as the tag; only a source build reaches here with latest
	// (#396 decision 10).
	if imageTag == "latest" {
		out.warning("The manifest follows the moving image tag \"latest\", so pods can run different releases")
		out.println("   and each start pulls whatever release it names then. Replace latest with a release")
		out.println("   version in both image lines to pin them.")
		out.println()
	}
	if config.servedByEnvoyGateway() {
		printEnvoyGatewayInstructions(out, config, paths)
	} else {
		printRoutingInstructions(out, config, paths)
	}
}

// printEnvoyGatewayInstructions prints the recipe's steps in the order an operator takes them, the
// order of the page at gatewayDocsURL: what the cluster needs, the deploy, DNS, and only then the
// ClusterIssuer, so cert-manager looks no host name up before its record exists (#542).
func printEnvoyGatewayInstructions(out *console, config *Config, paths outputPaths) {
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
	printDeployStep(out, config, paths, 4)
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

	printImportantNotes(out, config)

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
	printNetworkPolicyTip(out, config)
	out.println("  • Check Gateway and route status:")
	out.printf("      %skubectl get gateway,httproute -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.printf("      %skubectl describe gateway goiabada -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	out.println("  • Check certificates:")
	out.printf("      %skubectl get certificates -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	out.println()
	printPodTips(out, config)
}

// printRoutingInstructions prints the steps of a routing mode that attaches to what the cluster
// already has, in the order an operator takes them: check what the manifest names, deploy, point DNS
// at the address that serves the hosts, and check it, plain HTTP's redirect included wherever the
// manifest writes none (#686 section 3).
func printRoutingInstructions(out *console, config *Config, paths outputPaths) {
	ns := config.K8sNamespace
	out.printf("%s%sSTEPS%s\n", out.bold, out.yellow, out.reset)
	out.println()
	printRoutingPrerequisites(out, config)
	printDeployStep(out, config, paths, 2)

	authHost, adminHost := hostOf(config.AuthServerURL), hostOf(config.AdminConsoleURL)
	var target string
	switch {
	case config.Routing == routingNone:
		out.println("  3. Point DNS at what you route the Services with:")
		target = "<its address>"
	case !config.endsTLS() && config.Routing != routingExistingGateway:
		out.println("  3. Point DNS at the load balancer or CDN in front, which ends TLS, and point it at")
		out.println("     the routing layer's address, which can take a minute to appear:")
		target = "<the address in front>"
	case config.Routing == routingIngress:
		out.println("  3. Point DNS at the Ingress controller. Read its address, which can take a minute to")
		out.println("     appear:")
		target = "<the Ingress's address>"
	default:
		out.println("  3. Point DNS at the Gateway. Read its address, which can take a minute to appear:")
		target = "<the Gateway's address>"
	}
	switch {
	case config.ownsGateway():
		out.printf("     %skubectl get gateway goiabada -n %s -o jsonpath='{.status.addresses[0].value}'%s\n", out.cyan, ns, out.reset)
	case config.Routing == routingExistingGateway:
		out.printf("     %skubectl get gateway %s -n %s -o jsonpath='{.status.addresses[0].value}'%s\n", out.cyan, config.GatewayName, config.GatewayNamespace, out.reset)
	case config.Routing == routingIngress:
		out.printf("     %skubectl get ingress goiabada-authserver -n %s -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}'%s\n", out.cyan, ns, out.reset)
	}
	then := "Then create"
	if config.Routing == routingNone {
		then = "Create"
	}
	out.printf("     %s a record for each host name, an A record when the address is an IP\n", then)
	out.println("     address and a CNAME when it is a host name:")
	width := max(len(authHost), len(adminHost))
	out.printf("     %s%-*s -> %s%s\n", out.cyan, width, authHost, target, out.reset)
	out.printf("     %s%-*s -> %s%s\n", out.cyan, width, adminHost, target, out.reset)
	out.println()

	out.println("  4. Check it is up: both pods Running, then the route in.")
	out.printf("     %skubectl get pods -n %s%s\n", out.cyan, ns, out.reset)
	switch {
	case config.routesThroughGateway():
		out.printf("     %skubectl describe httproute -n %s%s\n", out.cyan, ns, out.reset)
		out.println("     Each route's parent condition Accepted is True once the Gateway admits it.")
	case config.Routing == routingIngress:
		out.printf("     %skubectl get ingress -n %s%s\n", out.cyan, ns, out.reset)
	}
	if config.issuesWithCertManager() {
		out.printf("     %skubectl get certificates -n %s%s\n", out.cyan, ns, out.reset)
		out.println("     Both certificates READY True, within a few minutes.")
	}
	if !config.writesRedirect() {
		out.printf("     Then check that %s redirects plain HTTP to HTTPS, which the\n", config.redirector())
		out.println("     manifest leaves to it: the answer should be a redirect, such as a 301, 302 or 308,")
		out.println("     whose location starts with https://, never a 200.")
		out.printf("     %scurl -sI http://%s/ | grep -i -E '^(HTTP|location)'%s\n", out.cyan, authHost, out.reset)
	}
	out.println()

	printImportantNotes(out, config)

	out.printf("%s%sTROUBLESHOOTING TIPS%s\n", out.bold, out.yellow, out.reset)
	out.println()
	printNetworkPolicyTip(out, config)
	if config.Routing == routingExistingGateway {
		out.println("  • A route whose Accepted condition is False with the reason NotAllowedByListeners is")
		out.printf("    refused by the Gateway's allowedRoutes: its owner must admit the namespace %s.\n", ns)
		out.println("    NoMatchingParent names a listener the Gateway has not got.")
		out.println()
	}
	if config.issuesWithCertManager() {
		out.println("  • A certificate that stays not READY: read why, and check the issuer is READY:")
		out.printf("      %skubectl describe certificate -n %s%s\n", out.cyan, ns, out.reset)
		out.println()
	}
	printPodTips(out, config)
}

// printRoutingPrerequisites prints the first step of a mode that attaches to what the cluster has:
// what the manifest names, and what must already exist or be set up for it.
func printRoutingPrerequisites(out *console, config *Config) {
	ns := config.K8sNamespace
	switch config.Routing {
	case routingGateway:
		out.printf("  1. The cluster must have the GatewayClass %s, ACCEPTED True:\n", config.GatewayClass)
		out.printf("     %skubectl get gatewayclass %s%s\n", out.cyan, config.GatewayClass, out.reset)
	case routingExistingGateway:
		out.printf("  1. The Gateway %s in %s must admit routes from the namespace %s on its\n", config.GatewayName, config.GatewayNamespace, ns)
		out.printf("     %s (allowedRoutes), serve HTTPS there with a certificate for each host,\n", config.listenersAnswer())
		out.println("     and redirect plain HTTP to HTTPS. Agree it with whoever runs it:")
		out.printf("     %skubectl get gateway %s -n %s -o yaml%s\n", out.cyan, config.GatewayName, config.GatewayNamespace, out.reset)
	case routingIngress:
		if config.IngressClass == "" {
			out.println("  1. The cluster must have an Ingress controller of its default IngressClass:")
		} else {
			out.printf("  1. The cluster must have an Ingress controller of the IngressClass %s:\n", config.IngressClass)
		}
		out.printf("     %skubectl get ingressclass%s\n", out.cyan, out.reset)
		if config.endsTLS() {
			out.println("     It must redirect plain HTTP to HTTPS, which no Ingress field asks for: Traefik, for")
			out.println("     one, serves an Ingress over plain HTTP too until its web entry point redirects.")
		}
	case routingNone:
		out.println("  1. Route both hosts over HTTPS to the Services, and redirect plain HTTP to HTTPS:")
		authHost, adminHost := hostOf(config.AuthServerURL), hostOf(config.AdminConsoleURL)
		width := max(len(authHost), len(adminHost))
		out.printf("     %s%-*s -> goiabada-authserver, port 9090%s\n", out.cyan, width, authHost, out.reset)
		out.printf("     %s%-*s -> goiabada-adminconsole, port 9091%s\n", out.cyan, width, adminHost, out.reset)
		out.println("     The ConfigMaps' comments say what the servers trust of the X-Forwarded-For header.")
	}
	switch {
	case !config.asksTLS():
	case config.TLS == tlsClusterIssuer:
		out.printf("     cert-manager issues the certificates from the ClusterIssuer %s, READY True:\n", config.TLSIssuer)
		out.printf("     %skubectl get clusterissuer %s%s\n", out.cyan, config.TLSIssuer, out.reset)
	case config.TLS == tlsIssuer:
		out.printf("     cert-manager issues the certificates from the Issuer %s in %s, READY True:\n", config.TLSIssuer, ns)
		out.printf("     %skubectl get issuer %s -n %s%s\n", out.cyan, config.TLSIssuer, ns, out.reset)
	case config.TLS == tlsSecrets && !config.NamespaceExists:
		out.printf("     The TLS Secrets %s and %s hold the certificates:\n", config.TLSSecretAuth, config.TLSSecretAdmin)
		out.printf("     create them in %s once step 2 has created it, and renew them.\n", ns)
	case config.TLS == tlsSecrets:
		out.printf("     The TLS Secrets %s and %s in %s hold the certificates, which you create\n", config.TLSSecretAuth, config.TLSSecretAdmin, ns)
		out.println("     and renew, for instance:")
		printCreateTLSSecret(out, config)
	default:
		out.println("     TLS ends in front, at a load balancer or a CDN that forwards plain HTTP to the routing")
		out.println("     layer and redirects plain HTTP to HTTPS itself. The routing layer must not redirect:")
		out.println("     every request reaches it as plain HTTP, and would be sent back to HTTPS in a loop.")
		out.println("     Let nothing else reach the routing layer.")
	}
	if config.Routing == routingGateway && config.issuesWithCertManager() {
		out.println("     cert-manager reads a Gateway's annotation only with its Gateway API support on: see")
		out.printf("     %s.\n", gatewayDocsURL)
	}
	out.println()
}

// printCreateTLSSecret prints the command creating the auth server's TLS Secret, for the operator to
// repeat for the admin console's: the auth server's alone, unless one Secret serves both hosts.
func printCreateTLSSecret(out *console, config *Config) {
	component := authServerComponent
	if config.TLSSecretAuth == config.TLSSecretAdmin {
		component = ""
	}
	printCreateSecret(out, config, "     ", component,
		fmt.Sprintf("kubectl create secret tls %s -n %s --cert=auth.crt --key=auth.key", config.TLSSecretAuth, config.K8sNamespace))
}

// printCreatePullSecret prints, at indent, the command that creates the image pull secret, which
// both servers' pods name, keyed by the registry the repository names.
func printCreatePullSecret(out *console, config *Config, indent string) {
	printCreateSecret(out, config, indent, "", fmt.Sprintf("kubectl create secret docker-registry %s -n %s --docker-server=%s --docker-username=<user> --docker-password=<password>",
		config.ImagePullSecret, config.K8sNamespace, config.imageRegistry()))
}

// printCreateSecret prints, at indent, create, a kubectl create secret command, as one carrying the
// labels every other object does, the standard ones of component and the operator's, and the
// operator's annotations. An admission policy checks a Secret as it is created, and kubectl create
// secret sets neither, so the Secret is written locally, labeled and annotated there, and only then
// created: kubectl apply would copy it, credentials included, into its last-applied-configuration
// annotation (#686 section 6).
func printCreateSecret(out *console, config *Config, indent, component, create string) {
	out.printf("%s%s%s --dry-run=client -o yaml |%s\n", indent, out.cyan, create, out.reset)
	for _, step := range []struct {
		command string
		pairs   []keyValue
	}{{"label", slices.Concat(config.standardLabels(component), config.Labels)}, {"annotate", config.Annotations}} {
		if len(step.pairs) == 0 {
			continue
		}
		words := []string{"kubectl", step.command, "--local", "-f", "-"}
		for _, pair := range step.pairs {
			words = append(words, shellQuote(pair.key+"="+pair.value))
		}
		out.printf("%s  %s%s -o yaml |%s\n", indent, out.cyan, strings.Join(words, " "), out.reset)
	}
	out.printf("%s  %skubectl create -f -%s\n", indent, out.cyan, out.reset)
}

// printDeployStep prints the deploy, step number of the steps: both files, the Secrets first, and
// only the manifest over a deployment that already runs, whose Secrets a new run's would replace
// (#542). TLS Secrets the operator supplies follow it when the files create the namespace, which a
// namespaced Secret needs first: until they exist, a Gateway's HTTPS listeners are refused as
// InvalidCertificateRef, and an Ingress controller serves a certificate of its own (#686 section 3).
// So does the image pull secret, until which the pods wait in ImagePullBackOff (#686 section 5).
func printDeployStep(out *console, config *Config, paths outputPaths, number int) {
	out.printf("  %d. Deploy Goiabada, the Secrets first, so no pod starts with an older copy of them:\n", number)
	out.printf("     %s%s%s\n", out.cyan, kubernetesApplyCommand(paths), out.reset)
	out.println()
	if config.asksTLS() && config.TLS == tlsSecrets && !config.NamespaceExists {
		out.printf("     Then create the TLS Secrets %s and %s,\n", config.TLSSecretAuth, config.TLSSecretAdmin)
		out.println("     now that the namespace exists: until then the hosts are served without their")
		out.println("     certificates. For instance:")
		printCreateTLSSecret(out, config)
		out.println()
	}
	if config.ImagePullSecret != "" {
		if config.NamespaceExists {
			out.printf("     The image pull secret %s must exist in %s, with your credentials for %s:\n", config.ImagePullSecret, config.K8sNamespace, config.imageRegistry())
			out.println("     until it does, the pods wait in ImagePullBackOff. For instance:")
		} else {
			out.printf("     Then create the image pull secret %s, now that the namespace exists, with your\n", config.ImagePullSecret)
			out.printf("     credentials for %s: until it exists, the pods wait in ImagePullBackOff. For instance:\n", config.imageRegistry())
		}
		printCreatePullSecret(out, config, "     ")
		out.println()
	}
	if config.NamespaceExists {
		out.printf("     The namespace %s must already exist: neither file creates it. The manifest's header\n", config.K8sNamespace)
		out.println("     has the Pod Security labels its owner can set.")
		out.println()
	}
	out.printf("     %sFor a deployment that already runs, apply only %s.%s %s holds\n", out.bold, filepath.Base(paths.description), out.reset, filepath.Base(paths.secrets))
	out.println("     newly generated secrets, which its database isn't under: a pod reads its Secrets")
	out.println("     only when it starts, so nothing changes until the next restart, and then the auth")
	out.println("     server and the admin console refuse to start. To write the manifest again without")
	out.printf("     them, run the wizard with the flags in %s's header.\n", filepath.Base(paths.answers))
	out.println()
}

// printImportantNotes prints the notes every Kubernetes completion message has.
func printImportantNotes(out *console, config *Config) {
	out.printf("%s%sIMPORTANT NOTES%s\n", out.bold, out.yellow, out.reset)
	out.println()
	out.println("  • The database must be empty for a fresh deployment. Goiabada will")
	out.println("    automatically seed the database with initial data including the")
	out.println("    admin user and OAuth clients configured with the URLs above.")
	out.println("    If redeploying with different URLs, use a fresh database.")
	out.println()
	out.printf("  • ")
	printConnectionSum(out, config, "    ")
	out.println()
	out.println("  • If using a managed database service (Supabase, PlanetScale, etc.),")
	out.println("    use the connection pooler endpoint for better compatibility (IPv4).")
	out.println()
	printMetricsNotes(out, config)
}

// printConnectionSum says how many database connections the auth server's running pods and its
// surge pod may open, which the database's max_connections must exceed with room for the pods a
// rollout is still stopping, its lines after the first indented by indent (#686 section 9).
func printConnectionSum(out *console, config *Config, indent string) {
	out.printf("The auth server's %d pods, and the one more a rollout starts, each open up to %d database\n", config.AuthServerReplicas, authServerPoolSize)
	out.printf("%sconnections: (%d + 1) × %d = %d. The database's max_connections must exceed that, beside\n", indent, config.AuthServerReplicas, authServerPoolSize, config.connectionBudget())
	out.printf("%sthe pods a rollout is still stopping and every other connection it takes:\n", indent)
	out.printf("%s%s\n", indent, highAvailabilityDocsURL)
}

// printNetworkPolicyTip says, with the NetworkPolicies on, how a blocked connection looks and how
// to read what they admit.
func printNetworkPolicyTip(out *console, config *Config) {
	if !config.NetworkPolicy {
		return
	}
	out.println("  • A connection a NetworkPolicy blocks either times out or is refused at once, depending on")
	out.println("    the network plugin. If a workload cannot reach a server, check what the policies admit:")
	out.printf("      %skubectl describe networkpolicy -n %s%s\n", out.cyan, config.K8sNamespace, out.reset)
	if !config.servedByEnvoyGateway() {
		out.printf("    A route that answers 502 or times out may come from proxies outside %s, which\n", config.ProxyNamespace)
		out.println("    the policies refuse: check where your routing layer's pods run.")
	}
	out.println()
}

// printPodTips prints the troubleshooting tips on the pods every Kubernetes message ends with.
func printPodTips(out *console, config *Config) {
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
		if len(config.MeshPorts) > 0 {
			out.println("    A scraper in the service mesh arrives on the mesh's port, which the second rule does not")
			out.println("    admit: keep it out of the mesh, or add that port to the rule.")
		}
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
		out.printf("    their CERTFILE and KEYFILE in %s, as its comments say. The admin console\n", filepath.Base(paths.description))
		out.println("    reaches the auth server at its public URL, so it waits to listen until the")
		out.println("    auth server serves HTTPS there.")
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
	switch {
	case paths.answers != "":
		out.printf("%s and %s hold none, and can be committed.\n", filepath.Base(paths.description), filepath.Base(paths.answers))
	case paths.separate():
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
