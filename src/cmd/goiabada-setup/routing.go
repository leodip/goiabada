package main

import (
	"fmt"
	"strings"
)

// The Gateway's listeners when the manifest creates it: plain HTTP, and one HTTPS listener per host
// when it ends TLS. The routes attach to them by these names.
const (
	httpListener       = "http"
	authHTTPSListener  = "auth-https"
	adminHTTPSListener = "admin-https"
)

// writeRouting writes what carries traffic from outside the cluster to the two Services, as the
// routing answer says: a Gateway of the manifest's own and its HTTPRoutes, HTTPRoutes attached to a
// Gateway someone else runs, an Ingress per host, or nothing (#686 section 3). Nothing names an
// implementation but the class answered, which for envoy-gateway is the eg class the completion
// message has the operator create for Envoy Gateway (#430).
//
// The Gateway modes keep the routes' names and their one rule, which the Internal TLS guide's
// kustomization patches by name and position (#687), and which a test builds against every golden.
func writeRouting(sb *strings.Builder, config *Config) {
	if config.Routing == routingNone {
		sb.WriteString("# No route: the Services goiabada-authserver, port 9090, and goiabada-adminconsole, port\n")
		sb.WriteString("# 9091, are routed by what you run in front of them, which must serve each URL above over\n")
		sb.WriteString("# HTTPS and redirect plain HTTP.\n")
		return
	}
	if config.Routing == routingIngress {
		writeIngresses(sb, config)
		return
	}

	// Routing is Gateway API rather than Ingress by default: the one controller the Ingresses were
	// written for, ingress-nginx, is retired and gets no more security fixes, and SIG Network points
	// its users at Gateway API (kubernetes.io blog, 2025-11-11).
	ns := config.K8sNamespace
	authHost := hostOf(config.AuthServerURL)
	adminHost := hostOf(config.AdminConsoleURL)
	parent := gatewayParent{name: "goiabada", authListener: authHTTPSListener, adminListener: adminHTTPSListener}
	switch {
	case config.Routing == routingExistingGateway:
		parent = gatewayParent{config.GatewayName, config.GatewayNamespace, config.AuthListener, config.AdminListener}
	case !config.endsTLS():
		parent.authListener, parent.adminListener = httpListener, httpListener
	}

	if config.ownsGateway() {
		writeGateway(sb, config, authHost, adminHost)
		sb.WriteString("\n")
	}
	writeHTTPRoute(sb, ns, "goiabada-authserver", parent, parent.authListener, authHost, 9090)
	sb.WriteString("\n")
	writeHTTPRoute(sb, ns, "goiabada-adminconsole", parent, parent.adminListener, adminHost, 9091)
	if config.writesRedirect() {
		sb.WriteString("\n")
		writeHTTPSRedirect(sb, ns, authHost, adminHost, httpsPortOf(config.AuthServerURL))
	}
}

// gatewayParent is the Gateway the HTTPRoutes attach to, its namespace empty for the routes' own, and
// the listener each route attaches to.
type gatewayParent struct {
	name, namespace             string
	authListener, adminListener string
}

// writeGateway writes the Gateway the manifest creates: plain HTTP, and, when it ends TLS, one HTTPS
// listener per host with its certificate. Under a cert-manager issuer the HTTP listener carries the
// redirect and the HTTP-01 challenges, and cert-manager reads the annotation and issues each
// listener's certificateRefs for its hostname (cert-manager docs, usage/gateway.md). With TLS ended
// in front, the HTTP listener carries the routes.
func writeGateway(sb *strings.Builder, config *Config, authHost, adminHost string) {
	sb.WriteString("---\n")
	switch {
	case !config.endsTLS():
		sb.WriteString("# TLS ends in front of this Gateway, at a load balancer or a CDN that forwards plain HTTP\n")
		sb.WriteString("# to it, so it has an HTTP listener alone. Let nothing but that reach the Gateway: it\n")
		sb.WriteString("# serves both hosts over plain HTTP.\n")
	case !config.issuesWithCertManager():
		sb.WriteString("# The certificates are the TLS Secrets each HTTPS listener names, which you supply in this\n")
		sb.WriteString("# namespace and renew before they expire.\n")
	}
	sb.WriteString("apiVersion: gateway.networking.k8s.io/v1\n")
	sb.WriteString("kind: Gateway\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada\n")
	fmt.Fprintf(sb, "  namespace: %s\n", yamlQuote(config.K8sNamespace))
	if config.issuesWithCertManager() {
		sb.WriteString("  annotations:\n")
		fmt.Fprintf(sb, "    %s: %s\n", config.certManagerAnnotation(), yamlQuote(config.TLSIssuer))
	}
	sb.WriteString("spec:\n")
	fmt.Fprintf(sb, "  gatewayClassName: %s\n", yamlQuote(config.GatewayClass))
	sb.WriteString("  listeners:\n")
	fmt.Fprintf(sb, "  - name: %s\n", httpListener)
	sb.WriteString("    protocol: HTTP\n")
	fmt.Fprintf(sb, "    port: %d\n", config.GatewayHTTPPort)
	if config.endsTLS() {
		writeHTTPSListener(sb, authHTTPSListener, authHost, config.GatewayHTTPSPort, config.TLSSecretAuth)
		writeHTTPSListener(sb, adminHTTPSListener, adminHost, config.GatewayHTTPSPort, config.TLSSecretAdmin)
	}
}

// writeHTTPSListener writes one HTTPS listener of the Gateway, on port, terminating TLS for host with
// the certificate in the Secret certificate.
func writeHTTPSListener(sb *strings.Builder, name, host string, port int, certificate string) {
	fmt.Fprintf(sb, "  - name: %s\n", name)
	sb.WriteString("    protocol: HTTPS\n")
	fmt.Fprintf(sb, "    port: %d\n", port)
	fmt.Fprintf(sb, "    hostname: %s\n", yamlQuote(host))
	sb.WriteString("    tls:\n")
	sb.WriteString("      mode: Terminate\n")
	sb.WriteString("      certificateRefs:\n")
	fmt.Fprintf(sb, "      - name: %s\n", yamlQuote(certificate))
}

// writeHTTPRoute writes the HTTPRoute sending host, on the parent Gateway's listener, to service's
// port.
func writeHTTPRoute(sb *strings.Builder, ns, service string, parent gatewayParent, listener, host string, port int) {
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: gateway.networking.k8s.io/v1\n")
	sb.WriteString("kind: HTTPRoute\n")
	sb.WriteString("metadata:\n")
	fmt.Fprintf(sb, "  name: %s\n", service)
	fmt.Fprintf(sb, "  namespace: %s\n", yamlQuote(ns))
	sb.WriteString("spec:\n")
	sb.WriteString("  parentRefs:\n")
	fmt.Fprintf(sb, "  - name: %s\n", yamlQuote(parent.name))
	if parent.namespace != "" {
		fmt.Fprintf(sb, "    namespace: %s\n", yamlQuote(parent.namespace))
	}
	fmt.Fprintf(sb, "    sectionName: %s\n", yamlQuote(listener))
	sb.WriteString("  hostnames:\n")
	fmt.Fprintf(sb, "  - %s\n", yamlQuote(host))
	sb.WriteString("  rules:\n")
	sb.WriteString("  - backendRefs:\n")
	fmt.Fprintf(sb, "    - name: %s\n", service)
	fmt.Fprintf(sb, "      port: %d\n", port)
}

// writeHTTPSRedirect writes the route answering plain HTTP on either host with a redirect to HTTPS,
// which ingress-nginx did by default for a host with TLS, to the port the URLs name, port, whatever
// port the HTTPS listener has: a load balancer in front may publish it as another, as K3s publishes
// Traefik's 8443 as 443. For URLs on 443 no port is written: with a scheme and no port "the redirect
// port MUST be the well-known port associated with the redirect scheme", 443 for https
// (HTTPRequestRedirectFilter.Port, Gateway API v1.6.1 apis/v1/httproute_types.go). An explicit 443
// changes nothing on Envoy Gateway v1.9.1, which renders either as Envoy's scheme redirect alone:
// that drops a Host's :80 and keeps any other port it names, so a URL on another port needs it
// written (#430, #686 section 3).
func writeHTTPSRedirect(sb *strings.Builder, ns, authHost, adminHost, port string) {
	sb.WriteString("---\n")
	sb.WriteString("apiVersion: gateway.networking.k8s.io/v1\n")
	sb.WriteString("kind: HTTPRoute\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: goiabada-https-redirect\n")
	fmt.Fprintf(sb, "  namespace: %s\n", yamlQuote(ns))
	sb.WriteString("spec:\n")
	sb.WriteString("  parentRefs:\n")
	sb.WriteString("  - name: goiabada\n")
	fmt.Fprintf(sb, "    sectionName: %s\n", httpListener)
	sb.WriteString("  hostnames:\n")
	fmt.Fprintf(sb, "  - %s\n", yamlQuote(authHost))
	fmt.Fprintf(sb, "  - %s\n", yamlQuote(adminHost))
	sb.WriteString("  rules:\n")
	sb.WriteString("  - filters:\n")
	sb.WriteString("    - type: RequestRedirect\n")
	sb.WriteString("      requestRedirect:\n")
	sb.WriteString("        scheme: https\n")
	if port != "" {
		fmt.Fprintf(sb, "        port: %s\n", port)
	}
	sb.WriteString("        statusCode: 301\n")
}

// writeIngresses writes one Ingress per host, named after the Service it sends to, as the HTTPRoutes
// are. An Ingress has no portable redirect from HTTP to HTTPS: some controllers serve an Ingress
// with TLS on plain HTTP as well, Traefik among them until its entry point redirects, so the comment
// and the completion message have the operator check it.
func writeIngresses(sb *strings.Builder, config *Config) {
	sb.WriteString("---\n")
	if config.endsTLS() {
		sb.WriteString("# Your Ingress controller must redirect plain HTTP to HTTPS, which no Ingress field asks\n")
		sb.WriteString("# for: some serve an Ingress with TLS on plain HTTP as well, by default, as Traefik does\n")
		sb.WriteString("# until its web entry point redirects to websecure.\n")
	} else {
		sb.WriteString("# TLS ends in front of the Ingress controller, at a load balancer or a CDN that forwards\n")
		sb.WriteString("# plain HTTP to it, so the Ingresses have no TLS. Let nothing but that reach the\n")
		sb.WriteString("# controller, which serves both hosts over plain HTTP, and keep its own redirect to HTTPS\n")
		sb.WriteString("# off: every request reaches it as plain HTTP, and would be sent back in a loop.\n")
	}
	if config.endsTLS() && !config.issuesWithCertManager() {
		sb.WriteString("# The certificates are the TLS Secrets each Ingress names, which you supply in this\n")
		sb.WriteString("# namespace and renew before they expire.\n")
	}
	writeIngress(sb, config, "goiabada-authserver", hostOf(config.AuthServerURL), 9090, config.TLSSecretAuth)
	sb.WriteString("\n")
	sb.WriteString("---\n")
	writeIngress(sb, config, "goiabada-adminconsole", hostOf(config.AdminConsoleURL), 9091, config.TLSSecretAdmin)
}

// writeIngress writes the Ingress sending host to service's port, ending TLS with the certificate in
// the Secret certificate unless TLS ends in front of it, the certificate issued by the cert-manager
// issuer its annotation names when there is one (cert-manager docs, usage/ingress.md).
func writeIngress(sb *strings.Builder, config *Config, service, host string, port int, certificate string) {
	sb.WriteString("apiVersion: networking.k8s.io/v1\n")
	sb.WriteString("kind: Ingress\n")
	sb.WriteString("metadata:\n")
	fmt.Fprintf(sb, "  name: %s\n", service)
	fmt.Fprintf(sb, "  namespace: %s\n", yamlQuote(config.K8sNamespace))
	if config.issuesWithCertManager() {
		sb.WriteString("  annotations:\n")
		fmt.Fprintf(sb, "    %s: %s\n", config.certManagerAnnotation(), yamlQuote(config.TLSIssuer))
	}
	sb.WriteString("spec:\n")
	if config.IngressClass != "" {
		fmt.Fprintf(sb, "  ingressClassName: %s\n", yamlQuote(config.IngressClass))
	}
	if config.endsTLS() {
		sb.WriteString("  tls:\n")
		sb.WriteString("  - hosts:\n")
		fmt.Fprintf(sb, "    - %s\n", yamlQuote(host))
		fmt.Fprintf(sb, "    secretName: %s\n", yamlQuote(certificate))
	}
	sb.WriteString("  rules:\n")
	fmt.Fprintf(sb, "  - host: %s\n", yamlQuote(host))
	sb.WriteString("    http:\n")
	sb.WriteString("      paths:\n")
	sb.WriteString("      - path: /\n")
	sb.WriteString("        pathType: Prefix\n")
	sb.WriteString("        backend:\n")
	sb.WriteString("          service:\n")
	fmt.Fprintf(sb, "            name: %s\n", service)
	sb.WriteString("            port:\n")
	fmt.Fprintf(sb, "              number: %d\n", port)
}

// proxies is what the NetworkPolicies' comments call what they admit: Envoy's proxies for the Envoy
// Gateway recipe, and the routing layer for any other mode.
func (c *Config) proxies() string {
	if c.servedByEnvoyGateway() {
		return "Envoy's proxies"
	}
	return "the routing layer"
}
