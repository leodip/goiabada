package main

import (
	"fmt"

	"github.com/leodip/goiabada/core/errs"
)

// Config holds all configuration values
type Config struct {
	Deployment *deployment
	Engine     *engine
	DBPort     string
	DBHost     string
	DBName     string
	DBUsername string
	DBPassword string
	// DBTLSMode is GOIABADA_DB_TLS_MODE, one of the five modes, for an engine with a server: asked
	// by Kubernetes and native binaries, prefer on Compose, whose database is on its own network.
	// DBTLSCAFile is the absolute path of the CA file the operator named, for verify-ca and
	// verify-full only, empty for the system's roots, and DBTLSCA the certificates it holds, as PEM:
	// native binaries name the file, and Kubernetes carries the certificates in a ConfigMap (#502).
	DBTLSMode   string
	DBTLSCAFile string
	DBTLSCA     string
	// DBTLSClientCertFile and DBTLSClientKeyFile are the absolute paths of the client certificate
	// pair the operator named, for require, verify-ca and verify-full on MySQL and PostgreSQL
	// alone, empty for none, and DBTLSClientCert and DBTLSClientKey the two files' contents, as
	// PEM, which the Kubernetes Secret is written from: native binaries name the files, and the
	// connection check pairs the contents as the auth server will (#546). DBTLSServerName is the
	// host name GOIABADA_DB_TLS_SERVER_NAME wants verify-full to check the certificate against,
	// empty leaving the host dialed.
	DBTLSClientCertFile string
	DBTLSClientKeyFile  string
	DBTLSClientCert     string
	DBTLSClientKey      string
	DBTLSServerName     string
	// DBTLSClientCertKept says the auth server presents a client certificate pair the secrets file
	// already holds, which a run under --keep-secrets leaves as it is, without reading the pair.
	DBTLSClientCertKept bool
	// KeepSecrets says the run writes every file but the secrets file, and generates no secret
	// (#686 section 4).
	KeepSecrets         bool
	AuthServerURL       string
	AdminConsoleURL     string
	AdminEmail          string
	AdminPassword       string
	AuthSessionAuthKey  string
	AuthSessionEncKey   string
	AdminSessionAuthKey string
	AdminSessionEncKey  string
	AESEncryptionKey    string
	OAuthClientSecret   string
	K8sNamespace        string
	// NamespaceExists says the Kubernetes namespace is someone else's to make, a platform team's as
	// a rule, so neither file declares it: applying a Namespace needs the right to patch it, which a
	// team granted rights inside the namespace lacks, and would reset the labels its owner set. Only
	// Kubernetes asks (#686 section 2).
	NamespaceExists bool
	// AdminPasswordGenerated and DBPasswordGenerated say the wizard generated the password rather
	// than the operator setting it, which is all the wizard reports of either (#396 decision 17).
	AdminPasswordGenerated bool
	DBPasswordGenerated    bool
	// LocalProxy says a reverse proxy on the same machine forwards to the native binaries: they
	// then listen on loopback alone and trust its forwarded headers. Only native binaries ask.
	LocalProxy bool
	// Routing is how traffic from outside the cluster reaches the servers. Only Kubernetes asks, and
	// the answers below it are read for the modes that ask them alone (#686 section 3).
	Routing routing
	// GatewayTrafficPolicy is the externalTrafficPolicy of Envoy Gateway's load balancer Service,
	// which decides the address the servers see for a client. Only the envoy-gateway mode asks (#396
	// decision 4).
	GatewayTrafficPolicy trafficPolicy
	// GatewayClass, GatewayHTTPPort and GatewayHTTPSPort are the class and listener ports of the
	// Gateway the manifest creates: asked by the gateway mode, and eg, 80 and 443 for envoy-gateway.
	// Some implementations accept only their own proxy's ports: Traefik's Gateway takes 8000 and
	// 8443, and refuses 80 as PortUnavailable.
	GatewayClass     string
	GatewayHTTPPort  int
	GatewayHTTPSPort int
	// GatewayName and GatewayNamespace name the Gateway someone else runs, and AuthListener and
	// AdminListener the HTTPS listeners of it each route attaches to, which the existing-gateway mode
	// asks. A route naming no listener would attach to every one its host matches, a plain HTTP one
	// on port 80 included, so a listener is always named.
	GatewayName      string
	GatewayNamespace string
	AuthListener     string
	AdminListener    string
	// IngressClass is the Ingresses' ingressClassName, empty for the cluster's default class: asked
	// by the ingress mode.
	IngressClass string
	// TLS is where the certificates of a Gateway or Ingresses the manifest creates come from:
	// TLSIssuer names the cert-manager issuer, and TLSSecretAuth and TLSSecretAdmin the Secrets
	// holding each host's certificate, which cert-manager writes under an issuer and the platform
	// supplies otherwise. envoy-gateway takes them from the letsencrypt-prod ClusterIssuer.
	TLS            tlsSource
	TLSIssuer      string
	TLSSecretAuth  string
	TLSSecretAdmin string
	// NetworkPolicy says the manifest admits the servers' ports from ProxyNamespace, where the
	// routing layer's proxies run, and the auth server's from the admin console, and from nothing
	// else. Only Kubernetes asks (#396 decision 5, #686 section 3). MeshPorts are the ports a service
	// mesh's proxies deliver on between meshed pods, admitted from the same sources, none unless
	// asked for (#686 section 8).
	NetworkPolicy  bool
	ProxyNamespace string
	MeshPorts      []int
	// AuthServerReplicas is the auth server Deployment's replica count, two unless asked for
	// otherwise; the admin console runs one. Only Kubernetes asks (#686 section 9).
	AuthServerReplicas int
	// RateLimiter turns on the auth server's built-in rate limiter. Production Compose, native
	// binaries and Kubernetes ask; local testing leaves it off (#396 decision 9).
	RateLimiter bool
	// Metrics is how a scraper discovers the servers' metrics listeners, which either answer but
	// none turns on: pod annotations, or a PodMonitor carrying PodMonitorLabels. MetricsNamespace is
	// the scraper's namespace, which the NetworkPolicies admit to the metrics ports, set only when
	// both are on. Only Kubernetes asks (#400 decisions 7 and 8).
	Metrics          metricsExposure
	PodMonitorLabels []keyValue
	MetricsNamespace string
	// ImageRepository is the repository both servers' images are pulled from, Docker Hub's unless a
	// mirror holds them. ImageDigest asks for each image line to name the digest its release pushed,
	// which a build carrying none cannot write (pinsDigests). ImagePullSecret is the Secret holding the
	// registry's credentials, empty for none, which Kubernetes alone asks: Compose pulls with the
	// host's docker login (#686 section 5).
	ImageRepository string
	ImageDigest     bool
	ImagePullSecret string
	// Labels and Annotations are the operator's, which every object and both pod templates carry
	// beside the standard labels, for the admission policies an organisation sets. Only Kubernetes
	// asks (#686 section 6).
	Labels      []keyValue
	Annotations []keyValue
}

// trafficPolicy is an externalTrafficPolicy, spelled as Kubernetes spells it.
type trafficPolicy string

const (
	trafficPolicyCluster trafficPolicy = "Cluster"
	trafficPolicyLocal   trafficPolicy = "Local"
)

// routing is a Kubernetes routing mode, spelled as --routing spells it.
type routing string

const (
	// routingEnvoyGateway is the tested recipe: a Gateway of class eg, the Envoy Gateway the
	// completion message has the operator install, with Let's Encrypt certificates.
	routingEnvoyGateway routing = "envoy-gateway"
	// routingGateway is a Gateway of the manifest's own, of a class the cluster already has.
	routingGateway routing = "gateway"
	// routingExistingGateway is HTTPRoutes alone, attached to a Gateway someone else runs.
	routingExistingGateway routing = "existing-gateway"
	// routingIngress is an Ingress per host.
	routingIngress routing = "ingress"
	// routingNone is the Services alone, which the operator routes.
	routingNone routing = "none"
)

// routings is every mode, in the order the wizard offers them.
var routings = []routing{routingEnvoyGateway, routingGateway, routingExistingGateway, routingIngress, routingNone}

// tlsSource is where the certificates of a Gateway or Ingresses the manifest creates come from,
// spelled as --tls spells it.
type tlsSource string

const (
	tlsClusterIssuer tlsSource = "cluster-issuer"
	tlsIssuer        tlsSource = "issuer"
	tlsSecrets       tlsSource = "secrets"
	// tlsExternal is TLS ended in front of the routing layer, at a load balancer or a CDN, which
	// forwards plain HTTP to it.
	tlsExternal tlsSource = "external"
)

// tlsSources is every source, in the order the wizard offers them.
var tlsSources = []tlsSource{tlsClusterIssuer, tlsIssuer, tlsSecrets, tlsExternal}

// The Secrets cert-manager writes the certificates to, which are also the names offered for Secrets
// the platform supplies.
const (
	authCertificateSecret  = "goiabada-tls-auth"  //nolint:gosec // G101: the Secret's name, not its value
	adminCertificateSecret = "goiabada-tls-admin" //nolint:gosec // G101: the Secret's name, not its value
)

// The envoy-gateway mode's answers to what the gateway mode asks: Envoy Gateway's eg class, Let's
// Encrypt through the ClusterIssuer the completion message prints, and the namespace Envoy Gateway
// runs its proxies in unless told otherwise, its controller's (KubernetesDeployMode, Envoy Gateway
// v1.9.1 api/v1alpha1/envoygateway_types.go), which the NetworkPolicies offer.
const (
	envoyGatewayClass   = "eg"
	letsEncryptIssuer   = "letsencrypt-prod"
	envoyProxyNamespace = "envoy-gateway-system"
)

// useEnvoyGatewayRecipe answers the gateway mode's questions as the envoy-gateway mode does, on the
// well-known ports, so the two modes write their Gateway alike.
func (c *Config) useEnvoyGatewayRecipe() {
	c.GatewayClass, c.GatewayHTTPPort, c.GatewayHTTPSPort = envoyGatewayClass, 80, 443
	c.TLS, c.TLSIssuer = tlsClusterIssuer, letsEncryptIssuer
	c.TLSSecretAuth, c.TLSSecretAdmin = authCertificateSecret, adminCertificateSecret
}

// servedByEnvoyGateway says the manifest is served through the Envoy Gateway the completion message
// has the operator install, whose traffic policy decides the address the servers see.
func (c *Config) servedByEnvoyGateway() bool {
	return c.Deployment.asksRouting && c.Routing == routingEnvoyGateway
}

// ownsGateway says the manifest creates its Gateway: the envoy-gateway and gateway modes.
func (c *Config) ownsGateway() bool {
	return c.Routing == routingEnvoyGateway || c.Routing == routingGateway
}

// routesThroughGateway says the manifest writes HTTPRoutes, to its own Gateway or another's.
func (c *Config) routesThroughGateway() bool {
	return c.ownsGateway() || c.Routing == routingExistingGateway
}

// presentsClientCertificate says the auth server presents a client certificate pair to the
// database: one this run read, or one the secrets file it leaves as it is holds.
func (c *Config) presentsClientCertificate() bool {
	return c.DBTLSClientCert != "" || c.DBTLSClientCertKept
}

// asksTLS says the mode creates what ends TLS and asks where its certificates come from.
func (c *Config) asksTLS() bool {
	return c.Routing == routingGateway || c.Routing == routingIngress
}

// endsTLS says the Gateway or Ingresses the manifest creates end TLS themselves: every mode that
// creates either, unless TLS ends in front of them.
func (c *Config) endsTLS() bool {
	return (c.ownsGateway() || c.Routing == routingIngress) && c.TLS != tlsExternal
}

// writesRedirect says the manifest redirects plain HTTP to HTTPS itself, on the Gateway it creates
// and ends TLS on; every other mode leaves the redirect to what is in front.
func (c *Config) writesRedirect() bool {
	return c.ownsGateway() && c.endsTLS()
}

// checkRedirectPort refuses, where the manifest writes the redirect, URLs naming two HTTPS ports:
// the Gateway serves both hosts on its one HTTPS port, so the redirect sends both to the port they
// name, which a route of both hosts can name once (#686 section 3).
func (c *Config) checkRedirectPort() error {
	if !c.writesRedirect() {
		return nil
	}
	auth, admin := httpsPortOf(c.AuthServerURL), httpsPortOf(c.AdminConsoleURL)
	if auth == admin {
		return nil
	}
	shown := func(port string) string {
		if port == "" {
			return "443"
		}
		return port
	}
	return errs.Errorf("the auth server's URL takes HTTPS on port %s and the admin console's on %s, and the Gateway serves both on one HTTPS port: give both URLs the same port", shown(auth), shown(admin))
}

// issuesWithCertManager says cert-manager issues the certificates, from the issuer an annotation
// names.
func (c *Config) issuesWithCertManager() bool {
	return c.endsTLS() && (c.TLS == tlsClusterIssuer || c.TLS == tlsIssuer)
}

// certManagerAnnotation is the annotation naming the issuer, which cert-manager reads on a Gateway
// and on an Ingress alike (cert-manager docs, usage/gateway.md and usage/ingress.md).
func (c *Config) certManagerAnnotation() string {
	if c.TLS == tlsIssuer {
		return "cert-manager.io/issuer"
	}
	return "cert-manager.io/cluster-issuer"
}

// routingAnswer is the routing answer as the summary reports it.
func (c *Config) routingAnswer() string {
	switch c.Routing {
	case routingEnvoyGateway:
		return "Envoy Gateway, a Gateway of class " + envoyGatewayClass
	case routingGateway:
		return "a Gateway of class " + c.GatewayClass
	case routingExistingGateway:
		return fmt.Sprintf("the Gateway %s/%s, %s", c.GatewayNamespace, c.GatewayName, c.listenersAnswer())
	case routingIngress:
		return "Ingresses of class " + c.ingressClassAnswer()
	}
	return "none, the Services alone"
}

// listenersAnswer names the listeners of someone else's Gateway the routes attach to: one, as a
// wildcard listener for both hosts is, or one per host.
func (c *Config) listenersAnswer() string {
	if c.AuthListener == c.AdminListener {
		return "listener " + c.AuthListener
	}
	return "listeners " + c.AuthListener + " and " + c.AdminListener
}

// redirector is what redirects plain HTTP to HTTPS where the manifest writes no redirect, as the
// completion message names it.
func (c *Config) redirector() string {
	switch {
	case c.asksTLS() && c.TLS == tlsExternal:
		return "the load balancer or CDN in front"
	case c.Routing == routingExistingGateway:
		return "the Gateway's owner"
	case c.Routing == routingIngress:
		return "your Ingress controller"
	}
	return "what routes the Services"
}

// ingressClassAnswer is the Ingresses' class as the wizard reports it.
func (c *Config) ingressClassAnswer() string {
	if c.IngressClass == "" {
		return "the cluster's default"
	}
	return c.IngressClass
}

// tlsAnswer is where the certificates come from, as the wizard reports it.
func (c *Config) tlsAnswer() string {
	switch c.TLS {
	case tlsClusterIssuer:
		return "the cert-manager ClusterIssuer " + c.TLSIssuer
	case tlsIssuer:
		return "the cert-manager Issuer " + c.TLSIssuer
	case tlsSecrets:
		if c.TLSSecretAuth == c.TLSSecretAdmin {
			return "the Secret " + c.TLSSecretAuth + ", for both hosts"
		}
		return "the Secrets " + c.TLSSecretAuth + " and " + c.TLSSecretAdmin
	}
	return "ended in front of the routing layer, which serves HTTP alone"
}

// seededAppName is the app name every configuration the wizard writes sets in GOIABADA_APPNAME,
// which the first start seeds, and so one of the words the first administrator's password is
// compared with (#550 decision 7).
const seededAppName = "Goiabada"

// rateLimitsDocsURL is where the auth server's limits are listed, those the rate limiter turns on
// and those that apply either way.
const rateLimitsDocsURL = "https://goiabada.dev/reference/environment-variables/#rate-limits"

// rateLimiterDefault is the answer the rate limiter question offers: on, but for a manifest behind
// Envoy under the Cluster traffic policy, where the servers see a node's address for every client,
// so the per-IP limits would count everyone arriving through one node together (#396 decision 9),
// and behind any other routing layer, whose address for a client the wizard cannot know (#686
// section 3).
func (c *Config) rateLimiterDefault() bool {
	if !c.Deployment.asksRouting {
		return true
	}
	return c.servedByEnvoyGateway() && c.GatewayTrafficPolicy == trafficPolicyLocal
}

// dbTLSComment is the comment above the TLS mode in an output that asks it, Kubernetes and native
// binaries: what the mode chosen does, and what a verifying one checks the certificate against,
// GOIABADA_DB_TLS_SERVER_NAME's name rather than the host when the file writes one (#546).
func (c *Config) dbTLSComment() []string {
	description := tlsModeDescription(c.DBTLSMode, c.Engine.name)
	if checksHostName(c.DBTLSMode) && c.DBTLSServerName != "" {
		description = verifyFullOverrideDescription
	}
	lines := []string{
		"How the auth server protects its connection to the database: disable, prefer, require,",
		"verify-ca or verify-full.",
		c.DBTLSMode + ": " + description + ".",
	}
	switch {
	case !checksCertificate(c.DBTLSMode):
		lines = append(lines, "Only verify-full makes sure it reached your database and nothing in between.")
	case c.DBTLSCA == "":
		lines = append(lines, "The certificate is checked against the system's roots; GOIABADA_DB_TLS_CA_FILE names a",
			"PEM file of the authorities to trust instead.")
	default:
		lines = append(lines, "The certificate is checked against the authorities in GOIABADA_DB_TLS_CA_FILE alone.")
	}
	return lines
}

// aesKeyComment is the warning every output writes beside the AES key: it is the one secret whose
// loss loses data, and the moment it is written is the one at which a backup can still be made
// (#396 decision 16).
func aesKeyComment() []string {
	return []string{
		"GOIABADA_AES_ENCRYPTION_KEY encrypts the client secrets, SMTP credentials, OTP seeds and",
		"signing keys the database holds. Back it up separately from the database: without it they",
		"cannot be recovered, and a backup holding both gives them to whoever reads it.",
	}
}

// rateLimiterComment is the comment above the rate limiter's switch in every output that writes it:
// what it turns on, what applies either way (#542, #503), where the limits are listed, and the
// startup warning it brings with this output's proxy trust, which the auth server logs only with the
// limiter on.
func (c *Config) rateLimiterComment() []string {
	lines := []string{
		"The auth server's rate limiter: per-IP limits on sign-in, password reset,",
		"self-registration and client registration, and a limit on wrong passwords per email from",
		"one network. The server's own default is off. Its limits per user (wrong one-time codes,",
		"Account-page password checks, email verification codes and verification mails) and per",
		"email (wrong passwords, password-reset mails and registration notices) apply either way.",
		"The limits are listed at",
		rateLimitsDocsURL,
	}
	switch {
	case c.servedByEnvoyGateway() && c.GatewayTrafficPolicy == trafficPolicyCluster:
		lines = append(lines,
			"Under the gateway's Cluster traffic policy the servers see a node's address, so the",
			"per-IP limits count every client arriving through one node together. With it on, 10",
			"wrong passwords block an email's password sign-ins for 15 minutes for every client",
			"through a node, since they all count as one network.",
			"With it on, the auth server logs a warning at every start that it trusts one proxy hop",
			"with no list; behind Envoy alone, that is expected.")
	case c.servedByEnvoyGateway():
		lines = append(lines,
			"Under the gateway's Local traffic policy the per-IP limits count each client alone when",
			"the load balancer passes connections through; one that proxies them shows every client",
			"with the load balancer's address, and they count every client together.",
			"With it on, the auth server logs a warning at every start that it trusts one proxy hop",
			"with no list; behind Envoy alone, that is expected.")
	case c.Deployment.asksRouting:
		lines = append(lines,
			"The servers see the address each connection reached your routing layer from, which can",
			"be a node's or a load balancer's, one for every client: the per-IP limits then count",
			"every client together. Check the ip= of your own request in the auth server's log",
			"before turning it on.",
			"With it on, the auth server logs a warning at every start that it trusts one proxy hop",
			"with no list; behind one routing layer, that is expected.")
	case c.Deployment.behindProxy:
		lines = append(lines,
			"With it on, the auth server logs a warning at every start that it trusts one proxy hop",
			"with no list; behind the one reverse proxy on this host, that is expected.")
	case c.Deployment.asksLocalProxy && !c.LocalProxy:
		lines = append(lines,
			"With it on, the auth server logs a warning at every start that it trusts no forwarded",
			"header; with no reverse proxy in front, that is expected.")
	}
	return lines
}
