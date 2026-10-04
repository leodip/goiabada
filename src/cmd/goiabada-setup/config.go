package main

// Config holds all configuration values
type Config struct {
	Deployment          *deployment
	Engine              *engine
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
	AESEncryptionKey    string
	OAuthClientSecret   string
	K8sNamespace        string
	// LocalProxy says a reverse proxy on the same machine forwards to the native binaries: they
	// then listen on loopback alone and trust its forwarded headers. Only native binaries ask.
	LocalProxy bool
	// GatewayTrafficPolicy is the externalTrafficPolicy of Envoy Gateway's load balancer Service,
	// which decides the address the servers see for a client. Only Kubernetes asks (#396 decision 4).
	GatewayTrafficPolicy trafficPolicy
	// NetworkPolicy says the manifest admits the servers' ports from Envoy's namespace, and the auth
	// server's from the admin console, and from nothing else. Only Kubernetes asks (#396 decision 5).
	NetworkPolicy bool
	// RateLimiter turns on the auth server's built-in rate limiter. Production Compose, native
	// binaries and Kubernetes ask; local testing leaves it off (#396 decision 9).
	RateLimiter bool
}

// trafficPolicy is an externalTrafficPolicy, spelled as Kubernetes spells it.
type trafficPolicy string

const (
	trafficPolicyCluster trafficPolicy = "Cluster"
	trafficPolicyLocal   trafficPolicy = "Local"
)

// rateLimitsDocsURL is where the limits the rate limiter turns on are listed.
const rateLimitsDocsURL = "https://goiabada.dev/reference/environment-variables/#security-settings"

// rateLimiterDefault is the answer the rate limiter question offers: on, but for a manifest behind
// Envoy under the Cluster traffic policy, where the servers see a node's address for every client,
// so the per-IP limits would count everyone arriving through one node together (#396 decision 9).
func (c *Config) rateLimiterDefault() bool {
	return !c.Deployment.servedByEnvoyGateway || c.GatewayTrafficPolicy != trafficPolicyCluster
}

// rateLimiterComment is the comment above the rate limiter's switch in every output that writes it:
// what it turns on, where the limits are listed, and the startup warning it brings with this
// output's proxy trust, which the auth server logs only with the limiter on.
func (c *Config) rateLimiterComment() []string {
	lines := []string{
		"The auth server's built-in rate limiter: per-IP limits on sign-in, password reset,",
		"self-registration and client registration, and limits on failed passwords and codes per",
		"account. The server's own default is off. The limits are listed at",
		rateLimitsDocsURL,
	}
	switch {
	case c.Deployment.servedByEnvoyGateway && c.GatewayTrafficPolicy == trafficPolicyCluster:
		lines = append(lines,
			"Under the gateway's Cluster traffic policy the servers see a node's address, so the",
			"per-IP limits count every client arriving through one node together.",
			"With it on, the auth server logs a warning at every start that it trusts one proxy hop",
			"with no list; behind Envoy alone, that is expected.")
	case c.Deployment.servedByEnvoyGateway:
		lines = append(lines,
			"With it on, the auth server logs a warning at every start that it trusts one proxy hop",
			"with no list; behind Envoy alone, that is expected.")
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
