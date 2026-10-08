package server

import "log/slog"

// The two configurations an operator who turns the rate limiter on cannot see from the
// outside, and what each one does to the per-IP buckets (#219).
//
// Both name the environment variables rather than describing the state, because an
// operator reading a startup log needs the setting to change, not a diagnosis.
const (
	warnRateLimiterNoProxyTrust = "config: GOIABADA_AUTHSERVER_RATELIMITER_ENABLED is true but " +
		"GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS is false; if this server sits behind a reverse proxy, " +
		"every request resolves to the proxy's address and the whole deployment shares one per-IP bucket. " +
		"Set GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS, and GOIABADA_AUTHSERVER_TRUSTED_PROXIES with it"

	// One hop is sound behind any proxy that sets or appends X-Forwarded-For, Envoy, nginx and
	// Cloudflare among them, since the rightmost entry is then the address that proxy received the
	// connection from. The server cannot tell that from a proxy passing the header through untouched
	// or a caller reaching it around the proxy, which is why this stays a warning (#396 decision 8).
	warnRateLimiterSingleHopTrust = "config: GOIABADA_AUTHSERVER_RATELIMITER_ENABLED is true and " +
		"GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS is true with no GOIABADA_AUTHSERVER_TRUSTED_PROXIES, " +
		"so the client is the rightmost X-Forwarded-For entry. That is sound behind one reverse proxy " +
		"that sets or appends X-Forwarded-For, as Envoy, nginx and Cloudflare do; what defeats it is a " +
		"caller that reaches this server without passing the proxy, which then chooses the address it " +
		"is rate-limited and audited under. Set GOIABADA_AUTHSERVER_TRUSTED_PROXIES only when a second " +
		"proxy hop, such as a CDN or a load balancer, sits in front of the one that connects here. " +
		"See https://goiabada.dev/deploy/client-ip-and-proxy-trust/#the-startup-warnings"
)

// rateLimiterConfigWarnings reports the proxy misconfigurations that change what a rate
// limit means, for a deployment that has turned the limiter on.
//
// Nothing is reported while the limiter is off, and that is what makes these warnings free
// rather than noise: the flag is off by default, so the audience is exactly the operators
// who opted in and for whom the per-IP buckets now decide who gets served. The two
// conditions fail in opposite directions, which is why both are worth a line: untrusted
// headers behind a proxy fail closed and throttle everybody at once, while single-hop trust
// with no allowlist fails open, handing the bucket choice to any caller that reaches the
// server without passing its proxy.
func rateLimiterConfigWarnings(enabled, trustProxyHeaders bool, trustedProxies []string) []string {
	if !enabled {
		return nil
	}

	if !trustProxyHeaders {
		return []string{warnRateLimiterNoProxyTrust}
	}

	if len(trustedProxies) == 0 {
		return []string{warnRateLimiterSingleHopTrust}
	}

	return nil
}

// emitRateLimiterConfigWarnings writes the warnings above to the startup log.
//
// slog.Warn rather than Error: a configuration worth questioning is not a failure, and an
// auth server whose error log carries expected events has no error log left.
func emitRateLimiterConfigWarnings(enabled, trustProxyHeaders bool, trustedProxies []string) {
	for _, warning := range rateLimiterConfigWarnings(enabled, trustProxyHeaders, trustedProxies) {
		slog.Warn("rate limiter configuration warning", "warning", warning)
	}
}
