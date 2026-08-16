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

	warnRateLimiterSingleHopTrust = "config: GOIABADA_AUTHSERVER_RATELIMITER_ENABLED is true and " +
		"GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS is true with no GOIABADA_AUTHSERVER_TRUSTED_PROXIES; " +
		"single-hop trust adopts the rightmost X-Forwarded-For entry, which is sound only if the proxy " +
		"overwrites the inbound header, and otherwise lets a client choose its own per-IP bucket. " +
		"Set GOIABADA_AUTHSERVER_TRUSTED_PROXIES to the proxy addresses or CIDRs"
)

// rateLimiterConfigWarnings reports the proxy misconfigurations that change what a rate
// limit means, for a deployment that has turned the limiter on.
//
// Nothing is reported while the limiter is off, and that is what makes these warnings free
// rather than noise: the flag is off by default, so the audience is exactly the operators
// who opted in and for whom the per-IP buckets now decide who gets served. The two
// conditions fail in opposite directions, which is why both are worth a line: untrusted
// headers behind a proxy fail closed and throttle everybody at once, while single-hop trust
// with no allowlist fails open and hands the bucket choice to the caller.
//
// One case it deliberately does not reach: a trusted-proxy list whose entries are all
// malformed leaves MiddlewareRealIP in single-hop mode with this function seeing a
// non-empty list. That is not silent, since parseCIDRs warns once per rejected entry and
// names it, which is the more actionable message of the two.
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
		slog.Warn(warning)
	}
}
