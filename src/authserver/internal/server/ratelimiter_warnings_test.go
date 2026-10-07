package server

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
)

// -----------------------------------------------------------------------------
// Seam 6: rateLimiterConfigWarnings
// -----------------------------------------------------------------------------

// TestRateLimiterConfigWarnings covers every combination of the three inputs that decides
// anything, asserting the exact slice rather than a count, so a branch returning the other
// message fails here rather than in a reader's log (#219).
//
// The two disabled rows are the ones worth keeping: the misconfiguration is present in both
// and neither may warn, because the flag is off by default and a warning every operator sees
// about a limiter nobody enabled is what would get all of these ignored.
func TestRateLimiterConfigWarnings(t *testing.T) {
	tests := []struct {
		name              string
		enabled           bool
		trustProxyHeaders bool
		trustedProxies    []string
		want              []string
	}{
		{
			name:              "the limiter is off, and untrusted proxy headers say nothing about it",
			enabled:           false,
			trustProxyHeaders: false,
			want:              nil,
		},
		{
			name:              "the limiter is off, and single-hop trust says nothing about it either",
			enabled:           false,
			trustProxyHeaders: true,
			want:              nil,
		},
		{
			name:              "on, with proxy headers untrusted: one bucket for the whole deployment",
			enabled:           true,
			trustProxyHeaders: false,
			want:              []string{warnRateLimiterNoProxyTrust},
		},
		{
			name:              "on, trusting proxy headers with no allowlist: the caller picks its bucket",
			enabled:           true,
			trustProxyHeaders: true,
			trustedProxies:    nil,
			want:              []string{warnRateLimiterSingleHopTrust},
		},
		{
			name:              "on, trusting proxy headers with an allowlist: nothing to say",
			enabled:           true,
			trustProxyHeaders: true,
			trustedProxies:    []string{"10.0.0.0/8"},
			want:              nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want,
				rateLimiterConfigWarnings(test.enabled, test.trustProxyHeaders, test.trustedProxies))
		})
	}
}

// TestRateLimiterSingleHopWarning_SaysWhenOneHopIsSound pins the single-hop text whole, because
// what it advises is the point of it. It used to say one hop is sound only behind a proxy that
// overwrites X-Forwarded-For and to set a trusted-proxy list, which is wrong for Envoy, nginx and
// Cloudflare, all of which append, and which behind Envoy is exactly the list that adopts a forged
// entry (#396 decision 8).
func TestRateLimiterSingleHopWarning_SaysWhenOneHopIsSound(t *testing.T) {
	assert.Equal(t,
		"config: GOIABADA_AUTHSERVER_RATELIMITER_ENABLED is true and "+
			"GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS is true with no GOIABADA_AUTHSERVER_TRUSTED_PROXIES, "+
			"so the client is the rightmost X-Forwarded-For entry. That is sound behind one reverse proxy "+
			"that sets or appends X-Forwarded-For, as Envoy, nginx and Cloudflare do; what defeats it is a "+
			"caller that reaches this server without passing the proxy, which then chooses the address it "+
			"is rate-limited and audited under. Set GOIABADA_AUTHSERVER_TRUSTED_PROXIES only when a second "+
			"proxy hop, such as a CDN or a load balancer, sits in front of the one that connects here. "+
			"See https://goiabada.dev/deploy/reverse-proxy/#client-ip-resolution-and-spoofing-protection",
		warnRateLimiterSingleHopTrust)
}

// -----------------------------------------------------------------------------
// The emission itself
// -----------------------------------------------------------------------------

// logtest.CaptureSlog holds the default logger for each case below and restores it afterwards.

// TestEmitRateLimiterConfigWarnings owns the one claim the table above cannot make: that
// something actually writes the strings to the log. Delete the loop and the table stays
// green while an operator is told nothing, which is the whole point of the change.
func TestEmitRateLimiterConfigWarnings(t *testing.T) {
	t.Run("an enabled misconfiguration produces one warning, carrying the message", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)

		emitRateLimiterConfigWarnings(true, false, nil)

		assert.Equal(t, 1, strings.Count(buf.Text(), "level=WARN"))
		assert.Contains(t, buf.Text(), warnRateLimiterNoProxyTrust)
	})

	t.Run("single-hop trust produces its own message, not the other one", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)

		emitRateLimiterConfigWarnings(true, true, nil)

		assert.Equal(t, 1, strings.Count(buf.Text(), "level=WARN"))
		assert.Contains(t, buf.Text(), warnRateLimiterSingleHopTrust)
	})

	t.Run("a disabled limiter writes nothing at all", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)

		emitRateLimiterConfigWarnings(false, false, nil)

		assert.Empty(t, buf.Text())
	})
}
