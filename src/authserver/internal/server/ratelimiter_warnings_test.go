package server

import (
	"strings"
	"testing"

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

// -----------------------------------------------------------------------------
// The emission itself
// -----------------------------------------------------------------------------

// captureSlog, which redirects the default logger into a buffer, lives in
// server_request_logger_test.go: one helper per package, not one per test file.

// TestEmitRateLimiterConfigWarnings owns the one claim the table above cannot make: that
// something actually writes the strings to the log. Delete the loop and the table stays
// green while an operator is told nothing, which is the whole point of the change.
func TestEmitRateLimiterConfigWarnings(t *testing.T) {
	t.Run("an enabled misconfiguration produces one warning, carrying the message", func(t *testing.T) {
		buf := captureSlog(t)

		emitRateLimiterConfigWarnings(true, false, nil)

		assert.Equal(t, 1, strings.Count(buf.String(), "level=WARN"))
		assert.Contains(t, buf.String(), warnRateLimiterNoProxyTrust)
	})

	t.Run("single-hop trust produces its own message, not the other one", func(t *testing.T) {
		buf := captureSlog(t)

		emitRateLimiterConfigWarnings(true, true, nil)

		assert.Equal(t, 1, strings.Count(buf.String(), "level=WARN"))
		assert.Contains(t, buf.String(), warnRateLimiterSingleHopTrust)
	})

	t.Run("a disabled limiter writes nothing at all", func(t *testing.T) {
		buf := captureSlog(t)

		emitRateLimiterConfigWarnings(false, false, nil)

		assert.Empty(t, buf.String())
	})
}
