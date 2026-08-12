package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// redirectDestinationLabel is the only thing on the interstitial a user can act on: it is what tells
// them where the client wanted to send them. It is pure, so the whole branch table lives here rather
// than costing a full authorization per case at the integration tier (#108, seam 7).
func TestRedirectDestinationLabel(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		want        string
		why         string
	}{
		{
			name:        "an ordinary web redirect URI shows the host alone",
			redirectURI: "https://app.example.com/cb?foo=bar",
			want:        "app.example.com",
			why:         "the path and query are noise a user cannot evaluate",
		},
		{
			name:        "a private-use URI scheme has no host, so the whole URI is shown",
			redirectURI: "com.example.app:/oauth",
			want:        "com.example.app:/oauth",
			why:         "dynamic registration accepts this today and url.Parse gives it an empty Host",
		},
		{
			name:        "mailto has no host either",
			redirectURI: "mailto:a@b.c",
			want:        "mailto:a@b.c",
			why:         "the validator's own table asserts this acceptable, and a blank line says nothing",
		},
		{
			name:        "a URI url.Parse rejects falls back to the whole string",
			redirectURI: "https://exa mple.com/\x7f",
			want:        "https://exa mple.com/\x7f",
			why:         "an unparsable destination is still better shown than swallowed",
		},
		{
			name:        "a host with a port keeps the port",
			redirectURI: "http://localhost:8080/callback",
			want:        "localhost:8080",
			why:         "the port is part of where the browser would have gone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, redirectDestinationLabel(tt.redirectURI), tt.why)
		})
	}
}

// promptRequestsSilence carries the OIDC Core 3.1.2.1 exemption at the two sites where the ceremony
// has not been given a validated prompt yet. Answering true wrongly delivers a user agent to a
// self-registered client's host, which is the whole attack; answering false wrongly renders a page
// for a silent request, which the spec forbids with a MUST NOT. Both directions matter, so both are
// here (#108).
func TestPromptRequestsSilence(t *testing.T) {
	tests := []struct {
		prompt string
		want   bool
		why    string
	}{
		{prompt: "none", want: true, why: "the plain silent request"},
		{prompt: "none login", want: true, why: "still asks for none, whatever else it asks for"},
		{prompt: "  none  ", want: true, why: "surrounding whitespace is not part of the value"},
		{prompt: "login", want: false, why: "an interactive prompt is not exempt"},
		{prompt: "consent", want: false, why: "an interactive prompt is not exempt"},
		{prompt: "", want: false, why: "no prompt at all is the ordinary interactive request"},
		{prompt: "nonetheless", want: false,
			why: "matched as a whole field, never as a substring, or a request asking for nothing would be exempt"},
		{prompt: "NONE", want: false, why: "prompt values are case sensitive per OIDC Core 3.1.2.1"},
	}

	for _, tt := range tests {
		t.Run(tt.prompt, func(t *testing.T) {
			assert.Equal(t, tt.want, promptRequestsSilence(tt.prompt), tt.why)
		})
	}
}
