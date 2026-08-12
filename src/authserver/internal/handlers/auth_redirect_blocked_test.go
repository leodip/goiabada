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
