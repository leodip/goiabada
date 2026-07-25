package handlers

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// GetProfileURL builds the link the auth server points users at to manage their
// own profile, which lives in the admin console rather than here.
func TestGetProfileURL(t *testing.T) {
	previous := config.GetAdminConsole().BaseURL
	t.Cleanup(func() { config.GetAdminConsole().BaseURL = previous })

	testCases := []struct {
		name    string
		baseURL string
		want    string
	}{
		{
			name:    "typical base URL",
			baseURL: "https://admin.example.com",
			want:    "https://admin.example.com/account/profile",
		},
		{
			name:    "base URL with a port",
			baseURL: "http://localhost:9091",
			want:    "http://localhost:9091/account/profile",
		},
		{
			// The base URL is concatenated as-is, so a trailing slash doubles up.
			// Pinned because it is the kind of thing that produces a subtly broken
			// link rather than an obvious failure.
			name:    "trailing slash is not normalized",
			baseURL: "https://admin.example.com/",
			want:    "https://admin.example.com//account/profile",
		},
		{
			name:    "empty base URL yields a relative path",
			baseURL: "",
			want:    "/account/profile",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config.GetAdminConsole().BaseURL = tc.baseURL

			got := GetProfileURL()

			assert.Equal(t, tc.want, got)
			assert.True(t, strings.HasSuffix(got, "/account/profile"))
		})
	}
}
