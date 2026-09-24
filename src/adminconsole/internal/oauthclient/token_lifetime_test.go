package oauthclient_test

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/oauth"
)

var lifetimeNow = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// Decisions 12 and 16: the access token's lifetime comes from expires_in, turned into a clock time
// on receipt, and a missing or non-positive one is the unknown expiry 0.
func TestExpiresAt(t *testing.T) {
	testCases := []struct {
		name     string
		response *oauth.TokenResponse
		want     int64
	}{
		{"positive", &oauth.TokenResponse{ExpiresIn: 300}, lifetimeNow.Unix() + 300},
		{"zero, which is also how an absent one reads", &oauth.TokenResponse{ExpiresIn: 0}, 0},
		{"negative", &oauth.TokenResponse{ExpiresIn: -1}, 0},
		{"overflowing saturates", &oauth.TokenResponse{ExpiresIn: math.MaxInt64}, math.MaxInt64},
		{"nil response", nil, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, oauthclient.ExpiresAt(tc.response, lifetimeNow))
		})
	}
}

// Due from 30 seconds before the recorded expiry, inclusive, and never for the unknown expiry.
func TestRefreshDue(t *testing.T) {
	testCases := []struct {
		name      string
		expiresAt int64
		now       time.Time
		want      bool
	}{
		{"unknown expiry, however late", 0, lifetimeNow.Add(100 * 365 * 24 * time.Hour), false},
		{"31 seconds left", lifetimeNow.Unix() + 31, lifetimeNow, false},
		// The margin's edge.
		{"30 seconds left", lifetimeNow.Unix() + 30, lifetimeNow, true},
		{"1 second left", lifetimeNow.Unix() + 1, lifetimeNow, true},
		{"expired an hour ago", lifetimeNow.Unix() - 3600, lifetimeNow, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, oauthclient.RefreshDue(tc.expiresAt, tc.now))
		})
	}
}

// RFC 6749 sections 3.3 and 6: the response's scope when it carries one, else the fallback.
func TestEffectiveScope(t *testing.T) {
	testCases := []struct {
		name          string
		responseScope string
		fallback      string
		want          string
	}{
		{"response scope present", "openid authserver:manage", "openid profile", "openid authserver:manage"},
		{"response scope empty", "", "openid profile", "openid profile"},
		{"both empty", "", "", ""},
		{"whitespace-only response scope is kept", " ", "openid profile", " "},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, oauthclient.EffectiveScope(tc.responseScope, tc.fallback))
		})
	}
}
