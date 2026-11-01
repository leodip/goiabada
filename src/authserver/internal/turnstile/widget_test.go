package turnstile_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The widget on a form's render, and Cloudflare's script admitted to that response's policy alone
// (#642 decision 9). A render that fails leaves the response's policy as it found it, so the error
// page drawn instead, which carries no widget, admits no Cloudflare script.

const (
	plainPolicy   = "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
	widenedPolicy = "script-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)

// stubRenderer records the policy each render saw and what it was bound with, and fails with err.
type stubRenderer struct {
	err     error
	policy  string
	bound   map[string]interface{}
	renders int
}

func (s *stubRenderer) RenderTemplate(w http.ResponseWriter, _ *http.Request, _, _ string, data map[string]interface{}) error {
	s.renders++
	s.policy = w.Header().Get("Content-Security-Policy")
	s.bound = data
	return s.err
}

func challengeSettings(enabled bool) *record.Settings {
	return &record.Settings{TurnstileEnabled: enabled, TurnstileSiteKey: "1x00000000000000000000AA"}
}

func TestWithWidget_ARenderWithTheChallengeOnCarriesTheWidgetAndAdmitsCloudflare(t *testing.T) {
	renderer := &stubRenderer{}
	w := httptest.NewRecorder()
	w.Header().Set("Content-Security-Policy", plainPolicy)

	err := turnstile.WithWidget(renderer, challengeSettings(true)).RenderTemplate(w,
		httptest.NewRequest(http.MethodGet, "/forgot-password", nil), "/layouts/auth_layout.html", "/forgot_password.html",
		map[string]interface{}{})

	require.NoError(t, err)
	assert.Equal(t, widenedPolicy, renderer.policy, "the form is rendered under the widened policy")
	assert.Equal(t, widenedPolicy, w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "1x00000000000000000000AA", renderer.bound["turnstileSiteKey"])
	assert.Equal(t, "https://challenges.cloudflare.com/turnstile/v0/api.js", renderer.bound["turnstileScriptURL"])
}

func TestWithWidget_AFailedRenderLeavesThePolicyAsItFoundIt(t *testing.T) {
	for _, tt := range []struct {
		name   string
		before []string
	}{
		{"the security headers' policy", []string{plainPolicy}},
		{"no policy at all", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			failure := errors.New("the template did not execute")
			renderer := &stubRenderer{err: failure}
			w := httptest.NewRecorder()
			if tt.before != nil {
				w.Header()["Content-Security-Policy"] = tt.before
			}

			err := turnstile.WithWidget(renderer, challengeSettings(true)).RenderTemplate(w,
				httptest.NewRequest(http.MethodGet, "/forgot-password", nil), "/layouts/auth_layout.html", "/forgot_password.html",
				map[string]interface{}{})

			require.ErrorIs(t, err, failure, "the caller draws the error page")
			assert.Equal(t, widenedPolicy, renderer.policy, "the form was tried under the widened policy")
			assert.Equal(t, tt.before, w.Header().Values("Content-Security-Policy"), "and the response's policy is put back")
		})
	}
}

func TestWithWidget_WithTheChallengeOffTheFormIsRenderedAsItIs(t *testing.T) {
	renderer := &stubRenderer{}
	w := httptest.NewRecorder()
	w.Header().Set("Content-Security-Policy", plainPolicy)
	bind := map[string]interface{}{}

	require.NoError(t, turnstile.WithWidget(renderer, challengeSettings(false)).RenderTemplate(w,
		httptest.NewRequest(http.MethodGet, "/forgot-password", nil), "/layouts/auth_layout.html", "/forgot_password.html", bind))

	assert.Equal(t, 1, renderer.renders)
	assert.Equal(t, plainPolicy, w.Header().Get("Content-Security-Policy"))
	assert.NotContains(t, bind, "turnstileSiteKey")
	assert.NotContains(t, bind, "turnstileScriptURL")
}
