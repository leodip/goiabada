package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The policy a browser receives from the running server (#816): a page and the stylesheet it
// links are sent script-src, style-src, img-src and font-src limited to the server itself, data:
// images beside it, and the three directives that refuse plugins, a <base> and framing. The
// Turnstile forms' widened policy is held in auth_pwd_turnstile_test.go.

const plainPolicy = "script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

func TestSecurityHeaders_ThePagesAndTheirFilesCarryThePolicy(t *testing.T) {
	form := reachPasswordForm(t)

	page := loadPage(t, form.httpClient, form.pwdURL)
	_ = page.Body.Close()
	require.Equal(t, http.StatusOK, page.StatusCode, "the sign-in form, the challenge off")
	assert.Equal(t, []string{plainPolicy}, page.Header.Values("Content-Security-Policy"))

	stylesheet := loadPage(t, form.httpClient, appConfig.AuthServer.BaseURL+"/static/main.css")
	_ = stylesheet.Body.Close()
	require.Equal(t, http.StatusOK, stylesheet.StatusCode)
	assert.Equal(t, []string{plainPolicy}, stylesheet.Header.Values("Content-Security-Policy"))
}
