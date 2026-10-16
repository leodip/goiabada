package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A password POST that finds no ceremony is redirected to the admin console's account page, on
// another origin, while its body carries the password. RFC 9700 section 4.12 is about exactly that
// request: the redirect is a 303, so the browser follows it with a GET and sends the body nowhere.
// The same step reached by a GET keeps its 302 (#576, decision 6).
func TestCeremony_APasswordPostFindingNoCeremonyIs303(t *testing.T) {
	pwdURL := appConfig.AuthServer.BaseURL + "/auth/pwd"
	accountPage := appConfig.AdminConsole.BaseURL + "/account/profile"

	t.Run("POST", func(t *testing.T) {
		form := url.Values{
			"email":      {"nobody@example.com"},
			"password":   {"not-a-real-password"},
			"ceremonyId": {"no-such-ceremony"},
		}
		request, err := http.NewRequest(http.MethodPost, pwdURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

		resp, err := createHttpClient(t).Do(request)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, accountPage, resp.Header.Get("Location"))
	})

	t.Run("GET", func(t *testing.T) {
		resp := loadPage(t, createHttpClient(t), pwdURL)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, accountPage, resp.Header.Get("Location"))
	})
}
