package integrationtests

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/require"
)

// TestCsrf_MiddlewareIsRegistered makes the one claim the unit tables in
// src/core/middleware/middleware_csrf_test.go cannot: that MiddlewareCsrf is actually mounted on
// the running auth server. Those tables pass perfectly against a middleware nobody wired up, and
// #155 rewrote both server wirings, so a deleted Use() line is exactly the regression they would
// miss.
//
// The two halves are otherwise identical requests. That pairing is the point: /auth/pwd has several
// ways to refuse a request, so a lone 403 would prove nothing about CSRF. Varying only the origin
// headers is what makes the rejection attributable to the origin check.
//
// Neither half authenticates, and neither needs to. The CSRF middleware runs before any handler, so
// the refused half never reaches one, and the allowed half only has to come back as something other
// than the CSRF 403.
func TestCsrf_MiddlewareIsRegistered(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/pwd"

	post := func(t *testing.T, headers map[string]string) *http.Response {
		t.Helper()

		form := url.Values{
			"email":    {"someone@example.com"},
			"password": {"whatever"},
		}
		req, err := http.NewRequest(http.MethodPost, destUrl, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for name, value := range headers {
			req.Header.Set(name, value)
		}

		resp, err := createHttpClient(t).Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("a cross-site POST is refused by the CSRF middleware", func(t *testing.T) {
		resp := post(t, map[string]string{
			"Origin":         "https://relying-party.example",
			"Sec-Fetch-Site": "cross-site",
		})
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusForbidden, resp.StatusCode,
			"a cross-site POST to a cookie-authenticated form endpoint must be refused; "+
				"if this is not a 403, MiddlewareCsrf is no longer registered on the auth server")

		// The body is MiddlewareCsrf's own message, which is what attributes the 403 to the
		// origin check rather than to any handler further down. It is read from the catalog
		// rather than repeated here, and this request sends no Accept-Language, so the running
		// server answers the English entry.
		//
		// The refusal's reason used to be interpolated after a "Forbidden - " prefix. It is
		// asserted absent now: it describes the deployment's own origin handling and, to a
		// genuine attacker, names the check that refused them. It goes to the server log.
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, i18n.T(context.Background(), "error.csrf_refused"), strings.TrimSpace(string(raw)),
			"the 403 must be the CSRF middleware's, got body %q", string(raw))
	})

	t.Run("the same POST without origin headers is not refused by the CSRF middleware", func(t *testing.T) {
		resp := post(t, nil)
		defer func() { _ = resp.Body.Close() }()

		// Deliberately not asserting a specific status. This request carries no auth context, so
		// what the handler does with it is that handler's business and not this test's; all that
		// matters is that the origin headers alone decided the case above.
		require.NotEqual(t, http.StatusForbidden, resp.StatusCode,
			"a request with no Origin and no Sec-Fetch-Site is not a browser cross-origin request "+
				"and must pass the origin check")
	})
}
