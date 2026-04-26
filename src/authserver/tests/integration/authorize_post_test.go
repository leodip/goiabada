package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

// Verifies OIDC Core 3.1.2.1: the authorization endpoint MUST support POST
// (form body) in addition to GET. Issues a real cross-origin POST mirroring
// what the OIDC conformance suite (oidcc-ensure-post-request-succeeds) sends,
// and asserts the server redirects into the auth flow rather than rejecting
// with 403 origin invalid.
func TestAuthorize_PostRequest(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"no trailing slash", "/auth/authorize"},
		{"trailing slash", "/auth/authorize/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &models.Client{
				ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
				Enabled:                  true,
				AuthorizationCodeEnabled: true,
				ConsentRequired:          false,
				DefaultAcrLevel:          enums.AcrLevel1,
			}
			if err := database.CreateClient(nil, client); err != nil {
				t.Fatal(err)
			}

			redirectUri := &models.RedirectURI{
				ClientId: client.Id,
				URI:      gofakeit.URL(),
			}
			if err := database.CreateRedirectURI(nil, redirectUri); err != nil {
				t.Fatal(err)
			}

			form := url.Values{}
			form.Set("client_id", client.ClientIdentifier)
			form.Set("redirect_uri", redirectUri.URI)
			form.Set("response_type", "code")
			form.Set("code_challenge_method", "S256")
			form.Set("code_challenge", gofakeit.LetterN(43))
			form.Set("scope", "openid profile")
			form.Set("state", gofakeit.LetterN(8))
			form.Set("nonce", gofakeit.LetterN(8))

			destURL := config.GetAuthServer().BaseURL + tc.path

			req, err := http.NewRequest(http.MethodPost, destURL, strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// Foreign Origin matches what the OIDC conformance suite sends; this
			// is the trigger for the gorilla/csrf 403 we are guarding against.
			req.Header.Set("Origin", "https://www.certification.openid.net")

			httpClient := createHttpClient(t)
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			assertRedirect(t, resp, "/auth/level1")
		})
	}
}
