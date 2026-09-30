package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// /auth/issue re-checks four conditions before it mints anything, and the implicit grant signs
// against the same session the code flow does (#197, decisions 16 and 17). Each case parks a real
// ceremony on its consent screen, submits the consent, changes exactly the thing its check is about
// while the ceremony is one hop from issuing, and loads the last hop. Every one runs for a code
// ceremony and for an implicit one, because the two flows reach different issuers behind the same
// decision.

// recheckFlows are the two flows the re-checks serve. An implicit request asks for both tokens, so
// the nonce and the openid scope the ID token needs are the helper's.
var recheckFlows = []struct {
	name         string
	responseType string
}{
	{"code", "code"},
	{"implicit", "id_token token"},
}

// finishTheCeremony submits the consent and returns the last hop's URL, which is what a case
// changes the world in front of.
func finishTheCeremony(t *testing.T, parked *parkedCeremony) string {
	t.Helper()
	resp := postConsent(t, parked.httpClient, parked.consentURL, parked.consentPage, []int{0, 1, 2, 3, 4})
	defer func() { _ = resp.Body.Close() }()
	return assertRedirect(t, resp, "/auth/issue")
}

// clientAnswer is what a redirect to the client carried: the destination without its parameters,
// and the parameters, read from where the flow puts them.
func clientAnswer(t *testing.T, resp *http.Response, responseType string) (string, url.Values) {
	t.Helper()
	require.Equal(t, http.StatusFound, resp.StatusCode, "the client is answered by redirect")
	parsed, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	destination := parsed.Scheme + "://" + parsed.Host + parsed.Path
	if responseType == "code" {
		return destination, parsed.Query()
	}
	values, err := url.ParseQuery(parsed.Fragment)
	require.NoError(t, err)
	return destination, values
}

func disableTheClient(t *testing.T, parked *parkedCeremony) {
	parked.client.Enabled = false
	require.NoError(t, database.UpdateClient(context.Background(), nil, parked.client))
}

func disableTheUser(t *testing.T, parked *parkedCeremony) {
	parked.user.Enabled = false
	require.NoError(t, database.UpdateUser(context.Background(), nil, parked.user))
}

// moveTheGenerationOn is a credential change reduced to the one thing /auth/issue reads: the user's
// authentication generation moves, and the session, which a real change would also end, is left
// alone, so the generation check is the only thing that can refuse the ceremony.
func moveTheGenerationOn(t *testing.T, parked *parkedCeremony) {
	tx, err := database.BeginTransaction(context.Background())
	require.NoError(t, err)
	_, err = database.IncrementUserAuthStateGeneration(context.Background(), tx, parked.user.Id)
	require.NoError(t, err)
	require.NoError(t, database.CommitTransaction(context.Background(), tx))
}

func endTheSession(t *testing.T, parked *parkedCeremony) {
	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, parked.user.Id)
	require.NoError(t, err)
	require.NotEmpty(t, sessions, "the ceremony created a session before the consent")
	for _, session := range sessions {
		require.NoError(t, database.DeleteUserSession(context.Background(), nil, session.Id))
	}
}

// A disabled client is refused on the page /auth/authorize renders for one, and the client is not
// answered: no redirect, no code, no tokens, and no error for it to read.
func TestIssue_ADisabledClientIsRefusedOnThePage(t *testing.T) {
	for _, flow := range recheckFlows {
		t.Run(flow.name, func(t *testing.T) {
			parked := parkCeremonyOnConsentScreen(t, flow.responseType, "openid", fake.LetterN(32), testCodeVerifier, nil)
			defer func() { _ = parked.consentPage.Body.Close() }()
			issueURL := finishTheCeremony(t, parked)
			disableTheClient(t, parked)

			resp := loadPage(t, parked.httpClient, issueURL)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode, "the refusal is rendered")
			assert.Empty(t, resp.Header.Get("Location"), "a disabled client is never answered")
			page := parseHTMLResponse(t, resp).Text()
			assert.Contains(t, page, "The client is disabled")

			// The context is cleared, so a reload finds nothing to resume and issues nothing.
			again := loadPage(t, parked.httpClient, issueURL)
			defer func() { _ = again.Body.Close() }()
			assert.NotContains(t, again.Header.Get("Location"), parked.redirectURI.URI,
				"the browser holds no ceremony to replay")
		})
	}
}

// A flow the operator switched off for the client while the ceremony sat on its consent screen is
// answered unauthorized_client, which the application can read, and issues nothing.
func TestIssue_AFlowSwitchedOffIsAnsweredUnauthorizedClient(t *testing.T) {
	for _, flow := range recheckFlows {
		t.Run(flow.name, func(t *testing.T) {
			parked := parkCeremonyOnConsentScreen(t, flow.responseType, "openid", fake.LetterN(32), testCodeVerifier, nil)
			defer func() { _ = parked.consentPage.Body.Close() }()
			issueURL := finishTheCeremony(t, parked)

			if flow.responseType == "code" {
				parked.client.AuthorizationCodeEnabled = false
			} else {
				off := false
				parked.client.ImplicitGrantEnabled = &off
			}
			require.NoError(t, database.UpdateClient(context.Background(), nil, parked.client))

			resp := loadPage(t, parked.httpClient, issueURL)
			defer func() { _ = resp.Body.Close() }()

			destination, params := clientAnswer(t, resp, flow.responseType)
			assert.Equal(t, parked.redirectURI.URI, destination)
			assert.Equal(t, "unauthorized_client", params.Get("error"))
			assert.Equal(t, parked.state, params.Get("state"))
			assert.Empty(t, params.Get("code"), "no code")
			assert.Empty(t, params.Get("access_token"), "no access token")
			assert.Empty(t, params.Get("id_token"), "no ID token")
		})
	}
}

// A user disabled while the ceremony waited is answered access_denied and audited.
func TestIssue_ADisabledUserIsAnsweredAccessDenied(t *testing.T) {
	for _, flow := range recheckFlows {
		t.Run(flow.name, func(t *testing.T) {
			parked := parkCeremonyOnConsentScreen(t, flow.responseType, "openid", fake.LetterN(32), testCodeVerifier, nil)
			defer func() { _ = parked.consentPage.Body.Close() }()
			issueURL := finishTheCeremony(t, parked)
			disableTheUser(t, parked)

			resp := loadPage(t, parked.httpClient, issueURL)
			defer func() { _ = resp.Body.Close() }()

			destination, params := clientAnswer(t, resp, flow.responseType)
			assert.Equal(t, parked.redirectURI.URI, destination)
			assert.Equal(t, "access_denied", params.Get("error"))
			assert.Equal(t, "The user account is disabled.", params.Get("error_description"))
			assert.Equal(t, parked.state, params.Get("state"))
			assert.Empty(t, params.Get("code"))
			assert.Empty(t, params.Get("access_token"))
		})
	}
}

// A credential changed while the ceremony waited restarts it: the person is asked for a password
// again, the client is told nothing and receives nothing.
func TestIssue_AChangedCredentialRestartsTheCeremony(t *testing.T) {
	for _, flow := range recheckFlows {
		t.Run(flow.name, func(t *testing.T) {
			parked := parkCeremonyOnConsentScreen(t, flow.responseType, "openid", fake.LetterN(32), testCodeVerifier, nil)
			defer func() { _ = parked.consentPage.Body.Close() }()
			issueURL := finishTheCeremony(t, parked)
			moveTheGenerationOn(t, parked)

			resp := loadPage(t, parked.httpClient, issueURL)
			defer func() { _ = resp.Body.Close() }()

			restart := assertRedirect(t, resp, "/auth/level1")
			assert.NotContains(t, restart, "code=")
			assert.NotContains(t, restart, "access_token")
			assert.NotContains(t, restart, parked.redirectURI.URI, "the refusal is a restart, not a response to the client")

			// A real restart: the browser is asked for a password again.
			next := loadPage(t, parked.httpClient, restart)
			defer func() { _ = next.Body.Close() }()
			assertRedirect(t, next, "/auth/pwd")
		})
	}
}

// A session ended while the ceremony waited restarts the ceremony for both flows. It was the
// implicit flow's exemption that let this through with tokens (decision 16 case 1), because the
// identifier reaches the request only while its row exists, so an implicit ceremony whose session
// had ended looked like one that never had a session.
func TestIssue_AnEndedSessionRestartsAnImplicitCeremonyAsItDoesACodeOne(t *testing.T) {
	for _, flow := range recheckFlows {
		t.Run(flow.name, func(t *testing.T) {
			parked := parkCeremonyOnConsentScreen(t, flow.responseType, "openid", fake.LetterN(32), testCodeVerifier, nil)
			defer func() { _ = parked.consentPage.Body.Close() }()
			issueURL := finishTheCeremony(t, parked)
			endTheSession(t, parked)

			resp := loadPage(t, parked.httpClient, issueURL)
			defer func() { _ = resp.Body.Close() }()

			restart := assertRedirect(t, resp, "/auth/level1")
			assert.NotContains(t, restart, "access_token", "no tokens are signed for a session that has ended")
			assert.NotContains(t, restart, "code=")
		})
	}
}

// The negative control for every case above: nothing changed, and the ceremony issues. A check that
// refused a ceremony it should not would be indistinguishable from the cases above without this.
func TestIssue_ACeremonyWithNothingChangedStillIssues(t *testing.T) {
	for _, flow := range recheckFlows {
		t.Run(flow.name, func(t *testing.T) {
			parked := parkCeremonyOnConsentScreen(t, flow.responseType, "openid", fake.LetterN(32), testCodeVerifier, nil)
			defer func() { _ = parked.consentPage.Body.Close() }()
			issueURL := finishTheCeremony(t, parked)

			resp := loadPage(t, parked.httpClient, issueURL)
			defer func() { _ = resp.Body.Close() }()

			destination, params := clientAnswer(t, resp, flow.responseType)
			assert.Equal(t, parked.redirectURI.URI, destination)
			assert.Empty(t, params.Get("error"))
			assert.Equal(t, parked.state, params.Get("state"))
			if flow.responseType == "code" {
				assert.NotEmpty(t, params.Get("code"))
			} else {
				assert.NotEmpty(t, params.Get("access_token"))
				assert.NotEmpty(t, params.Get("id_token"))
			}
		})
	}
}

// The implicit flow now reads on the transaction it signs in, and on SQLite, which the integration
// tier runs, a read on nil while that transaction holds the one connection would hang the request
// and, where the read is the claim mapper's picture lookup, drop the claim without an error. So the
// end-to-end case is a user who has a picture, signing in for profile claims in both tokens: the
// picture must be in each.
func TestIssue_AnImplicitSignInKeepsThePictureClaim(t *testing.T) {
	changeSettings(t, func(settings *models.Settings) {
		settings.IncludeOpenIDConnectClaimsInAccessToken = true
		settings.IncludeOpenIDConnectClaimsInIdToken = true
	})

	parked := parkCeremonyOnConsentScreen(t, "id_token token", "openid profile", fake.LetterN(32), testCodeVerifier, nil)
	defer func() { _ = parked.consentPage.Body.Close() }()
	require.NoError(t, database.CreateUserProfilePicture(context.Background(), nil, &models.UserProfilePicture{
		UserId:      parked.user.Id,
		Picture:     createTestPNGImage(64, 64),
		ContentType: "image/png",
	}))
	issueURL := finishTheCeremony(t, parked)

	resp := loadPage(t, parked.httpClient, issueURL)
	defer func() { _ = resp.Body.Close() }()

	_, params := clientAnswer(t, resp, "id_token token")
	require.Empty(t, params.Get("error"), "the sign-in completes: %v", params)

	wantPicture := appConfig.AuthServer.BaseURL + "/userinfo/picture/" + parked.user.Subject
	for _, name := range []string{"access_token", "id_token"} {
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(params.Get(name), claims)
		require.NoError(t, err, name)
		assert.Equal(t, wantPicture, claims["picture"], "the %s carries the picture", name)
	}
}
