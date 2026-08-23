package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The authentication target is fixed when the request is accepted (#240)
// =============================================================================
//
// /auth/level1completed, /auth/level2 and /auth/completed each reload the client, so before the
// snapshot existed the level a ceremony had to reach was a live read of a mutable row at three
// separate points in one ceremony. An administrator editing default_acr_level while somebody was
// mid-ceremony therefore redefined, retroactively, what that ceremony had been required to do.
//
// This is the case that could not be caught anywhere else: every unit case can pass with
// HandleAuthorizeGet never calling SetTargetAcrLevel at all, because they call the reader and the
// writer directly. Only a real ceremony proves the snapshot is taken and carried.

// TestAcrSnapshot_ClientRaisedMidCeremonyDoesNotElevateTheAcr drives a password-only ceremony on a
// level1 client and raises that client to level2_mandatory in the gap between the step-up decision
// and the code being stamped.
//
// Without the snapshot /auth/completed reads the raised row, hands level2_mandatory to
// BumpUserSession and SetAcrLevel, and the authorization code goes out claiming
// acr: urn:goiabada:level2_mandatory over amr: ["pwd"]. No second factor was ever presented, and
// OIDC Core section 2 defines acr as the class "the authentication performed satisfied", so that
// claim is false in the direction a relying party doing OIDC Core 3.1.2.2's check trusts.
//
// The raise is applied between two hops the test drives itself, which is why the ceremony is
// stepped through here rather than run by one of the suite's sign-in helpers: the whole subject of
// the case is what happens in the gap between them.
func TestAcrSnapshot_ClientRaisedMidCeremonyDoesNotElevateTheAcr(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	require.NoError(t, database.CreateClient(nil, client))

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	require.NoError(t, database.CreateRedirectURI(nil, redirectUri))

	password := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	// No OTP: this user has no second factor to present, so an acr naming one can only have come
	// from the client row rather than from anything the ceremony did.
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(nil, user))

	httpClient := createHttpClient(t)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)

	loc := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, loc)

	loc = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, loc)

	// Held rather than closed: the submission reads the ceremony id out of this page (#79).
	pwdPage := resp
	resp = authenticateWithPassword(t, httpClient, loc, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()

	loc = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, loc)

	// The step-up decision has now been taken against the level1 the request was accepted at, and
	// it is the only hop that could have sent this ceremony to a second factor.
	loc = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	// The administrator tightens the client's policy, mid-ceremony.
	client.DefaultAcrLevel = enums.AcrLevel2Mandatory
	require.NoError(t, database.UpdateClient(nil, client))

	resp = loadPage(t, httpClient, loc)
	loc = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()

	resp = loadPage(t, httpClient, loc)
	defer func() { _ = resp.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp)
	require.NotEmpty(t, codeVal, "the ceremony should still complete; the raise applies to later requests")

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel,
		"the acr must describe the authentication this ceremony performed, not the policy that "+
			"replaced the one it was accepted under")
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods,
		"no second factor was presented, which is what makes a level2_mandatory acr a false claim")

	// The session the ceremony bound to carries the same level, so the next request on this browser
	// is judged against what actually happened here too. A raise reaches that request through the
	// client's row, where it now sits, and steps the user up properly.
	sessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, enums.AcrLevel1.String(), sessions[0].AcrLevel,
		"the session records the level reached, so a later step-up is decided from the truth")
}
