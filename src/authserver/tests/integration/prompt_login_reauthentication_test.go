package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A ceremony that verifies the password itself is a new authentication, not an extension of the
// browser's session (#537). OIDC Core 1.0 section 3.1.2.3: with prompt=login the server "MUST
// reauthenticate the End-User even if the End-User is already authenticated", and section 2 has acr,
// amr and auth_time all describe "the authentication". So prompt=login:
//
//   - asks for every factor the requested level needs, whatever the session already gave;
//   - leaves the session holding that authentication's level, methods and time, which can be lower
//     than what the session held, so a later request at the higher level steps up again.
//
// Until #537 the session's code counted: prompt=login at level 3 over a level 3 session asked only
// for the password and issued acr level 3 beside amr ["pwd"], and the session kept level 3 with its
// methods cut to "pwd", so every later SSO token contradicted itself (#239 finding F4).
//
// Each test uses its own user, because a TOTP step can be spent once per user and only a step
// later than the last one is accepted: the first code is the current step and the second the next,
// which the server's one-step window accepts.

// reauthFixture is a user with an authenticator, and a client at each end of the ACR range.
type reauthFixture struct {
	user          *record.User
	password      string
	otpSecret     string
	level3Client  *record.Client
	level3URI     *record.RedirectURI
	level1Client  *record.Client
	level1URI     *record.RedirectURI
	otpStepsTaken int
}

func newReauthFixture(t *testing.T) *reauthFixture {
	t.Helper()
	ctx := context.Background()
	fx := &reauthFixture{password: fake.Password(12)}

	newClient := func(level record.AcrLevel) (*record.Client, *record.RedirectURI) {
		client := &record.Client{
			ClientIdentifier:         "reauth-" + fake.LetterN(8),
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			DefaultAcrLevel:          level,
		}
		require.NoError(t, database.CreateClient(ctx, nil, client))
		redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
		require.NoError(t, database.CreateRedirectURI(ctx, nil, redirectURI))
		return client, redirectURI
	}
	fx.level3Client, fx.level3URI = newClient(record.AcrLevel2Mandatory)
	fx.level1Client, fx.level1URI = newClient(record.AcrLevel1)

	email := fake.Email()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: email})
	require.NoError(t, err)
	fx.otpSecret = key.Secret()
	passwordHashed, err := passwordhash.Hash(fx.password)
	require.NoError(t, err)
	fx.user = &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              email,
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, fx.otpSecret),
		OTPEnabled:         true,
	}
	require.NoError(t, database.CreateUser(ctx, nil, fx.user))
	return fx
}

// nextOtpCode is a code for a step later than any this user has spent: the current step first, then
// the next one. A third would fall outside the server's window, so no test asks for one.
func (fx *reauthFixture) nextOtpCode(t *testing.T) string {
	t.Helper()
	require.Less(t, fx.otpStepsTaken, 2, "a third code would be outside the one-step window")
	code, err := totp.GenerateCode(fx.otpSecret, time.Now().Add(time.Duration(fx.otpStepsTaken)*30*time.Second))
	require.NoError(t, err)
	fx.otpStepsTaken++
	return code
}

// signIn runs one authorization request in browser through to the code it issues, entering the
// password when the password page is shown and a code when the code page is shown, and answers the
// code as stored and the steps the user was asked for, in order ("pwd", "otp").
func (fx *reauthFixture) signIn(t *testing.T, browser *http.Client, client *record.Client,
	redirectURI *record.RedirectURI, prompt string) (*record.Code, []string) {
	t.Helper()

	authorizeURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code&code_challenge_method=S256&code_challenge=" + fake.LetterN(43) +
		"&scope=" + url.QueryEscape("openid") + "&state=" + fake.LetterN(8) + "&nonce=" + fake.LetterN(8)
	if prompt != "" {
		authorizeURL += "&prompt=" + prompt
	}

	steps := []string{}
	resp := loadPage(t, browser, authorizeURL)
	for range 20 {
		_ = resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode, "steps so far: %v", steps)
		location := resp.Header.Get("Location")
		if strings.HasPrefix(location, redirectURI.URI) {
			parsed, err := url.Parse(location)
			require.NoError(t, err)
			require.Empty(t, parsed.Query().Get("error"), "the sign-in was refused: %s", location)
			return loadCodeFromDatabase(t, parsed.Query().Get("code")), steps
		}
		parsed, err := url.Parse(location)
		require.NoError(t, err)
		page := loadPage(t, browser, location)
		switch parsed.Path {
		case "/auth/pwd":
			steps = append(steps, "pwd")
			resp = authenticateWithPassword(t, browser, location, page, fx.user.Email, fx.password)
			_ = page.Body.Close()
		case "/auth/otp":
			steps = append(steps, "otp")
			resp = authenticateWithOtp(t, browser, location, page, fx.nextOtpCode(t))
			_ = page.Body.Close()
		default:
			resp = page
		}
	}
	t.Fatalf("the sign-in did not reach the client's redirect URI; steps so far: %v", steps)
	return nil, nil
}

// reauthSession loads the session a code was issued under, as stored.
func reauthSession(t *testing.T, code *record.Code) *record.UserSession {
	t.Helper()
	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, code.SessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session, "the code names a session that does not exist")
	return session
}

// prompt=login at level 3 over the user's own level 3 session asks for the code again, and the code
// it issues says pwd and otp at a fresh auth_time, all of it about this sign-in.
func TestPromptLogin_AtLevel3OverALevel3SessionAsksForTheCodeAgain(t *testing.T) {
	fx := newReauthFixture(t)
	browser := createHttpClient(t)

	first, steps := fx.signIn(t, browser, fx.level3Client, fx.level3URI, "")
	require.Equal(t, []string{"pwd", "otp"}, steps)
	require.Equal(t, record.AcrLevel2Mandatory, first.AcrLevel)

	second, steps := fx.signIn(t, browser, fx.level3Client, fx.level3URI, "login")

	assert.Equal(t, []string{"pwd", "otp"}, steps,
		"prompt=login is a new authentication: the session's earlier code does not count (#537)")
	assert.Equal(t, record.AcrLevel2Mandatory, second.AcrLevel)
	assert.Equal(t, "pwd otp", second.AuthMethods)
	assert.False(t, second.AuthenticatedAt.Before(first.AuthenticatedAt), "auth_time is this sign-in's")

	assert.Equal(t, first.SessionIdentifier, second.SessionIdentifier,
		"the session is kept, so other clients' session-bound grants are not cut off")
	session := reauthSession(t, second)
	assert.Equal(t, record.AcrLevel2Mandatory, session.AcrLevel)
	assert.Equal(t, "pwd otp", session.AuthMethods)
	assert.True(t, session.AuthTime.Equal(second.AuthenticatedAt), "the session's auth time is this sign-in's")
}

// prompt=login at a level 1 client over a level 3 session asks for the password alone, which is all
// level 1 needs, and the session then holds that authentication: level 1, "pwd". The next request at
// level 3 is a step-up and asks for the code. Keeping level 3 beside "pwd" was #239 F4's
// contradiction, and merging the methods back to "pwd otp" beside the fresh auth time would claim a
// code nobody entered at that time (PR #238 decision 9).
func TestPromptLogin_AtALowerLevelReplacesTheSessionsAuthentication(t *testing.T) {
	fx := newReauthFixture(t)
	browser := createHttpClient(t)

	first, steps := fx.signIn(t, browser, fx.level3Client, fx.level3URI, "")
	require.Equal(t, []string{"pwd", "otp"}, steps)

	lower, steps := fx.signIn(t, browser, fx.level1Client, fx.level1URI, "login")

	assert.Equal(t, []string{"pwd"}, steps)
	assert.Equal(t, record.AcrLevel1, lower.AcrLevel, "acr is the level this authentication reached")
	assert.Equal(t, "pwd", lower.AuthMethods)
	assert.Equal(t, first.SessionIdentifier, lower.SessionIdentifier)
	session := reauthSession(t, lower)
	assert.Equal(t, record.AcrLevel1, session.AcrLevel)
	assert.Equal(t, "pwd", session.AuthMethods)
	assert.True(t, session.AuthTime.Equal(lower.AuthenticatedAt))

	stepUp, steps := fx.signIn(t, browser, fx.level3Client, fx.level3URI, "")

	assert.Equal(t, []string{"otp"}, steps, "SSO keeps the password, and level 3 steps up for the code")
	assert.Equal(t, record.AcrLevel2Mandatory, stepUp.AcrLevel)
	assert.Equal(t, "pwd otp", stepUp.AuthMethods)
	session = reauthSession(t, stepUp)
	assert.Equal(t, record.AcrLevel2Mandatory, session.AcrLevel)
	assert.Equal(t, "pwd otp", session.AuthMethods)
}

// SSO, with no prompt, never lowers a session: a level 1 client reusing a level 3 session asks for
// nothing, gets the session's level and methods, and leaves the session as it was. This is the path
// that kept its behaviour through #537, held here beside the one that changed.
func TestSSO_AtALowerLevelLeavesTheSessionAsItWas(t *testing.T) {
	fx := newReauthFixture(t)
	browser := createHttpClient(t)

	first, steps := fx.signIn(t, browser, fx.level3Client, fx.level3URI, "")
	require.Equal(t, []string{"pwd", "otp"}, steps)

	sso, steps := fx.signIn(t, browser, fx.level1Client, fx.level1URI, "")

	assert.Empty(t, steps)
	assert.Equal(t, record.AcrLevel2Mandatory, sso.AcrLevel, "acr is the session's, which is higher than the target")
	assert.Equal(t, "pwd otp", sso.AuthMethods)
	assert.True(t, sso.AuthenticatedAt.Equal(first.AuthenticatedAt), "auth_time is the sign-in that earned the session")
	session := reauthSession(t, sso)
	assert.Equal(t, record.AcrLevel2Mandatory, session.AcrLevel)
	assert.Equal(t, "pwd otp", session.AuthMethods)
}
