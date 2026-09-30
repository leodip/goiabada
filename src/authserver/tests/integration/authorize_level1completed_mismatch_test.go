package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
)

// /auth/level1completed reached before the password answers the state mismatch page at 400, like
// every other gated step. It answered a 500 page with a stack until #436 put it behind the one gate
// the other ten use (#248 part 1). The refusal leaves the ceremony where it was, so the password
// form rendered before it still posts and the sign-in completes with a code.
func TestAuthorize_Level1CompletedInTheWrongStateAnswersTheMismatchPage(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          models.AcrLevel1,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestState := fake.LetterN(8)

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + fake.LetterN(43) +
		"&scope=" + url.QueryEscape("openid") +
		"&state=" + requestState +
		"&nonce=" + fake.LetterN(8)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	pwdLocation := assertRedirect(t, resp, "/auth/pwd")
	pwdPage := loadPage(t, httpClient, pwdLocation)
	defer func() { _ = pwdPage.Body.Close() }()

	// The ceremony is on level1_password. /auth/level1completed accepts
	// level1_password_completed and level1_existing_session only.
	mismatch := loadPage(t, httpClient, stepURLOfTheSameCeremony(t, pwdLocation, "/auth/level1completed"))
	defer func() { _ = mismatch.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, mismatch.StatusCode,
		"a step reached out of order is a client's mistake, not a server fault")
	assertStateMismatchPage(t, mismatch)

	resp = authenticateWithPassword(t, httpClient, pwdLocation, pwdPage, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, user.Id, code.User.Id)
}
