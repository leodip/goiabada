package integrationtests

import (
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// The two refusals in /auth/completed leave the browser holding an auth context in the
// authentication_completed state unless the clear reaches it, and that state is one the handler
// accepts: replaying the refused ceremony re-runs the same checks, refuses the client a second time
// and re-bumps the session. Both tests below drive a real ceremony on a real cookie jar, take the
// refusal, then replay GET /auth/completed and require it to land on the account profile, which is
// the shared no-context branch. On a tree where the clear runs after the response is committed the
// replay refuses again instead, so the second half of each test is what fails (#141).
//
// Both tests reassign one resp across seven hops, so each body is passed into its deferred close
// rather than read out of resp when the test returns. The bare `defer func() { _ = resp.Body.Close()
// }()` used elsewhere in this package captures the variable, so under reassignment every defer closes
// the last response and the six before it are never closed.

// TestAuthCompleted_DisabledUserRefusal_CannotBeReplayed covers the disabled-user refusal. The user
// is disabled between the /auth/level1completed and /auth/completed hops, since disabling before
// login makes /auth/pwd reject the credentials and /auth/completed is never reached.
func TestAuthCompleted_DisabledUserRefusal_CannotBeReplayed(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	completedUrl := assertRedirect(t, resp, "/auth/completed")

	// The password has already been accepted and the session exists, so the account is disabled
	// here rather than up front: this is the only window in which /auth/completed sees a disabled
	// user.
	user.Enabled = false
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resp = loadPage(t, httpClient, completedUrl)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	refusalUrl, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "access_denied", refusalUrl.Query().Get("error"))
	assert.Equal(t, "The user account is disabled.", refusalUrl.Query().Get("error_description"))
	assert.Equal(t, requestState, refusalUrl.Query().Get("state"))

	// The refusal ended the ceremony, so the auth context is gone from the browser and the replay
	// has nothing to resume: it lands on the account profile instead of refusing a second time.
	resp = loadPage(t, httpClient, completedUrl)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/account/profile", resp.Header.Get("Location"),
		"replaying the refused ceremony must not reach the auth context again")
}

// TestAuthCompleted_NoAuthorizedScopesRefusal_CannotBeReplayed covers the empty-effective-scope
// refusal. The request asks for one resource:permission scope the user does not hold, and neither
// openid nor offline_access, which FilterOutScopesWhereUserIsNotAuthorized always keeps. The
// authorize validator only checks the scope exists, so the ceremony passes validation and the
// filtering to nothing happens at /auth/completed.
func TestAuthCompleted_NoAuthorizedScopesRefusal_CannotBeReplayed(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	// Created but deliberately not assigned to the user.
	resource := createResource(t)
	permission := createPermission(t, resource.Id)
	requestScope := resource.ResourceIdentifier + ":" + permission.PermissionIdentifier

	requestState := gofakeit.LetterN(8)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	completedUrl := assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, completedUrl)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	refusalUrl, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "access_denied", refusalUrl.Query().Get("error"))
	assert.Equal(t, "The user is not authorized to access any of the requested scopes",
		refusalUrl.Query().Get("error_description"))
	assert.Equal(t, requestState, refusalUrl.Query().Get("state"))

	resp = loadPage(t, httpClient, completedUrl)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/account/profile", resp.Header.Get("Location"),
		"replaying the refused ceremony must not reach the auth context again")
}
