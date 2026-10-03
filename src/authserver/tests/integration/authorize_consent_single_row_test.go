package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user has one consent per client, and a save replaces it and records when (#249, #115, #437).
// Before, two saves for one user and client that overlapped could each create a row, and the page
// that lists a user's consents would show the client twice with whichever scope the engine returned
// first; a save that rewrote a row left its granted date at the first grant's. Both are observed
// here through the admin API's list of the user's consents, which is what the consents page reads,
// and not by reading the table: that the engine refuses a second row, and that a loser is rerun, is
// the data tier's.

type consentFixture struct {
	client      *record.Client
	redirectUri *record.RedirectURI
	user        *record.User
	password    string
	// scope is three entries, so the consent screen offers three checkboxes: 0 is openid, 1 is
	// profile and 2 is the permission.
	scope string
}

func newConsentFixture(t *testing.T) *consentFixture {
	t.Helper()

	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          record.AcrLevel1,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))

	redirectUri := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectUri))

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))

	resource := createResource(t)
	permission := createPermission(t, resource.Id)
	assignPermissionToUser(t, user.Id, permission.Id)

	return &consentFixture{
		client: client, redirectUri: redirectUri, user: user, password: password,
		scope: "openid profile " + resource.ResourceIdentifier + ":" + permission.PermissionIdentifier,
	}
}

// reachConsentScreen signs the fixture's user in at a browser of its own, through a fresh
// authorization request, and returns that browser at the consent screen with the ceremony id its
// form carries. extraQuery is appended to the authorization request.
func (f *consentFixture) reachConsentScreen(t *testing.T, extraQuery string) (browser *http.Client, consentUrl, ceremonyId string) {
	t.Helper()

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(f.redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + fake.LetterN(43) +
		"&scope=" + url.QueryEscape(f.scope) +
		"&state=" + fake.LetterN(8) +
		"&nonce=" + fake.LetterN(8) + extraQuery

	browser = createHttpClient(t)

	resp, err := browser.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()

	location = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()

	resp = authenticateWithPassword(t, browser, location, resp, f.user.Email, f.password)
	defer func() { _ = resp.Body.Close() }()

	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()

	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()

	location = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()

	return browser, location, getCeremonyIdFromPage(t, resp)
}

// submitConsent posts the consent form ticking the given checkboxes. It reports its failures as
// errors and never through t, so a goroutine may call it.
func submitConsent(browser *http.Client, consentUrl, ceremonyId string, ticked []int) (*http.Response, error) {
	form := url.Values{}
	form.Add("ceremonyId", ceremonyId)
	for _, index := range ticked {
		form.Add(fmt.Sprintf("consent%d", index), "[on]")
	}
	form.Add("btnSubmit", "submit")

	request, err := http.NewRequest("POST", consentUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", consentUrl)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	return browser.Do(request)
}

// consentsOf is what the user holds for the client, as the admin API lists it.
func consentsOf(t *testing.T, adminToken string, userId, clientId int64) []api.UserConsentResponse {
	t.Helper()

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/admin/users/"+strconv.FormatInt(userId, 10)+"/consents", adminToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var listed api.GetUserConsentsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listed))
	var forClient []api.UserConsentResponse
	for _, consent := range listed.Consents {
		if consent.ClientId == clientId {
			forClient = append(forClient, consent)
		}
	}
	return forClient
}

// A second consent for the same client replaces the first, scope and all, and the date shown is the
// second save's. The second sign-in asks for prompt=consent because the first consent already
// covers the scope, and the screen is otherwise skipped.
func TestAuthorize_Consent_ASecondSaveReplacesTheConsentAndRefreshesItsDate(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	f := newConsentFixture(t)

	browser, consentUrl, ceremonyId := f.reachConsentScreen(t, "")
	resp, err := submitConsent(browser, consentUrl, ceremonyId, []int{0, 1, 2})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assertRedirect(t, resp, "/auth/issue")

	first := consentsOf(t, adminToken, f.user.Id, f.client.Id)
	require.Len(t, first, 1, "the first save created the user's consent for the client")
	assert.Equal(t, f.scope, first[0].Scope, "all three scopes were ticked")
	require.NotNil(t, first[0].GrantedAt)

	browser, consentUrl, ceremonyId = f.reachConsentScreen(t, "&prompt=consent")
	resp2, err := submitConsent(browser, consentUrl, ceremonyId, []int{0, 1})
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assertRedirect(t, resp2, "/auth/issue")

	second := consentsOf(t, adminToken, f.user.Id, f.client.Id)
	require.Len(t, second, 1, "the second save rewrote the consent, it did not add one")
	assert.Equal(t, first[0].Id, second[0].Id, "the same row")
	assert.Equal(t, "openid profile", second[0].Scope, "the scope is what the second save ticked: the permission the user unticked is gone")
	require.NotNil(t, second[0].GrantedAt)
	assert.Truef(t, second[0].GrantedAt.After(*first[0].GrantedAt),
		"the date shown is the second save's, %v, after the first's, %v", second[0].GrantedAt, first[0].GrantedAt)
}

// Two sign-ins of one user for one client, each at its own consent screen, both submitted at once.
// Both are accepted and move on to issuance, and the user holds one consent for the client whose
// scope is what one of them ticked.
func TestAuthorize_Consent_TwoSubmissionsAtOnceLeaveOneConsentForTheClient(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	f := newConsentFixture(t)

	// Both browsers reach the consent screen before either submits, so the two saves meet.
	ticks := [][]int{{0, 1}, {0, 1, 2}}
	browsers := make([]*http.Client, len(ticks))
	urls := make([]string, len(ticks))
	ceremonies := make([]string, len(ticks))
	for i := range ticks {
		browsers[i], urls[i], ceremonies[i] = f.reachConsentScreen(t, "")
	}

	responses := make([]*http.Response, len(ticks))
	errs := make([]error, len(ticks))
	var wg sync.WaitGroup
	for i := range ticks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses[i], errs[i] = submitConsent(browsers[i], urls[i], ceremonies[i], ticks[i])
		}()
	}
	wg.Wait()

	for i := range ticks {
		require.NoErrorf(t, errs[i], "submission %d", i)
		defer func() { _ = responses[i].Body.Close() }()
		assertRedirect(t, responses[i], "/auth/issue")
	}

	held := consentsOf(t, adminToken, f.user.Id, f.client.Id)
	require.Len(t, held, 1, "one consent for the user and client however the two saves overlapped")
	assert.Containsf(t, []string{"openid profile", f.scope}, held[0].Scope,
		"the scope is what one of the two ticked, never a mixture; got %q", held[0].Scope)
}
