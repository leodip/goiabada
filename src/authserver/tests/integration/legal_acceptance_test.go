package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The acceptance step (#622, decisions 7 and 8): a browser sign-in to an app, once the user is
// authenticated and before consent and any token, lists the must-accept documents the user owes
// for that app, each with an unticked box. Accept records the versions shown; a box left unticked
// records nothing and shows the step again; Decline answers the app access_denied and keeps the
// session. A new version is asked again, a single sign-on is asked too, prompt=none is answered
// interaction_required, the password grant is refused with invalid_grant until the user accepts in
// the browser, a refresh keeps working, and the admin console's own sign-in is never asked. A
// retired document is asked of nobody until it is restored, and an app a published document gains
// asks its users at their next sign-in there, with no new version, but not a user who accepted the
// document on another app.
//
// Every document here applies to selected apps with a client of the test's own, so no other test's
// sign-in owes it, but for the admin console's, which needs one for all apps and retires it before
// it ends.

// legalAcceptanceState is the state every request here carries.
const legalAcceptanceState = "legal-acceptance-state"

// The answers the step and the paths that cannot show it give, as the agreement words them.
const (
	declinedDescription      = "The user declined a required legal document"
	silentOwedDescription    = "Acceptance of a legal document is required"
	passwordGrantDescription = "The user has not accepted a legal document this app requires. " +
		"Sign in to the app in a browser to accept it, then try again."
)

// legalAcceptanceFixture is an app of the test's own, a confidential client with consent off and
// the authorization code flow on, and a user with a password.
type legalAcceptanceFixture struct {
	client       *record.Client
	clientSecret string
	redirectURI  string
	user         *record.User
	password     string
	adminToken   string
}

func newLegalAcceptanceApp(t *testing.T, user *record.User, password, adminToken string) *legalAcceptanceFixture {
	t.Helper()
	clientSecret := fake.LetterN(32)
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	ropc := true
	client := &record.Client{
		ClientIdentifier:                        "legal-acceptance-" + strings.ToLower(fake.LetterN(10)),
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropc,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         record.AcrLevel1,
		ClientSecretEncrypted:                   clientSecretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	redirectURI := "https://" + client.ClientIdentifier + ".example.com/callback"
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
		&record.RedirectURI{ClientId: client.Id, URI: redirectURI}))
	return &legalAcceptanceFixture{client: client, clientSecret: clientSecret, redirectURI: redirectURI,
		user: user, password: password, adminToken: adminToken}
}

func newLegalAcceptanceFixture(t *testing.T) *legalAcceptanceFixture {
	t.Helper()
	adminToken, _ := createAdminClientWithToken(t)
	user, password := newLegalAcceptanceUser(t)
	return newLegalAcceptanceApp(t, user, password, adminToken)
}

func newLegalAcceptanceUser(t *testing.T) (*record.User, string) {
	t.Helper()
	password := fake.Password(12)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user, password
}

// withUser answers the fixture's app with another user signing in to it.
func (f *legalAcceptanceFixture) withUser(user *record.User, password string) *legalAcceptanceFixture {
	other := *f
	other.user, other.password = user, password
	return &other
}

// acceptAll signs the fixture's user in to its app in browser, accepts every document the step
// lists, and asserts the app gets its code.
func (f *legalAcceptanceFixture) acceptAll(t *testing.T, browser *http.Client) {
	t.Helper()
	page, stepURL := toStep(t, browser, f.signInToCompleted(t, browser))
	_, documents := readStep(t, page)
	f.assertCodeIssued(t, browser, postStep(t, browser, stepURL, page, versionsOf(documents), false))
	_ = page.Body.Close()
}

// mustAcceptFor publishes a must-accept document for the fixture's app alone and answers its id and
// short name.
func (f *legalAcceptanceFixture) mustAcceptFor(t *testing.T, prefix, title string) (int64, string) {
	t.Helper()
	shortName := legalShortName(prefix)
	id := createLegalDocumentOverAPI(t, f.adminToken, "must_accept", shortName, title, "Be nice to "+title+".")
	status, body := setApps(t, f.adminToken, id, "selected_apps", []int64{f.client.Id}, []int64{})
	require.Equal(t, http.StatusOK, status, "apps: %v", body)
	status, body, _ = legalCall(t, f.adminToken, http.MethodPost, legalPath(id, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "publish: %v", body)
	return id, shortName
}

// versionId answers the id of version n of a document.
func versionId(t *testing.T, documentId int64, n int) int64 {
	t.Helper()
	version, err := database.GetLegalDocumentVersion(context.Background(), nil, documentId, n)
	require.NoError(t, err)
	require.NotNil(t, version, "version %d of document %d", n, documentId)
	return version.Id
}

// acceptedVersionIds answers the version ids the user has accepted, in the order they were stored.
func acceptedVersionIds(t *testing.T, userId int64) []int64 {
	t.Helper()
	acceptances, err := database.GetLegalDocumentAcceptancesByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	ids := []int64{}
	for _, acceptance := range acceptances {
		ids = append(ids, acceptance.LegalDocumentVersionId)
	}
	return ids
}

// link is an authorization request from the fixture's app for openid, with extra appended as it is.
func (f *legalAcceptanceFixture) link(extra string) string {
	return appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(f.redirectURI) +
		"&response_type=code" +
		"&scope=openid" +
		"&state=" + legalAcceptanceState +
		"&nonce=" + fake.LetterN(8) +
		"&code_challenge_method=S256&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier) +
		extra
}

// signInToCompleted follows the fixture's link in browser through the password page and answers
// /auth/completed's response. The caller closes it.
func (f *legalAcceptanceFixture) signInToCompleted(t *testing.T, browser *http.Client) *http.Response {
	t.Helper()
	resp, err := browser.Get(f.link(""))
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	pwdPage := loadPage(t, browser, location)
	resp = authenticateWithPassword(t, browser, location, pwdPage, f.user.Email, f.password)
	_ = pwdPage.Body.Close()
	location = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	return loadPage(t, browser, location)
}

// ssoToCompleted follows the fixture's link in a browser that holds a session, through the session's
// shortcut, and answers /auth/completed's response. The caller closes it.
func (f *legalAcceptanceFixture) ssoToCompleted(t *testing.T, browser *http.Client) *http.Response {
	t.Helper()
	resp, err := browser.Get(f.link(""))
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	return loadPage(t, browser, location)
}

// toStep answers the step's page, which completed must redirect to, and its address.
func toStep(t *testing.T, browser *http.Client, completed *http.Response) (*http.Response, string) {
	t.Helper()
	location := assertRedirect(t, completed, "/auth/legal-acceptance")
	_ = completed.Body.Close()
	page := loadPage(t, browser, location)
	require.Equal(t, http.StatusOK, page.StatusCode, "the step is a page")
	return page, location
}

// stepDocument is one document the step lists.
type stepDocument struct {
	title, href, version string
	ticked               bool
}

// readStep answers the documents a step page lists, in its order, and re-buffers the body.
func readStep(t *testing.T, page *http.Response) (*goquery.Document, []stepDocument) {
	t.Helper()
	body, err := io.ReadAll(page.Body)
	require.NoError(t, err)
	page.Body = io.NopCloser(strings.NewReader(string(body)))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	require.NoError(t, err)
	documents := []stepDocument{}
	doc.Find(`form input[type="checkbox"][name="legalDocument"]`).Each(func(_ int, box *goquery.Selection) {
		row := box.Closest("label")
		link := row.Find("a")
		href, _ := link.Attr("href")
		value, _ := box.Attr("value")
		_, ticked := box.Attr("checked")
		documents = append(documents, stepDocument{
			title: strings.TrimSpace(link.Text()), href: href, version: value, ticked: ticked,
		})
	})
	return doc, documents
}

// postStep submits the step's form as a browser on page would, ticking the boxes whose values are
// in ticked, with Accept, or with Decline when decline is set.
func postStep(t *testing.T, browser *http.Client, stepURL string, page *http.Response, ticked []string,
	decline bool) *http.Response {
	t.Helper()
	doc, _ := readStep(t, page)
	form := url.Values{}
	form.Set("ceremonyId", getCeremonyIdFromPage(t, page))
	doc.Find(`form input[type="hidden"][name="shownVersion"]`).Each(func(_ int, s *goquery.Selection) {
		value, _ := s.Attr("value")
		form.Add("shownVersion", value)
	})
	for _, value := range ticked {
		form.Add("legalDocument", value)
	}
	if decline {
		form.Set("btnDecline", "decline")
	} else {
		form.Set("btnAccept", "accept")
	}
	postURL := stepURL
	if i := strings.Index(postURL, "?"); i >= 0 {
		postURL = postURL[:i]
	}
	request, err := http.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", stepURL)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	resp, err := browser.Do(request)
	require.NoError(t, err)
	return resp
}

// versionsOf answers the version values of the documents.
func versionsOf(documents []stepDocument) []string {
	values := []string{}
	for _, d := range documents {
		values = append(values, d.version)
	}
	return values
}

// assertCodeIssued follows a redirect to /auth/issue and asserts the app got a code.
func (f *legalAcceptanceFixture) assertCodeIssued(t *testing.T, browser *http.Client, resp *http.Response) {
	t.Helper()
	location := assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	redirect, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, f.redirectURI, redirect.Scheme+"://"+redirect.Host+redirect.Path, "back to the app")
	assert.NotEmpty(t, redirect.Query().Get("code"), "the app gets a code")
	assert.Equal(t, legalAcceptanceState, redirect.Query().Get("state"))
}

// appRedirect answers the query of a redirect to the fixture's app: 302 from a GET, 303 from a
// submitted form.
func (f *legalAcceptanceFixture) appRedirect(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode)
	redirect, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, f.redirectURI, redirect.Scheme+"://"+redirect.Host+redirect.Path, "back to the app: %s", redirect)
	return redirect.Query()
}

// latestAuditDetails answers the details of the latest audit event of the type, decoded, or nil.
func latestAuditDetails(t *testing.T, eventType string) map[string]any {
	t.Helper()
	logs, _, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 1, eventType, "")
	require.NoError(t, err)
	if len(logs) == 0 {
		return nil
	}
	details := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(logs[0].Details), &details))
	return details
}

// detailNumber answers a number in an audit event's decoded details.
func detailNumber(t *testing.T, details map[string]any, key string) int64 {
	t.Helper()
	number, ok := details[key].(float64)
	require.True(t, ok, "%s is a number: %v", key, details)
	return int64(number)
}

func TestLegalAcceptance_ASignInWithADocumentOwedLandsOnTheStepAndAcceptRecordsTheVersion(t *testing.T) {
	requireDatabaseAuditLogs(t)
	f := newLegalAcceptanceFixture(t)
	termsId, terms := f.mustAcceptFor(t, "terms", "Shop terms")
	// A notice for the same app is for information, so the step never lists it.
	publishedForApps(t, f.adminToken, "notice", "Shop notice", "For information.", f.client)
	browser := createHttpClient(t)

	page, stepURL := toStep(t, browser, f.signInToCompleted(t, browser))
	_, documents := readStep(t, page)
	version1 := strconv.FormatInt(versionId(t, termsId, 1), 10)
	assert.Equal(t, []stepDocument{{title: "Shop terms", href: "/legal/" + terms, version: version1}}, documents,
		"the step lists the one must-accept document, unticked, linking its public page")
	assert.Empty(t, acceptedVersionIds(t, f.user.Id), "showing the step records nothing")

	started := time.Now().UTC().Add(-time.Second)
	resp := postStep(t, browser, stepURL, page, []string{version1}, false)
	_ = page.Body.Close()
	f.assertCodeIssued(t, browser, resp)

	acceptances, err := database.GetLegalDocumentAcceptancesByUserId(context.Background(), nil, f.user.Id)
	require.NoError(t, err)
	require.Len(t, acceptances, 1, "one acceptance, of the version shown")
	assert.Equal(t, versionId(t, termsId, 1), acceptances[0].LegalDocumentVersionId)
	assertStampedSince(t, acceptances[0].AcceptedAt, started)

	details := latestAuditDetails(t, audit.EventAcceptedLegalDocument)
	require.NotNil(t, details, "the acceptance is audited")
	assert.Equal(t, f.user.Id, detailNumber(t, details, "user_id"))
	assert.Equal(t, f.client.Id, detailNumber(t, details, "client_id"))
	assert.Equal(t, termsId, detailNumber(t, details, "legal_document_id"))
	assert.Equal(t, terms, details["short_name"])
	assert.Equal(t, int64(1), detailNumber(t, details, "version"))

	// Accepted once, the next sign-in goes straight on.
	again := createHttpClient(t)
	resp = f.signInToCompleted(t, again)
	f.assertCodeIssued(t, again, resp)
}

func TestLegalAcceptance_AnUntickedBoxShowsTheStepAgainAndRecordsNothing(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	f.mustAcceptFor(t, "first", "First terms")
	f.mustAcceptFor(t, "second", "Second terms")
	browser := createHttpClient(t)

	page, stepURL := toStep(t, browser, f.signInToCompleted(t, browser))
	_, documents := readStep(t, page)
	require.Len(t, documents, 2, "both documents are listed")
	assert.Equal(t, "First terms", documents[0].title, "in the order they were created")

	resp := postStep(t, browser, stepURL, page, []string{documents[0].version}, false)
	_ = page.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the step is shown again")
	doc, redrawn := readStep(t, resp)
	assert.Equal(t, 1, doc.Find("#legal-acceptance-error").Length(), "with an error")
	assert.Equal(t, versionsOf(documents), versionsOf(redrawn), "listing the same documents")
	assert.True(t, redrawn[0].ticked, "the box ticked stays ticked")
	assert.False(t, redrawn[1].ticked)
	assert.Empty(t, acceptedVersionIds(t, f.user.Id), "nothing is recorded")

	resp2 := postStep(t, browser, stepURL, resp, versionsOf(redrawn), false)
	_ = resp.Body.Close()
	f.assertCodeIssued(t, browser, resp2)
	assert.Len(t, acceptedVersionIds(t, f.user.Id), 2)
}

func TestLegalAcceptance_DeclineAnswersAccessDeniedKeepsTheSessionAndAsksAgain(t *testing.T) {
	requireDatabaseAuditLogs(t)
	f := newLegalAcceptanceFixture(t)
	f.mustAcceptFor(t, "declined", "Terms to decline")
	browser := createHttpClient(t)

	page, stepURL := toStep(t, browser, f.signInToCompleted(t, browser))
	resp := postStep(t, browser, stepURL, page, nil, true)
	_ = page.Body.Close()
	query := f.appRedirect(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, "access_denied", query.Get("error"))
	assert.Equal(t, declinedDescription, query.Get("error_description"))
	assert.Equal(t, legalAcceptanceState, query.Get("state"))
	assert.Empty(t, query.Get("code"))
	assert.Empty(t, acceptedVersionIds(t, f.user.Id), "a decline is never stored")

	details := latestAuditDetails(t, audit.EventDeclinedLegalDocuments)
	require.NotNil(t, details, "the decline is audited")
	assert.Equal(t, f.user.Id, detailNumber(t, details, "user_id"))
	assert.Equal(t, f.client.Id, detailNumber(t, details, "client_id"))

	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, f.user.Id)
	require.NoError(t, err)
	assert.Len(t, sessions, 1, "the user's session stays")

	// The next sign-in, over that session, asks again.
	page, _ = toStep(t, browser, f.ssoToCompleted(t, browser))
	_ = page.Body.Close()
}

func TestLegalAcceptance_ANewVersionIsAskedAgain(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	termsId, _ := f.mustAcceptFor(t, "versioned", "Versioned terms")
	browser := createHttpClient(t)

	page, stepURL := toStep(t, browser, f.signInToCompleted(t, browser))
	_, documents := readStep(t, page)
	f.assertCodeIssued(t, browser, postStep(t, browser, stepURL, page, versionsOf(documents), false))
	_ = page.Body.Close()

	publishOverAPI(t, f.adminToken, termsId, "Versioned terms", "Version 2.")
	page, stepURL = toStep(t, browser, f.ssoToCompleted(t, browser))
	_, documents = readStep(t, page)
	version2 := strconv.FormatInt(versionId(t, termsId, 2), 10)
	assert.Equal(t, []string{version2}, versionsOf(documents), "the new version is asked")

	// Version 3 is published while the step shows version 2: accepting version 2 shows the step
	// again with version 3, and records nothing.
	publishOverAPI(t, f.adminToken, termsId, "Versioned terms", "Version 3.")
	resp := postStep(t, browser, stepURL, page, []string{version2}, false)
	_ = page.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the step is shown again")
	doc, redrawn := readStep(t, resp)
	version3 := strconv.FormatInt(versionId(t, termsId, 3), 10)
	assert.Equal(t, []string{version3}, versionsOf(redrawn), "with the version now current")
	assert.Equal(t, 1, doc.Find("#legal-acceptance-changed").Length(), "saying it changed")
	assert.Equal(t, 0, doc.Find("#legal-acceptance-error").Length())
	assert.Equal(t, []int64{versionId(t, termsId, 1)}, acceptedVersionIds(t, f.user.Id), "nothing more is recorded")

	f.assertCodeIssued(t, browser, postStep(t, browser, stepURL, resp, []string{version3}, false))
	_ = resp.Body.Close()
	assert.Equal(t, []int64{versionId(t, termsId, 1), versionId(t, termsId, 3)}, acceptedVersionIds(t, f.user.Id),
		"the version accepted is the one shown")
}

func TestLegalAcceptance_AnAppSpecificDocumentBlocksOnlyItsAppsAndAnAcceptanceCountsForEveryAppItCovers(t *testing.T) {
	shop := newLegalAcceptanceFixture(t)
	blog := newLegalAcceptanceApp(t, shop.user, shop.password, shop.adminToken)
	forum := newLegalAcceptanceApp(t, shop.user, shop.password, shop.adminToken)
	id, _ := shop.mustAcceptFor(t, "shared", "Shared terms")
	status, body := setApps(t, shop.adminToken, id, "selected_apps", []int64{shop.client.Id, forum.client.Id},
		[]int64{shop.client.Id})
	require.Equal(t, http.StatusOK, status, "apps: %v", body)

	browser := createHttpClient(t)
	blog.assertCodeIssued(t, browser, blog.signInToCompleted(t, browser))

	page, stepURL := toStep(t, browser, shop.ssoToCompleted(t, browser))
	_, documents := readStep(t, page)
	shop.assertCodeIssued(t, browser, postStep(t, browser, stepURL, page, versionsOf(documents), false))
	_ = page.Body.Close()

	forum.assertCodeIssued(t, browser, forum.ssoToCompleted(t, browser))
}

func TestLegalAcceptance_SingleSignOnIsAsked(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	other := newLegalAcceptanceApp(t, f.user, f.password, f.adminToken)
	f.mustAcceptFor(t, "sso", "Terms over a session")
	browser := createHttpClient(t)
	other.assertCodeIssued(t, browser, other.signInToCompleted(t, browser))

	page, _ := toStep(t, browser, f.ssoToCompleted(t, browser))
	_, documents := readStep(t, page)
	_ = page.Body.Close()
	assert.Len(t, documents, 1, "a sign-in with no password asked passes the step too")
}

func TestLegalAcceptance_PromptNoneIsAnsweredInteractionRequiredUntilAccepted(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	other := newLegalAcceptanceApp(t, f.user, f.password, f.adminToken)
	f.mustAcceptFor(t, "silent", "Silent terms")
	browser := createHttpClient(t)
	other.assertCodeIssued(t, browser, other.signInToCompleted(t, browser))

	resp, err := browser.Get(f.link("&prompt=none"))
	require.NoError(t, err)
	query := f.appRedirect(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, "interaction_required", query.Get("error"))
	assert.Equal(t, silentOwedDescription, query.Get("error_description"))
	assert.Equal(t, legalAcceptanceState, query.Get("state"))
	assert.Empty(t, query.Get("code"))

	page, stepURL := toStep(t, browser, f.ssoToCompleted(t, browser))
	_, documents := readStep(t, page)
	f.assertCodeIssued(t, browser, postStep(t, browser, stepURL, page, versionsOf(documents), false))
	_ = page.Body.Close()

	resp, err = browser.Get(f.link("&prompt=none"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/issue")
	resp2 := loadPage(t, browser, location)
	defer func() { _ = resp2.Body.Close() }()
	query = f.appRedirect(t, resp2)
	assert.NotEmpty(t, query.Get("code"), "accepted, the silent request gets its code")
}

// passwordGrant posts a password grant for the fixture's user to its app and answers the status
// and the decoded body.
func (f *legalAcceptanceFixture) passwordGrant(t *testing.T) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"username":      {f.user.Email},
		"password":      {f.password},
		"scope":         {"openid"},
	}
	resp, err := createHttpClient(t).PostForm(appConfig.AuthServer.BaseURL+"/auth/token/", form)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body := map[string]any{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

func TestLegalAcceptance_ThePasswordGrantIsRefusedUntilTheUserAcceptsInTheBrowser(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })
	f := newLegalAcceptanceFixture(t)
	f.mustAcceptFor(t, "ropc", "Terms for the password grant")

	status, body := f.passwordGrant(t)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, passwordGrantDescription, body["error_description"])
	assert.Nil(t, body["access_token"])

	browser := createHttpClient(t)
	page, stepURL := toStep(t, browser, f.signInToCompleted(t, browser))
	_, documents := readStep(t, page)
	f.assertCodeIssued(t, browser, postStep(t, browser, stepURL, page, versionsOf(documents), false))
	_ = page.Body.Close()

	status, body = f.passwordGrant(t)
	assert.Equal(t, http.StatusOK, status, "accepted in the browser, the grant works again: %v", body)
	assert.NotEmpty(t, body["access_token"])
}

func TestLegalAcceptance_ARefreshKeepsWorkingWhileADocumentIsOwed(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	browser := createHttpClient(t)
	resp := f.signInToCompleted(t, browser)
	location := assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	code := f.appRedirect(t, resp).Get("code")
	_ = resp.Body.Close()
	require.NotEmpty(t, code)

	tokens := postToTokenEndpoint(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"code":          {code},
		"redirect_uri":  {f.redirectURI},
		"code_verifier": {testCodeVerifier},
	})
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the code is redeemed with a refresh token: %v", tokens)

	f.mustAcceptFor(t, "refresh", "Terms published after the sign-in")

	refreshed := postToTokenEndpoint(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"refresh_token": {refreshToken},
	})
	assert.Nil(t, refreshed["error"], "the refresh is not refused: %v", refreshed["error_description"])
	assert.NotEmpty(t, refreshed["access_token"], "the user is asked at the next sign-in instead")
}

func TestLegalAcceptance_TheAdminConsolesOwnSignInIsNeverAsked(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	user, password := newLegalAcceptanceUser(t)
	assignPermissionToUser(t, user.Id, authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier))

	// A must-accept document for all apps, the one kind that could reach the admin console's
	// sign-in, retired before the test ends so no other test's sign-in owes it.
	shortName := legalShortName("everyone")
	id := createLegalDocumentOverAPI(t, adminToken, "must_accept", shortName, "Everyone's terms", "For all.")
	status, body, _ := legalCall(t, adminToken, http.MethodPost, legalPath(id, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "publish: %v", body)
	defer retireOverAPI(t, adminToken, id)

	browser := createHttpClient(t)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize?" + url.Values{
		"client_id":             {builtin.AdminConsoleClientIdentifier},
		"redirect_uri":          {appConfig.AdminConsole.BaseURL + "/auth/callback"},
		"response_mode":         {"form_post"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {oauth.GeneratePKCECodeChallenge(testCodeVerifier)},
		"state":                 {legalAcceptanceState},
		"nonce":                 {fake.LetterN(16)},
		"scope":                 {"openid authserver:manage-account"},
	}.Encode()
	resp, err := browser.Get(destUrl)
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	pwdPage := loadPage(t, browser, location)
	resp = authenticateWithPassword(t, browser, location, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()
	location = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	for strings.Contains(resp.Header.Get("Location"), "/auth/level2") {
		location = resp.Header.Get("Location")
		_ = resp.Body.Close()
		resp = loadPage(t, browser, location)
	}
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	assertRedirect(t, resp, "/auth/issue")
	assert.Empty(t, acceptedVersionIds(t, user.Id))

	// The same document is owed on a sign-in to any other app.
	app := newLegalAcceptanceApp(t, user, password, adminToken)
	page, _ := toStep(t, browser, app.ssoToCompleted(t, browser))
	_, documents := readStep(t, page)
	_ = page.Body.Close()
	assert.True(t, slices.ContainsFunc(documents, func(d stepDocument) bool { return d.href == "/legal/"+shortName }),
		"another app's sign-in owes the all-apps document")
}

func TestLegalAcceptance_ARetiredDocumentIsAskedOfNobodyUntilItIsRestored(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	owing := f.withUser(newLegalAcceptanceUser(t))
	termsId, _ := f.mustAcceptFor(t, "retired", "Terms to retire")

	// The fixture's user accepts version 1 before the document is retired.
	accepted := createHttpClient(t)
	f.acceptAll(t, accepted)

	retireOverAPI(t, f.adminToken, termsId)
	browser := createHttpClient(t)
	owing.assertCodeIssued(t, browser, owing.signInToCompleted(t, browser))

	status, body, _ := legalCall(t, f.adminToken, http.MethodPost, legalPath(termsId, "/restore"), nil)
	require.Equal(t, http.StatusOK, status, "restore: %v", body)

	// In effect again at version 1: the user who never accepted it is asked at their next sign-in,
	// and the one who accepted version 1 is not.
	page, _ := toStep(t, browser, owing.ssoToCompleted(t, browser))
	_, documents := readStep(t, page)
	_ = page.Body.Close()
	assert.Equal(t, []string{strconv.FormatInt(versionId(t, termsId, 1), 10)}, versionsOf(documents),
		"version 1, as it was")
	f.assertCodeIssued(t, accepted, f.ssoToCompleted(t, accepted))
}

func TestLegalAcceptance_ADocumentsAppsChangeWhoIsAskedWithNoNewVersion(t *testing.T) {
	shop := newLegalAcceptanceFixture(t)
	forum := newLegalAcceptanceApp(t, shop.user, shop.password, shop.adminToken)
	owingUser, owingPassword := newLegalAcceptanceUser(t)
	owingAtShop, owingAtForum := shop.withUser(owingUser, owingPassword), forum.withUser(owingUser, owingPassword)
	id, _ := shop.mustAcceptFor(t, "gains-an-app", "Terms that gain an app")

	// The fixture's user accepts it on the shop; the forum asks the other user nothing yet.
	accepted := createHttpClient(t)
	shop.acceptAll(t, accepted)
	browser := createHttpClient(t)
	owingAtForum.assertCodeIssued(t, browser, owingAtForum.signInToCompleted(t, browser))

	// The forum is added, which publishes no new version.
	status, body := setApps(t, shop.adminToken, id, "selected_apps", []int64{shop.client.Id, forum.client.Id},
		[]int64{shop.client.Id})
	require.Equal(t, http.StatusOK, status, "apps: %v", body)
	versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(context.Background(), nil, id)
	require.NoError(t, err)
	assert.Len(t, versions, 1, "changing the apps publishes no version")

	// The user who never accepted it is asked at their next sign-in to the forum, and the one who
	// accepted it on the shop is not: one acceptance counts on every app the document covers.
	page, _ := toStep(t, browser, owingAtForum.ssoToCompleted(t, browser))
	_ = page.Body.Close()
	forum.assertCodeIssued(t, accepted, forum.ssoToCompleted(t, accepted))

	// The shop taken off, the document asks nothing there.
	status, body = setApps(t, shop.adminToken, id, "selected_apps", []int64{forum.client.Id},
		[]int64{shop.client.Id, forum.client.Id})
	require.Equal(t, http.StatusOK, status, "apps: %v", body)
	owingAtShop.assertCodeIssued(t, browser, owingAtShop.ssoToCompleted(t, browser))
}
