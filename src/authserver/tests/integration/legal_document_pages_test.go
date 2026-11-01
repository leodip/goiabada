package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A legal document's public pages and where documents show (#622 decision 5 and "Where documents
// show"): /legal/<short-name> shows the current version and links every earlier one at
// /legal/<short-name>/versions/<n>, with no sign-in; drafts are never public and a retired
// document's pages answer not found. The sign-in pages' footer links the all-apps documents, plus
// the app's own on a sign-in for that app; the registration form links the same documents where it
// collects the data; the public settings carry the all-apps documents for My Account's footer.
//
// Every document here applies to selected apps with a client of the test's own, but for the few
// for information that a test needs for all apps, which are retired when the test ends.

// publishOverAPI saves the draft and publishes it as the document's next version.
func publishOverAPI(t *testing.T, accessToken string, id int64, title, markdown string) {
	t.Helper()
	status, body, _ := legalCall(t, accessToken, http.MethodPut, legalPath(id, "/draft"), map[string]any{
		"title": title, "markdown": markdown,
	})
	require.Equal(t, http.StatusOK, status, "draft: %v", body)
	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "publish: %v", body)
}

// publishedForApps creates a document for information that applies to the clients given, or to all
// apps when there are none, publishes it with title and markdown, and answers its short name.
func publishedForApps(t *testing.T, accessToken, prefix, title, markdown string, clients ...*record.Client) (int64, string) {
	t.Helper()
	shortName := legalShortName(prefix)
	id := createLegalDocumentOverAPI(t, accessToken, "for_information", shortName, title, markdown)
	if len(clients) > 0 {
		clientIds := []int64{}
		for _, c := range clients {
			clientIds = append(clientIds, c.Id)
		}
		status, body := setApps(t, accessToken, id, "selected_apps", clientIds, []int64{})
		require.Equal(t, http.StatusOK, status, "apps: %v", body)
	}
	status, body, _ := legalCall(t, accessToken, http.MethodPost, legalPath(id, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "publish: %v", body)
	return id, shortName
}

// retireOverAPI retires a published document.
func retireOverAPI(t *testing.T, accessToken string, id int64) {
	t.Helper()
	status, body, _ := legalCall(t, accessToken, http.MethodPost, legalPath(id, "/retire"), nil)
	require.Equal(t, http.StatusOK, status, "retire: %v", body)
}

// getPublicPage loads a page with a browser that holds no session: the pages need no sign-in.
func getPublicPage(t *testing.T, path string) (int, *goquery.Document) {
	t.Helper()
	resp := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+path)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, parseHTMLResponse(t, resp)
}

// linksIn answers each link's text by its address, inside the elements selection names.
func linksIn(doc *goquery.Document, selection string) map[string]string {
	links := map[string]string{}
	doc.Find(selection).Find("a").Each(func(_ int, a *goquery.Selection) {
		href, _ := a.Attr("href")
		links[href] = strings.TrimSpace(a.Text())
	})
	return links
}

// footerLinks answers the legal footer's links on a page, by address.
func footerLinks(doc *goquery.Document) map[string]string {
	return linksIn(doc, "nav.legal-footer")
}

// appWithRedirect creates a client of the test's own with one redirect URI, deleted when the test
// ends.
func appWithRedirect(t *testing.T) (*record.Client, string) {
	t.Helper()
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "legal-app-" + strings.ToLower(fake.LetterN(10)),
		DefaultAcrLevel:  record.AcrLevel1,
	})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	redirectURI := fake.URL()
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, &record.RedirectURI{
		ClientId: client.Id, URI: redirectURI,
	}))
	return client, redirectURI
}

func TestLegalDocumentPages_TheCurrentVersionAndEveryEarlierOne(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	app, _ := appWithRedirect(t)
	id, shortName := publishedForApps(t, accessToken, "privacy", "Privacy notice", "# What we keep\n\nYour **email**.", app)
	publishOverAPI(t, accessToken, id, "Privacy notice, revised", "We keep your *address* too.")

	status, page := getPublicPage(t, "/legal/"+shortName)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "Privacy notice, revised", strings.TrimSpace(page.Find("h1").First().Text()))
	text, err := page.Find(".legal-text").Html()
	require.NoError(t, err)
	assert.Contains(t, text, "<em>address</em>", "the Markdown is rendered")
	assert.NotContains(t, text, "What we keep", "the current version alone")
	assert.Contains(t, page.Find("#legal-document-version").Text(), "Version 2")
	versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(context.Background(), nil, id)
	require.NoError(t, err)
	require.Len(t, versions, 2)
	published, _ := page.Find("#legal-document-version time").Attr("datetime")
	assert.Equal(t, versions[1].PublishedAt.UTC().Format("2006-01-02"), published)
	assert.Equal(t, map[string]string{
		"/legal/" + shortName + "/versions/1": "Version 1",
		"/legal/" + shortName + "/versions/2": "Version 2",
	}, linksIn(page, "#legal-document-versions"))

	status, page = getPublicPage(t, "/legal/"+shortName+"/versions/1")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "Privacy notice", strings.TrimSpace(page.Find("h1").First().Text()))
	text, err = page.Find(".legal-text").Html()
	require.NoError(t, err)
	assert.Contains(t, text, "<strong>email</strong>")
	// The page's title is its one h1; the text's "# What we keep" sits under it (docs/development/ui.md).
	assert.Equal(t, 1, page.Find("h1").Length(), "one h1 on the page")
	assert.Equal(t, "What we keep", strings.TrimSpace(page.Find(".legal-text h2").First().Text()))
	assert.Zero(t, page.Find(".legal-text h1").Length())
	assert.Contains(t, page.Find("#legal-document-version").Text(), "Version 1")
	current, ok := page.Find("#legal-document-superseded a").Attr("href")
	require.True(t, ok, "an earlier version links to the current one")
	assert.Equal(t, "/legal/"+shortName, current)

	status, page = getPublicPage(t, "/legal/"+shortName+"/versions/2")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "Privacy notice, revised", strings.TrimSpace(page.Find("h1").First().Text()))
	assert.Equal(t, 0, page.Find("#legal-document-superseded").Length(), "the current version is not superseded")

	for _, missing := range []string{"/versions/3", "/versions/0", "/versions/01", "/versions/-1", "/versions/one"} {
		status, _ = getPublicPage(t, "/legal/"+shortName+missing)
		assert.Equal(t, http.StatusNotFound, status, missing)
	}
}

func TestLegalDocumentPages_DraftsUnknownAndRetiredDocumentsAreNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	app, _ := appWithRedirect(t)

	draftName := legalShortName("draft")
	createLegalDocumentOverAPI(t, accessToken, "must_accept", draftName, "Terms", "Never published.")
	status, _ := getPublicPage(t, "/legal/"+draftName)
	assert.Equal(t, http.StatusNotFound, status, "a document never published has no page")
	status, _ = getPublicPage(t, "/legal/"+draftName+"/versions/1")
	assert.Equal(t, http.StatusNotFound, status)

	status, _ = getPublicPage(t, "/legal/"+legalShortName("unknown"))
	assert.Equal(t, http.StatusNotFound, status)

	id, shortName := publishedForApps(t, accessToken, "retired", "Old notice", "Old text.", app)
	// A draft beside the published version stays private.
	status, body, _ := legalCall(t, accessToken, http.MethodPut, legalPath(id, "/draft"), map[string]any{
		"title": "Old notice", "markdown": "The draft's secret text.",
	})
	require.Equal(t, http.StatusOK, status, "%v", body)
	status, page := getPublicPage(t, "/legal/"+shortName)
	require.Equal(t, http.StatusOK, status)
	assert.NotContains(t, page.Text(), "secret text", "the draft is never public")
	status, _ = getPublicPage(t, "/legal/"+shortName+"/versions/2")
	assert.Equal(t, http.StatusNotFound, status, "a draft is not a version")

	retireOverAPI(t, accessToken, id)
	status, _ = getPublicPage(t, "/legal/"+shortName)
	assert.Equal(t, http.StatusNotFound, status, "a retired document's page")
	status, _ = getPublicPage(t, "/legal/"+shortName+"/versions/1")
	assert.Equal(t, http.StatusNotFound, status, "and every version of it")

	status, body, _ = legalCall(t, accessToken, http.MethodPost, legalPath(id, "/restore"), nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	status, _ = getPublicPage(t, "/legal/"+shortName)
	assert.Equal(t, http.StatusOK, status, "restored, it has its page again")
}

func TestLegalDocumentFooter_SignInPagesLinkTheAllAppsDocumentsAndTheAppsOwn(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	app, redirectURI := appWithRedirect(t)
	other, _ := appWithRedirect(t)
	allAppsId, allApps := publishedForApps(t, accessToken, "all", "Everyone's notice", "For all.")
	_, own := publishedForApps(t, accessToken, "own", "The app's notice", "For one app.", app)
	_, others := publishedForApps(t, accessToken, "others", "Another app's notice", "For another.", other)
	unpublished := legalShortName("unpublished")
	createLegalDocumentOverAPI(t, accessToken, "for_information", unpublished, "Not yet", "Draft only.")

	resp := navigateToPasswordScreen(t, createHttpClient(t), app, redirectURI)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	links := footerLinks(parseHTMLResponse(t, resp))
	_ = resp.Body.Close()
	assert.Equal(t, "Everyone's notice", links["/legal/"+allApps])
	assert.Equal(t, "The app's notice", links["/legal/"+own], "the app's own document, on a sign-in to it")
	assert.NotContains(t, links, "/legal/"+others, "another app's document")
	assert.NotContains(t, links, "/legal/"+unpublished, "a document never published")

	// A page no app is behind links the all-apps documents alone.
	status, page := getPublicPage(t, "/legal/"+legalShortName("nothing-here"))
	require.Equal(t, http.StatusNotFound, status)
	links = footerLinks(page)
	assert.Equal(t, "Everyone's notice", links["/legal/"+allApps])
	assert.NotContains(t, links, "/legal/"+own)

	// The public page itself carries the footer.
	status, page = getPublicPage(t, "/legal/"+own)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, footerLinks(page), "/legal/"+allApps)

	retireOverAPI(t, accessToken, allAppsId)
	resp = navigateToPasswordScreen(t, createHttpClient(t), app, redirectURI)
	links = footerLinks(parseHTMLResponse(t, resp))
	_ = resp.Body.Close()
	assert.NotContains(t, links, "/legal/"+allApps, "a retired document leaves the footer")
	assert.Contains(t, links, "/legal/"+own)
}

func TestLegalDocumentFooter_TheRegistrationFormLinksTheDocumentsWhereItCollectsTheData(t *testing.T) {
	setRegSettings(t, true, false, false)
	accessToken, _ := createAdminClientWithToken(t)
	app, redirectURI := appWithRedirect(t)
	other, _ := appWithRedirect(t)
	_, allApps := publishedForApps(t, accessToken, "reg-all", "Everyone's terms", "For all.")
	_, own := publishedForApps(t, accessToken, "reg-own", "The app's privacy notice", "For one app.", app)
	_, others := publishedForApps(t, accessToken, "reg-others", "Another app's notice", "For another.", other)

	// Registration from the app's sign-in: the password page's Create an account link names it.
	browser := createHttpClient(t)
	resp := navigateToPasswordScreen(t, browser, app, redirectURI)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ceremonyId := resp.Request.URL.Query().Get(ceremony.QueryParameter)
	_ = resp.Body.Close()
	require.NotEmpty(t, ceremonyId)
	registerURL := appConfig.AuthServer.BaseURL + "/account/register?" + url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode()

	resp = loadPage(t, browser, registerURL)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	page := parseHTMLResponse(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, map[string]string{
		"/legal/" + allApps: "Everyone's terms",
		"/legal/" + own:     "The app's privacy notice",
	}, linksIn(page, "form #legal-documents"), "inside the form, the all-apps documents and the app's own")
	assert.Contains(t, footerLinks(page), "/legal/"+own)
	assert.NotContains(t, footerLinks(page), "/legal/"+others)

	// The same link in a browser that does not hold that sign-in names no app.
	resp = loadPage(t, createHttpClient(t), registerURL)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	page = parseHTMLResponse(t, resp)
	_ = resp.Body.Close()
	formLinks := linksIn(page, "form #legal-documents")
	assert.Contains(t, formLinks, "/legal/"+allApps)
	assert.NotContains(t, formLinks, "/legal/"+own, "a sign-in the browser does not hold")

	// Registration reached from anywhere else links the all-apps documents.
	resp = loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/account/register")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	page = parseHTMLResponse(t, resp)
	_ = resp.Body.Close()
	formLinks = linksIn(page, "form #legal-documents")
	assert.Contains(t, formLinks, "/legal/"+allApps)
	assert.NotContains(t, formLinks, "/legal/"+own)

	// A refused submission shows the form again, with the same links.
	resp = postRegister(t, browser, fake.Email(), "one-password-1A!", "another-password-2B!")
	page = parseHTMLResponse(t, resp)
	_ = resp.Body.Close()
	require.Equal(t, 1, page.Find("#register-error").Length(), "the refusal is shown")
	assert.Contains(t, linksIn(page, "form #legal-documents"), "/legal/"+allApps)
}

func TestLegalDocumentFooter_ThePublicSettingsCarryTheAllAppsDocuments(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	app, _ := appWithRedirect(t)
	allAppsId, allApps := publishedForApps(t, accessToken, "settings-all", "Everyone's notice", "For all.")
	_, own := publishedForApps(t, accessToken, "settings-own", "The app's notice", "For one app.", app)

	read := func() map[string]map[string]any {
		resp := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/api/public/settings")
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			LegalDocuments []map[string]any `json:"legalDocuments"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		byShortName := map[string]map[string]any{}
		for _, doc := range body.LegalDocuments {
			byShortName[doc["shortName"].(string)] = doc
		}
		return byShortName
	}

	docs := read()
	assert.Equal(t, map[string]any{
		"title":     "Everyone's notice",
		"shortName": allApps,
		"url":       appConfig.AuthServer.BaseURL + "/legal/" + allApps,
	}, docs[allApps])
	assert.NotContains(t, docs, own, "a document for selected apps")

	retireOverAPI(t, accessToken, allAppsId)
	assert.NotContains(t, read(), allApps, "a retired document")
}
