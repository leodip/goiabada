package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The English link texts of consent.client_privacy_policy and consent.client_terms_of_service,
// written out: this process never loads the catalogs.
const (
	consentPrivacyPolicyLinkText  = "This application's privacy policy"
	consentTermsOfServiceLinkText = "This application's terms of service"
)

// consentDocumentLink returns the consent screen's link with this text, and whether there is one.
func consentDocumentLink(doc *goquery.Document, text string) (*goquery.Selection, bool) {
	link := doc.Find("a").FilterFunction(func(_ int, s *goquery.Selection) bool {
		return strings.TrimSpace(s.Text()) == text
	})
	return link, link.Length() > 0
}

// assertConsentDocumentLink holds the consent screen to one link with this text and address, opened
// in a new tab with no opener or referrer, as the website link is; or to none when href is empty.
func assertConsentDocumentLink(t *testing.T, doc *goquery.Document, text, href string) {
	t.Helper()
	link, found := consentDocumentLink(doc, text)
	if href == "" {
		assert.Falsef(t, found, "no %q link", text)
		return
	}
	require.Truef(t, found, "the consent screen links %q", text)
	assert.Equal(t, 1, link.Length())
	got, _ := link.Attr("href")
	assert.Equal(t, href, got)
	target, _ := link.Attr("target")
	assert.Equal(t, "_blank", target)
	rel, _ := link.Attr("rel")
	assert.Equal(t, "noopener noreferrer", rel)
}

// consentScreenOfClient signs a new user in to the client and returns the consent screen it reaches.
func consentScreenOfClient(t *testing.T, client *record.Client) *goquery.Document {
	t.Helper()
	redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))

	resp := navigateToConsentScreen(t, createHttpClient(t), client, user, password, redirectURI.URI)
	defer func() { _ = resp.Body.Close() }()
	return parseHTMLResponse(t, resp)
}

// A client's privacy policy and terms of service URLs are linked from its consent screen whenever
// they are set, with every "Sign-in and consent pages" switch off: RFC 7591 section 2 says the
// server SHOULD display them, and there is no switch to hide them (#622 decision 12).
func TestConsent_ClientDocumentLinks_ShownWheneverSet(t *testing.T) {
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier:  "docs-app-" + fake.LetterN(8),
		WebsiteURL:        "https://docs-app.example.com",
		PrivacyPolicyURL:  "https://docs-app.example.com/privacy",
		TermsOfServiceURL: "https://legal.example.org/docs-app/terms?v=2",
		ConsentRequired:   true,
		DefaultAcrLevel:   record.AcrLevel1,
	})
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	doc := consentScreenOfClient(t, client)

	assertConsentDocumentLink(t, doc, consentPrivacyPolicyLinkText, "https://docs-app.example.com/privacy")
	assertConsentDocumentLink(t, doc, consentTermsOfServiceLinkText, "https://legal.example.org/docs-app/terms?v=2")
	assertClientWebsiteUrlInHTML(t, doc, "https://docs-app.example.com", false)
}

// Each link is drawn on its own: a client with only a terms of service URL gets that link alone, and
// one with neither gets neither.
func TestConsent_ClientDocumentLinks_EachShownOnItsOwn(t *testing.T) {
	termsOnly := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier:  "terms-app-" + fake.LetterN(8),
		TermsOfServiceURL: "https://terms-app.example.com/terms",
		ConsentRequired:   true,
		DefaultAcrLevel:   record.AcrLevel1,
	})
	defer func() { _ = database.DeleteClient(context.Background(), nil, termsOnly.Id) }()

	doc := consentScreenOfClient(t, termsOnly)
	assertConsentDocumentLink(t, doc, consentPrivacyPolicyLinkText, "")
	assertConsentDocumentLink(t, doc, consentTermsOfServiceLinkText, "https://terms-app.example.com/terms")

	neither := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "plain-app-" + fake.LetterN(8),
		ConsentRequired:  true,
		DefaultAcrLevel:  record.AcrLevel1,
	})
	defer func() { _ = database.DeleteClient(context.Background(), nil, neither.Id) }()

	doc = consentScreenOfClient(t, neither)
	assertConsentDocumentLink(t, doc, consentPrivacyPolicyLinkText, "")
	assertConsentDocumentLink(t, doc, consentTermsOfServiceLinkText, "")
}

// Dynamic registration keeps a policy_uri on a redirect URI's scheme and host and drops a tos_uri on
// another host, registering the client anyway; the answer carries what was stored, and the consent
// screen links the kept URL alone (#622 decision 12, RFC 7591 sections 2, 3.2.1 and 5).
func TestDCR_DocumentURLs_KeptOnARedirectURIsHostAndShownOnConsent(t *testing.T) {
	enableDCR(t)

	const redirectURI = "https://dcr-docs-app.example.com/callback"
	resp := makeDCRRequest(t, oidc.DynamicClientRegistrationRequest{
		ClientName:   "Documented Portal",
		RedirectURIs: []string{redirectURI},
		PolicyURI:    "https://dcr-docs-app.example.com/privacy",
		TOSURI:       "https://elsewhere.example.org/terms",
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "a dropped tos_uri does not refuse the registration")

	var answer map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	assert.Equal(t, "https://dcr-docs-app.example.com/privacy", answer["policy_uri"], "the kept policy_uri is answered")
	_, hasTOS := answer["tos_uri"]
	assert.False(t, hasTOS, "the dropped tos_uri is absent from the answer")

	clientIdentifier, _ := answer["client_id"].(string)
	client, err := database.GetClientByClientIdentifier(context.Background(), nil, clientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()
	assert.Equal(t, "https://dcr-docs-app.example.com/privacy", client.PrivacyPolicyURL)
	assert.Empty(t, client.TermsOfServiceURL)

	user, password := createCeremonyUser(t)
	chain, page := followAuthChain(t, createHttpClient(t), client.ClientIdentifier, redirectURI, user, password)
	defer func() { _ = page.Body.Close() }()
	require.Contains(t, strings.Join(chain, " -> "), "/auth/consent")

	doc := parseHTMLResponse(t, page)
	assertConsentDocumentLink(t, doc, consentPrivacyPolicyLinkText, "https://dcr-docs-app.example.com/privacy")
	assertConsentDocumentLink(t, doc, consentTermsOfServiceLinkText, "")
}
