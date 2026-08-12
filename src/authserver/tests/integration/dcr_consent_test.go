package integrationtests

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// followAuthChain drives /auth/authorize for a self-registered client and returns the path chain it
// produced together with the page that finally rendered.
//
// navigateToConsentScreen cannot be reused here: it asserts a fixed chain of
// /auth/level1completed -> /auth/completed, while a client created through /connect/register
// carries DefaultAcrLevel level2_optional and so routes through /auth/level2 first. Walking the
// chain instead of asserting it step by step is also what lets the caller assert where the flow
// went, which is the security property this file owns (#108).
//
// The caller owns the returned response body.
func followAuthChain(t *testing.T, httpClient *http.Client, clientIdentifier string,
	redirectURI string, user *models.User, password string) ([]string, *http.Response) {

	t.Helper()

	authorizeURL := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + clientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(authorizeURL)
	require.NoError(t, err)

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "authorize must redirect")
	_ = resp.Body.Close()

	var chain []string
	passwordDone := false

	for i := 0; i < 15 && loc != ""; i++ {
		parsed, err := url.Parse(loc)
		require.NoError(t, err)
		chain = append(chain, parsed.Path)

		if strings.HasPrefix(loc, redirectURI) {
			// The flow left this server for the client. Nothing rendered.
			t.Fatalf("the flow redirected to the client: %s", strings.Join(chain, " -> "))
		}

		page := loadPage(t, httpClient, loc)

		if strings.Contains(parsed.Path, "/auth/pwd") && !passwordDone {
			next := authenticateWithPassword(t, httpClient, loc, page, user.Email, password)
			_ = page.Body.Close()
			page = next
			passwordDone = true
		}

		nextLoc := page.Header.Get("Location")
		if nextLoc == "" {
			// A page rendered rather than redirecting. This is the one the caller wants.
			return chain, page
		}

		loc = nextLoc
		_ = page.Body.Close()
	}

	t.Fatalf("no page rendered within 15 hops: %s", strings.Join(chain, " -> "))
	return chain, nil
}

// TestDCR_Consent_ReachesConsentAndMarksTheNameUnverified is the regression guard for the issue as
// reported. It is probe/reproduce_silent_grant_test.go inverted: that probe drove exactly this flow
// and watched it run from /auth/completed straight to /auth/issue, handing out a code for every
// scope the user held with nothing rendered to them at all.
//
// The client is registered through the endpoint rather than built with database.CreateClient, so
// the defaults under test are the registration handler's rather than ones this test chose (#108).
func TestDCR_Consent_ReachesConsentAndMarksTheNameUnverified(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	const selfAssertedName = "Payroll Portal"
	const redirectURI = "https://dcr-consent-app.example.com/callback"

	client := registerDCRClient(t, selfAssertedName, redirectURI)
	user, password := createCeremonyUser(t)
	httpClient := createHttpClient(t)

	chain, resp := followAuthChain(t, httpClient, client.ClientIdentifier, redirectURI, user, password)
	defer func() { _ = resp.Body.Close() }()

	flow := strings.Join(chain, " -> ")
	assert.Contains(t, flow, "/auth/consent", "a self-registered client must reach the consent screen: %s", flow)
	assert.NotContains(t, flow, "/auth/issue", "no code may be issued before consent: %s", flow)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc := parseHTMLResponse(t, resp)

	// The name the client asserted, not the dcr_<uuid> the server generated. A prompt reading
	// "dcr_a3f9e1b2-... wants access" is one nobody can evaluate.
	assertClientNameInHTML(t, doc, selfAssertedName)

	body := doc.Text()
	assert.NotContains(t, body, client.ClientIdentifier,
		"the generated identifier is replaced by the asserted name, not shown beside it")

	// The English copy for consent.client_unverified, written out rather than read back through
	// i18n.T: this process never loads the catalogs, so T would answer with the key itself and the
	// assertion would pass against a page that rendered nothing.
	assert.Contains(t, body, "This application registered itself and has not been verified.",
		"the self-asserted name is shown as a claim, never as an attestation (RFC 7591 section 5)")
}

// TestDCR_Consent_SelfAssertedNameIsEscaped pins what the issue asked to have pinned rather than
// assumed. client_name is attacker-controlled text that now reaches a rendered page, and Go's
// html/template escapes it by default, so this asserts that default rather than trusting it.
//
// It cannot be observed at the unit tier: handler_consent_test.go mocks RenderTemplate, so no
// escaping happens there at all.
func TestDCR_Consent_SelfAssertedNameIsEscaped(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	const payload = `<script>alert(1)</script>`
	const redirectURI = "https://dcr-escape-app.example.com/callback"

	client := registerDCRClient(t, payload, redirectURI)
	require.Equal(t, payload, client.Description, "the payload is stored verbatim; escaping is the renderer's job")

	user, password := createCeremonyUser(t)
	httpClient := createHttpClient(t)

	chain, resp := followAuthChain(t, httpClient, client.ClientIdentifier, redirectURI, user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Contains(t, strings.Join(chain, " -> "), "/auth/consent")

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	page := string(raw)

	// Asserted against the raw bytes on purpose. goquery decodes entities, so reading the name
	// through the parsed document cannot tell an escaped payload from an executed one.
	assert.NotContains(t, page, payload, "the payload must not reach the page as markup")
	assert.Contains(t, page, "&lt;script&gt;alert(1)&lt;/script&gt;", "it reaches the page as text")
}

// TestDCR_Consent_UnverifiedNameSuppressesTheDescriptionLine covers the one behaviour in this stage
// that no other case would notice being deleted. A self-registered client's name and its
// description are the same self-asserted string, so an administrator who ticks "show description"
// on one would read it twice on the consent screen (#108).
func TestDCR_Consent_UnverifiedNameSuppressesTheDescriptionLine(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	const selfAssertedName = "Duplicated Portal"
	const redirectURI = "https://dcr-dup-app.example.com/callback"

	client := registerDCRClient(t, selfAssertedName, redirectURI)

	// The one thing an administrator can do that would surface the duplication.
	client.ShowDescription = true
	require.NoError(t, database.UpdateClient(nil, client))

	user, password := createCeremonyUser(t)
	httpClient := createHttpClient(t)

	chain, resp := followAuthChain(t, httpClient, client.ClientIdentifier, redirectURI, user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Contains(t, strings.Join(chain, " -> "), "/auth/consent")

	doc := parseHTMLResponse(t, resp)
	assert.Equal(t, 1, strings.Count(doc.Text(), selfAssertedName),
		"the name is shown once, as the client name under the unverified notice")
}
