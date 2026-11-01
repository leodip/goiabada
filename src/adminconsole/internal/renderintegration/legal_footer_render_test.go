package renderintegration

import (
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderPhonePageAt renders the account phone page requested at path, with the public settings
// carrying legalDocuments.
func renderPhonePageAt(t *testing.T, path string, legalDocuments []api.PublicLegalDocumentResponse) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	settings := &api.PublicSettingsResponse{AppName: "Test", LegalDocuments: legalDocuments}
	req = req.WithContext(reqctx.WithSettings(req.Context(), settings))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "en"))
	w := httptest.NewRecorder()
	err := render.New(web.TemplateFS(), web.StaticFS()).RenderTemplate(w, req, "/layouts/menu_layout.html", "/account_phone.html",
		map[string]interface{}{"phoneCountries": phonecountries.All(), "savedSuccessfully": false})
	require.NoError(t, err)
	return w.Body.String()
}

var (
	// legalFooterRe captures the legal footer inside the page's main region.
	legalFooterRe = regexp.MustCompile(`(?s)<main\b.*<nav class="legal-footer" aria-label="([^"]*)">(.*?)</nav>.*</main>`)
	footerLinkRe  = regexp.MustCompile(`<a class="text-link" href="([^"]*)">([^<]*)</a>`)
)

// My Account's footer links the auth server's legal documents in effect for all apps, as its public
// settings carry them (#622).
func TestRender_MyAccountFooterLinksTheAllAppsLegalDocuments(t *testing.T) {
	out := renderPhonePageAt(t, "/account/phone", []api.PublicLegalDocumentResponse{
		{Title: "Privacy notice", ShortName: "privacy", URL: "https://auth.example/legal/privacy"},
		{Title: "Terms of use", ShortName: "terms", URL: "https://auth.example/legal/terms"},
	})

	m := legalFooterRe.FindStringSubmatch(out)
	require.NotNil(t, m, "the footer, inside the page's main region")
	assert.Equal(t, "Legal documents", m[1])
	links := map[string]string{}
	for _, link := range footerLinkRe.FindAllStringSubmatch(m[2], -1) {
		links[html.UnescapeString(link[1])] = strings.TrimSpace(html.UnescapeString(link[2]))
	}
	assert.Equal(t, map[string]string{
		"https://auth.example/legal/privacy": "Privacy notice",
		"https://auth.example/legal/terms":   "Terms of use",
	}, links)
}

func TestRender_MyAccountFooterIsLeftOutWithNoDocument(t *testing.T) {
	out := renderPhonePageAt(t, "/account/phone", []api.PublicLegalDocumentResponse{})
	assert.NotContains(t, out, "legal-footer")
}

// The admin pages, which administrators read, draw no footer.
func TestRender_AdminPagesHaveNoLegalFooter(t *testing.T) {
	out := renderPhonePageAt(t, "/admin/users/7/phone", []api.PublicLegalDocumentResponse{
		{Title: "Privacy notice", ShortName: "privacy", URL: "https://auth.example/legal/privacy"},
	})
	assert.NotContains(t, out, "legal-footer")
}
