package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
)

// formPostFooterLink is a link the form_post page's footer draws: its href, target and rel, its
// visible text and the text it says to assistive technology alone.
type formPostFooterLink struct {
	Href, Target, Rel, Text, SrOnly string
}

func readFormPostFooterLinks(links *goquery.Selection) []formPostFooterLink {
	var drawn []formPostFooterLink
	links.Each(func(_ int, link *goquery.Selection) {
		var l formPostFooterLink
		l.Href, _ = link.Attr("href")
		l.Target, _ = link.Attr("target")
		l.Rel, _ = link.Attr("rel")
		l.SrOnly = strings.TrimSpace(link.Find(".sr-only").Text())
		visible := link.Clone()
		visible.Find(".sr-only").Remove()
		l.Text = strings.TrimSpace(visible.Text())
		drawn = append(drawn, l)
	})
	return drawn
}

// The form_post page is parsed alone, with no layout, so it draws its brand's footer itself, as the
// layouts do: outside main and straight after it, the links in a list with the label of the page's
// language, then "Need help?" with the contact, on a panel while the brand has a background image
// (#814 decisions 1 to 6).
func TestFormPost_ThePageDrawsTheBrandsFooter(t *testing.T) {
	const callback = "https://example.com/callback"
	brand := record.NewBrand("Night", record.BrandAppearanceAuto, "plum")
	brand.Id = 7
	brand.BackgroundAssetId = sql.NullInt64{Int64: 14, Valid: true}
	brand.FooterLinks = record.BrandFooterLinks{
		{URL: "https://acme.example/privacy", Label: "Privacy", Labels: map[string]string{"de": "Datenschutz"}},
		{URL: "https://status.acme.example/", Label: "Status"},
	}
	brand.SupportEmail = "100%pure@acme.example"
	brand.SupportURL = "https://acme.example/support"
	brand.SupportPhone = "+442079460958"
	database := datamocks.NewDatabase(t)
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(&brand, nil).Once()
	database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{14}).Return([]record.BrandAsset{
		{Id: 14, Kind: record.BrandAssetKindBackground, Fingerprint: "444444444444"},
	}, nil).Once()
	w := httptest.NewRecorder()
	r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/issue", nil),
		&record.Settings{Issuer: testResponseIssuer, AppName: "Acme Portal"})
	r.Header.Set("Accept-Language", "de")
	r = r.WithContext(i18n.ResolveRequestLocale(r.Context(), r))

	require.NoError(t, issueAuthCode(w, r, formPostTemplate{fs: web.TemplateFS(), brands: database},
		&record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "form_post"))

	require.Equal(t, http.StatusOK, w.Code)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(w.Body.String()))
	require.NoError(t, err)
	footer := doc.Find("footer")
	require.Equal(t, 1, footer.Length())
	assert.Zero(t, doc.Find("main footer").Length(), "the footer is its own landmark, outside main")
	assert.Equal(t, 1, doc.Find("main + footer").Length())
	assert.True(t, footer.HasClass("auth-footer-panel"), "the brand has a background image")
	const notice = "(öffnet sich in einem neuen Tab)"
	assert.Equal(t, []formPostFooterLink{
		{"https://acme.example/privacy", "_blank", "noopener noreferrer", "Datenschutz", notice},
		{"https://status.acme.example/", "_blank", "noopener noreferrer", "Status", notice},
	}, readFormPostFooterLinks(footer.Find("ul > li > a")))
	contact := footer.Find("p")
	visible := contact.Clone()
	visible.Find(".sr-only").Remove()
	assert.Equal(t, "Brauchen Sie Hilfe? 100%pure@acme.example +442079460958 Supportseite", strings.Join(strings.Fields(visible.Text()), " "))
	assert.Equal(t, []formPostFooterLink{
		{"mailto:100%25pure@acme.example", "", "", "100%pure@acme.example", ""},
		{"tel:+442079460958", "", "", "+442079460958", ""},
		{"https://acme.example/support", "_blank", "noopener noreferrer", "Supportseite", notice},
	}, readFormPostFooterLinks(contact.Find("a")))
	// The response is still the whole form.
	assert.Equal(t, 1, doc.Find(`main form input[name="code"]`).Length())
}

// A brand with no links and no contact leaves the form_post page as it was, with no footer.
func TestFormPost_ABrandWithNoFooterDrawsNone(t *testing.T) {
	const callback = "https://example.com/callback"
	brand := record.NewBrand("Night", record.BrandAppearanceDark, "plum")
	brand.Id = 7
	database := datamocks.NewDatabase(t)
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(&brand, nil).Once()
	w := httptest.NewRecorder()
	r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/issue", nil),
		&record.Settings{Issuer: testResponseIssuer, AppName: "Acme Portal"})

	require.NoError(t, issueAuthCode(w, r, formPostTemplate{fs: web.TemplateFS(), brands: database},
		&record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "form_post"))

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(w.Body.String()))
	require.NoError(t, err)
	assert.Zero(t, doc.Find("footer").Length())
	assert.Zero(t, doc.Find(".auth-footer").Length())
}
