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
)

// The form_post page is a card page parsed alone, with no layout, so it draws its brand's logo, name
// and favicon itself, as the layouts do (#813 decisions 4 and 5).
func TestFormPost_TheCardDrawsTheBrandsLogoAndFavicon(t *testing.T) {
	const callback = "https://example.com/callback"
	brand := record.NewBrand("Night", record.BrandAppearanceAuto, "plum")
	brand.Id = 7
	brand.HideAppName = true
	brand.LogoAssetId = sql.NullInt64{Int64: 11, Valid: true}
	brand.DarkLogoAssetId = sql.NullInt64{Int64: 12, Valid: true}
	brand.FaviconAssetId = sql.NullInt64{Int64: 13, Valid: true}
	database := datamocks.NewDatabase(t)
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(&brand, nil).Once()
	database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{11, 12, 13}).Return([]record.BrandAsset{
		{Id: 11, Kind: record.BrandAssetKindLogo, Fingerprint: "111111111111"},
		{Id: 12, Kind: record.BrandAssetKindLogo, Fingerprint: "222222222222"},
		{Id: 13, Kind: record.BrandAssetKindFavicon, Fingerprint: "333333333333"},
	}, nil).Once()
	w := httptest.NewRecorder()
	r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/issue", nil),
		&record.Settings{Issuer: testResponseIssuer, AppName: "Acme Portal"})

	require.NoError(t, issueAuthCode(w, r, formPostTemplate{fs: web.TemplateFS(), brands: database},
		&record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "form_post"))

	require.Equal(t, http.StatusOK, w.Code)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(w.Body.String()))
	require.NoError(t, err)
	img := doc.Find(".auth-card .auth-logo picture img")
	require.Equal(t, 1, img.Length())
	src, _ := img.Attr("src")
	alt, hasAlt := img.Attr("alt")
	assert.Equal(t, "/brand-assets/11?v=111111111111", src)
	assert.True(t, hasAlt)
	assert.Equal(t, "Acme Portal", alt, "the name text is hidden, so the logo carries it")
	srcset, _ := doc.Find(".auth-card .auth-logo picture source").Attr("srcset")
	assert.Equal(t, "/brand-assets/12?v=222222222222", srcset)
	assert.Zero(t, doc.Find("p.auth-brand").Length())
	icon, _ := doc.Find(`head link[rel="icon"]`).Attr("href")
	touch, _ := doc.Find(`head link[rel="apple-touch-icon"]`).Attr("href")
	assert.Equal(t, "/brand-assets/13?v=333333333333", icon)
	assert.Equal(t, "/brand-assets/13?v=333333333333", touch)
}

// A brand with no logo leaves the form_post card as it was: the name, and no icon link, as before.
func TestFormPost_ABrandWithoutAKitIsDrawnAsBefore(t *testing.T) {
	const callback = "https://example.com/callback"
	brand := record.NewBrand("Night", record.BrandAppearanceDark, "plum")
	brand.Id = 7
	brand.HideAppName = true
	database := datamocks.NewDatabase(t)
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(&brand, nil).Once()
	w := httptest.NewRecorder()
	r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/issue", nil),
		&record.Settings{Issuer: testResponseIssuer, AppName: "Acme Portal"})

	require.NoError(t, issueAuthCode(w, r, formPostTemplate{fs: web.TemplateFS(), brands: database},
		&record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "form_post"))

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(w.Body.String()))
	require.NoError(t, err)
	assert.Zero(t, doc.Find(".auth-logo").Length())
	assert.Equal(t, "Acme Portal", strings.TrimSpace(doc.Find("p.auth-brand").Text()))
	assert.Zero(t, doc.Find(`head link[rel="icon"], head link[rel="apple-touch-icon"]`).Length())
}
