package render

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// A card page draws its brand's logo, dark logo, name and favicon (#813 decisions 4 and 5), in both
// layouts the auth server's card pages are drawn in.

const (
	logoPath     = "/brand-assets/11?v=111111111111"
	darkLogoPath = "/brand-assets/12?v=222222222222"
	faviconPath  = "/brand-assets/13?v=333333333333"
)

// kitAssets are the brand's logo, dark logo and favicon, as stored and read without their bytes.
var kitAssets = []record.BrandAsset{
	{Id: 11, Kind: record.BrandAssetKindLogo, ContentType: "image/png", Fingerprint: "111111111111", Width: 200, Height: 60},
	{Id: 12, Kind: record.BrandAssetKindLogo, ContentType: "image/webp", Fingerprint: "222222222222", Width: 200, Height: 60},
	{Id: 13, Kind: record.BrandAssetKindFavicon, ContentType: "image/png", Fingerprint: "333333333333", Width: 64, Height: 64},
}

var cardLayouts = []struct{ layout, page string }{
	{"/layouts/auth_layout.html", "/logged_out.html"},
	{"/layouts/no_menu_layout.html", "/not_found.html"},
}

// kitPageBrand is the default brand of id 7, on Blueberry, in appearance, its logo slot naming
// asset 11 when logo is set, its dark logo slot asset 12 when darkLogo is, and its favicon slot
// asset 13 when favicon is.
func kitPageBrand(appearance record.BrandAppearance, logo, darkLogo, favicon, hideAppName bool) *record.Brand {
	brand := record.NewBrand("Shop", appearance, "blueberry")
	brand.Id = 7
	brand.HideAppName = hideAppName
	if logo {
		brand.LogoAssetId = sql.NullInt64{Int64: 11, Valid: true}
	}
	if darkLogo {
		brand.DarkLogoAssetId = sql.NullInt64{Int64: 12, Valid: true}
	}
	if favicon {
		brand.FaviconAssetId = sql.NullInt64{Int64: 13, Valid: true}
	}
	return &brand
}

func renderKitPage(t *testing.T, layout, page string, brands *defaultBrandStub) *goquery.Document {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Acme Portal"}))
	buf, err := New(web.TemplateFS(), web.StaticFS(), brands).RenderTemplateToBuffer(req, layout, page, map[string]interface{}{})
	require.NoError(t, err)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(buf.String()))
	require.NoError(t, err)
	return doc
}

// cardLogo is what a card says about its brand's logo: the one image drawn, its src and alt, and
// the dark-mode source a picture gives it, if any.
type cardLogo struct {
	images      int
	src         string
	alt         string
	hasAlt      bool
	darkSources []string
	darkMedia   []string
}

func readCardLogo(doc *goquery.Document) cardLogo {
	var logo cardLogo
	images := doc.Find(".auth-card .auth-logo img")
	logo.images = images.Length()
	logo.src, _ = images.First().Attr("src")
	logo.alt, logo.hasAlt = images.First().Attr("alt")
	doc.Find(".auth-card .auth-logo picture source").Each(func(_ int, source *goquery.Selection) {
		srcset, _ := source.Attr("srcset")
		media, _ := source.Attr("media")
		logo.darkSources = append(logo.darkSources, srcset)
		logo.darkMedia = append(logo.darkMedia, media)
	})
	return logo
}

// The logo sits above the app name, drawn as one image, so one is in the accessibility tree: the
// light one on a light page and on an automatic page without a dark logo; the dark one on a dark
// page, the light one there when there is none; and on an automatic page with both, the light one
// with the dark one as its source while the device prefers dark (#813 decision 5).
func TestRender_TheCardDrawsTheLogoOfItsMode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		appearance record.BrandAppearance
		darkLogo   bool
		wantSrc    string
		wantDark   []string
	}{
		{"light, a logo alone", record.BrandAppearanceLight, false, logoPath, nil},
		{"light, both logos", record.BrandAppearanceLight, true, logoPath, nil},
		{"dark, a logo alone", record.BrandAppearanceDark, false, logoPath, nil},
		{"dark, both logos", record.BrandAppearanceDark, true, darkLogoPath, nil},
		{"automatic, a logo alone", record.BrandAppearanceAuto, false, logoPath, nil},
		{"automatic, both logos", record.BrandAppearanceAuto, true, logoPath, []string{darkLogoPath}},
	} {
		for _, layout := range cardLayouts {
			t.Run(layout.layout+" "+tc.name, func(t *testing.T) {
				brands := &defaultBrandStub{brand: kitPageBrand(tc.appearance, true, tc.darkLogo, false, false), assets: kitAssets}

				doc := renderKitPage(t, layout.layout, layout.page, brands)

				logo := readCardLogo(doc)
				assert.Equal(t, 1, logo.images)
				assert.Equal(t, tc.wantSrc, logo.src)
				assert.True(t, logo.hasAlt, "every image carries an alt attribute")
				assert.Empty(t, logo.alt, "the name is shown as text, so the logo is not announced")
				assert.Equal(t, tc.wantDark, logo.darkSources)
				if tc.wantDark != nil {
					assert.Equal(t, []string{"(prefers-color-scheme: dark)"}, logo.darkMedia)
				}
				assert.Equal(t, "Acme Portal", strings.TrimSpace(doc.Find(".auth-card p.auth-brand").Text()))
				// The logo comes before the name.
				assert.Equal(t, 1, doc.Find(".auth-card .auth-logo + p.auth-brand").Length())
			})
		}
	}
}

// While the switch hides the name text, the logo's alt is the app name, so a screen reader still
// says it; without a logo the switch has no effect, so the name never disappears with nothing in its
// place (#813 decision 5).
func TestRender_TheSwitchHidesTheNameOnlyBesideALogo(t *testing.T) {
	for _, layout := range cardLayouts {
		t.Run(layout.layout+" a logo with the name hidden", func(t *testing.T) {
			brands := &defaultBrandStub{brand: kitPageBrand(record.BrandAppearanceAuto, true, true, false, true), assets: kitAssets}

			doc := renderKitPage(t, layout.layout, layout.page, brands)

			logo := readCardLogo(doc)
			assert.Equal(t, 1, logo.images)
			assert.Equal(t, "Acme Portal", logo.alt)
			assert.Zero(t, doc.Find(".auth-card p.auth-brand").Length(), "the name text is hidden")
		})
		t.Run(layout.layout+" the switch without a logo", func(t *testing.T) {
			brands := &defaultBrandStub{brand: kitPageBrand(record.BrandAppearanceAuto, false, false, false, true), assets: kitAssets}

			doc := renderKitPage(t, layout.layout, layout.page, brands)

			assert.Zero(t, doc.Find(".auth-card .auth-logo").Length())
			assert.Zero(t, doc.Find(".auth-card img").Length())
			assert.Equal(t, "Acme Portal", strings.TrimSpace(doc.Find(".auth-card p.auth-brand").Text()))
		})
		t.Run(layout.layout+" no logo", func(t *testing.T) {
			brands := &defaultBrandStub{brand: kitPageBrand(record.BrandAppearanceDark, false, false, false, false)}

			doc := renderKitPage(t, layout.layout, layout.page, brands)

			assert.Zero(t, doc.Find(".auth-card .auth-logo").Length(), "a brand without a logo is drawn as today")
			assert.Equal(t, "Acme Portal", strings.TrimSpace(doc.Find(".auth-card p.auth-brand").Text()))
		})
	}
}

// readIconLinks reads each link of a page's head but its stylesheets, as its rel, type, sizes and
// href, space-separated, an absent attribute as empty.
func readIconLinks(doc *goquery.Document) []string {
	var links []string
	doc.Find(`head link`).Each(func(_ int, link *goquery.Selection) {
		rel, _ := link.Attr("rel")
		if rel == "stylesheet" {
			return
		}
		typ, _ := link.Attr("type")
		sizes, _ := link.Attr("sizes")
		href, _ := link.Attr("href")
		links = append(links, strings.Join([]string{rel, typ, sizes, href}, " "))
	})
	return links
}

// A page whose brand has a favicon links it twice, as its icon and as its Apple touch icon, and
// links neither favicon.ico nor the web manifest; a page whose brand has none links exactly what
// pages linked before the kit (#813 decision 4).
func TestRender_ThePageLinksItsBrandsFavicon(t *testing.T) {
	for _, layout := range cardLayouts {
		t.Run(layout.layout+" a favicon", func(t *testing.T) {
			brands := &defaultBrandStub{brand: kitPageBrand(record.BrandAppearanceAuto, false, false, true, false), assets: kitAssets}

			doc := renderKitPage(t, layout.layout, layout.page, brands)

			assert.Equal(t, []string{
				"icon image/png  " + faviconPath,
				"apple-touch-icon   " + faviconPath,
			}, readIconLinks(doc))
		})
		t.Run(layout.layout+" no favicon", func(t *testing.T) {
			brands := &defaultBrandStub{brand: kitPageBrand(record.BrandAppearanceAuto, true, false, false, false), assets: kitAssets}

			doc := renderKitPage(t, layout.layout, layout.page, brands)

			assert.Equal(t, []string{
				"icon   /static/favicon/favicon.ico",
				"apple-touch-icon  180x180 /static/favicon/apple-touch-icon.png",
				"icon image/png 32x32 /static/favicon/favicon-32x32.png",
				"icon image/png 16x16 /static/favicon/favicon-16x16.png",
				"manifest   /static/favicon/site.webmanifest",
			}, readIconLinks(doc))
		})
	}
}

// A brand's assets that cannot be read leave the page as an unreadable brand does, automatic in
// main.css's colors with no brand stylesheet, logo or favicon, and the fault is logged: a page is
// never refused over its look.
func TestRender_ABrandWhoseAssetsCannotBeReadIsDrawnAsToday(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	brands := &defaultBrandStub{brand: kitPageBrand(record.BrandAppearanceDark, true, true, true, true),
		assetErr: errs.New("the database went away")}

	doc := renderKitPage(t, "/layouts/auth_layout.html", "/logged_out.html", brands)

	_, hasTheme := doc.Find("html").Attr("data-theme")
	assert.False(t, hasTheme)
	assert.Equal(t, 1, doc.Find(`link[rel="stylesheet"]`).Length(), "main.css alone")
	assert.Zero(t, doc.Find(".auth-logo").Length())
	assert.Equal(t, "Acme Portal", strings.TrimSpace(doc.Find("p.auth-brand").Text()))
	assert.Equal(t, 1, doc.Find(`link[rel="manifest"]`).Length())
	var messages []string
	for _, record := range logs.Records() {
		messages = append(messages, record.Message)
	}
	assert.Equal(t, []string{"unable to read the assets of the brand a page is drawn in"}, messages)
}

// The page brand names its images by their paths, which carry each asset's fingerprint, so a page
// links an image a browser may keep for a year; the public settings make them absolute.
func TestClientPageBrand_NamesTheLogosAndTheFavicon(t *testing.T) {
	brand := kitPageBrand(record.BrandAppearanceAuto, true, true, true, true)

	page := ClientPageBrand(t.Context(), &defaultBrandStub{brand: brand, assets: kitAssets}, "")

	assert.Equal(t, logoPath, page.Logo)
	assert.Equal(t, darkLogoPath, page.DarkLogo)
	assert.Equal(t, faviconPath, page.Favicon)
	assert.True(t, page.HideAppName)

	// The switch has no effect without a logo, and neither has a dark logo, which a write refuses.
	brand = kitPageBrand(record.BrandAppearanceAuto, false, true, false, true)
	page = ClientPageBrand(t.Context(), &defaultBrandStub{brand: brand, assets: kitAssets}, "")
	assert.Empty(t, page.Logo)
	assert.Empty(t, page.DarkLogo)
	assert.False(t, page.HideAppName)
}
