package renderintegration

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The console draws its brand's kit (#813 decisions 4, 5 and 9). An admin page, one drawn with the
// admin menu, links the brand's colors-only stylesheet and keeps Goiabada's icons; every other page,
// Account, home and each card page, links the full stylesheet and the brand's favicon. The logo is
// drawn on both: above the app name on a card, and before it in the header's link to home. Its alt
// is empty while the name is shown as text and is the app name while the switch hides the name.

// The URLs as the auth server publishes them: absolute and opaque to the console. Their host is not
// auth.…, which rawKeyRe would read as a catalog key leaked into the page.
const (
	kitStylesheetURL       = "https://id.example.test/brand/7/stylesheet.css?v=0123456789ab"
	kitColorsStylesheetURL = "https://id.example.test/brand/7/colors.css?v=ba9876543210"
	kitLogoURL             = "https://id.example.test/brand-assets/11?v=1111"
	kitDarkLogoURL         = "https://id.example.test/brand-assets/12?v=2222"
	kitFaviconURL          = "https://id.example.test/brand-assets/13?v=3333"
)

// goiabadaIcons are the links a page carries for Goiabada's own icons, in their order.
var goiabadaIcons = []string{
	`<link rel="icon" href="/static/favicon/favicon.ico">`,
	`<link rel="apple-touch-icon" sizes="180x180" href="/static/favicon/apple-touch-icon.png">`,
	`<link rel="icon" type="image/png" sizes="32x32" href="/static/favicon/favicon-32x32.png">`,
	`<link rel="icon" type="image/png" sizes="16x16" href="/static/favicon/favicon-16x16.png">`,
	`<link rel="manifest" href="/static/favicon/site.webmanifest">`,
}

// brandFaviconIcons are the links a page carries for a brand's favicon, the one stored image.
var brandFaviconIcons = []string{
	`<link rel="icon" type="image/png" href="` + kitFaviconURL + `">`,
	`<link rel="apple-touch-icon" href="` + kitFaviconURL + `">`,
}

var iconLinkRe = regexp.MustCompile(`<link rel="(?:icon|apple-touch-icon|manifest)"[^>]*>`)

// consolePage is a page of the console, drawn in its layout at its path.
type consolePage struct {
	name, layout, path, page string
	bind                     func() map[string]interface{}
}

var (
	adminConsolePage = consolePage{"an admin page", "/layouts/menu_layout.html", "/admin/settings/keys",
		"/admin_settings_keys.html", func() map[string]interface{} {
			created := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
			return map[string]interface{}{"keys": []adminsettingshandlers.SettingsKey{{
				Id: 1, CreatedAt: &created, State: "current", KeyIdentifier: "key-1", Type: "RSA", Algorithm: "RS256"}}}
		}}
	accountConsolePage = consolePage{"an Account page", "/layouts/menu_layout.html", "/account/phone",
		"/account_phone.html", func() map[string]interface{} {
			return map[string]interface{}{"selectedPhoneCountryUniqueId": "", "phoneNumber": "",
				"phoneCountries": []phonecountries.PhoneCountry{}, "savedSuccessfully": false}
		}}
	homeConsolePage = consolePage{"the home page", "/layouts/no_menu_layout.html", "/",
		"/index.html", func() map[string]interface{} {
			return map[string]interface{}{"AuthServerBaseUrl": "https://id.example.test", "IsAuthenticated": false,
				"LoggedInUser": "", "LogoutLink": "", "SessionEnded": false}
		}}
	// An error answered for an admin URL is a card page, and so an end-user page (#813 decision 9).
	errorConsolePage = consolePage{"an error page at an admin URL", "/layouts/no_menu_layout.html",
		"/admin/clients/7/settings", "/error.html", func() map[string]interface{} {
			return map[string]interface{}{"requestId": "req-1"}
		}}
)

func renderConsolePage(t *testing.T, p consolePage, brand *api.PublicBrandResponse) string {
	t.Helper()
	settings := &api.PublicSettingsResponse{AppName: "Acme Portal", SMTPEnabled: true, Brand: brand}
	return renderPageWith(t, p.path, p.layout, p.page, p.bind(), nil, "en", settings)
}

// kitBrand is a brand with every part of the kit the console draws.
func kitBrand(appearance string) *api.PublicBrandResponse {
	return &api.PublicBrandResponse{Appearance: appearance, StylesheetURL: kitStylesheetURL,
		ColorsStylesheetURL: kitColorsStylesheetURL, LogoURL: kitLogoURL, DarkLogoURL: kitDarkLogoURL,
		FaviconURL: kitFaviconURL}
}

func TestRender_AnAdminPageLinksTheColorsOnlyStylesheetAndKeepsGoiabadasIcons(t *testing.T) {
	out := renderConsolePage(t, adminConsolePage, kitBrand("auto"))

	head := readConsolePageHead(t, out)
	require.Len(t, head.stylesheets, 2, "main.css, then one brand stylesheet")
	assert.Equal(t, kitColorsStylesheetURL, head.stylesheets[1])
	assert.Equal(t, goiabadaIcons, iconLinkRe.FindAllString(out, -1))
}

func TestRender_AnEndUserPageLinksTheFullStylesheetAndTheBrandsFavicon(t *testing.T) {
	for _, p := range []consolePage{accountConsolePage, homeConsolePage, errorConsolePage} {
		t.Run(p.name, func(t *testing.T) {
			out := renderConsolePage(t, p, kitBrand("auto"))

			head := readConsolePageHead(t, out)
			require.Len(t, head.stylesheets, 2, "main.css, then one brand stylesheet")
			assert.Equal(t, kitStylesheetURL, head.stylesheets[1])
			assert.Equal(t, brandFaviconIcons, iconLinkRe.FindAllString(out, -1),
				"the brand's favicon in place of Goiabada's icons and manifest")
		})
	}
}

// A brand with no favicon leaves every page with Goiabada's icons, as before.
func TestRender_ABrandWithoutAFaviconKeepsGoiabadasIcons(t *testing.T) {
	brand := kitBrand("auto")
	brand.FaviconURL = ""
	for _, p := range []consolePage{adminConsolePage, accountConsolePage, homeConsolePage} {
		t.Run(p.name, func(t *testing.T) {
			out := renderConsolePage(t, p, brand)
			assert.Equal(t, goiabadaIcons, iconLinkRe.FindAllString(out, -1))
		})
	}
}

// brandMark is where a page draws its brand: the card's logo and name, or the header's link to home.
type brandMark struct {
	html string
	// images are the img elements in it, and sources the source elements of a picture.
	images, sources []string
	text            string
}

var (
	cardLogoRe        = regexp.MustCompile(`(?s)<div class="auth-logo">(.*?)</div>`)
	cardNameRe        = regexp.MustCompile(`<p class="auth-brand">([^<]*)</p>`)
	headerBrandLinkRe = regexp.MustCompile(`(?s)<a class="app-header-brand" href="/">(.*?)</a>`)
	sidebarBrandRe    = regexp.MustCompile(`(?s)<a class="sidebar-brand" href="/">(.*?)</a>`)
	imgRe             = regexp.MustCompile(`<img [^>]*>`)
	sourceRe          = regexp.MustCompile(`<source [^>]*>`)
	markupTagRe       = regexp.MustCompile(`<[^>]*>`)
)

func markOf(html string) brandMark {
	return brandMark{
		html:    html,
		images:  imgRe.FindAllString(html, -1),
		sources: sourceRe.FindAllString(html, -1),
		text:    strings.TrimSpace(markupTagRe.ReplaceAllString(html, "")),
	}
}

// cardMarks reads a card's logo and the app name's text below it.
func cardMarks(t *testing.T, out string) (logo brandMark, hasLogo bool, name string, hasName bool) {
	t.Helper()
	logos := cardLogoRe.FindAllStringSubmatch(out, -1)
	require.LessOrEqual(t, len(logos), 1, "one logo on the card")
	if len(logos) == 1 {
		logo, hasLogo = markOf(logos[0][1]), true
	}
	names := cardNameRe.FindAllStringSubmatch(out, -1)
	require.LessOrEqual(t, len(names), 1)
	if len(names) == 1 {
		name, hasName = names[0][1], true
	}
	return
}

// headerMarks reads the two links to home a menu page draws its brand in: the header's, and the
// sidebar's head, which stands in for the header on a wide screen.
func headerMarks(t *testing.T, out string) []brandMark {
	t.Helper()
	header := headerBrandLinkRe.FindStringSubmatch(out)
	require.NotNil(t, header, "the header's link to home")
	sidebar := sidebarBrandRe.FindStringSubmatch(out)
	require.NotNil(t, sidebar, "the sidebar's link to home")
	return []brandMark{markOf(header[1]), markOf(sidebar[1])}
}

// The logo each appearance draws: a light page and an automatic one without a dark logo the light
// logo; a dark page the dark logo, or the light one without it; an automatic page with both a
// picture whose source switches to the dark logo when the device asks for dark.
var logoModeCases = []struct {
	name        string
	appearance  string
	darkLogo    string
	wantImage   string
	wantSources []string
}{
	{"light with a dark logo", "light", kitDarkLogoURL, `<img src="` + kitLogoURL + `" alt="">`, nil},
	{"light without one", "light", "", `<img src="` + kitLogoURL + `" alt="">`, nil},
	{"dark with a dark logo", "dark", kitDarkLogoURL, `<img src="` + kitDarkLogoURL + `" alt="">`, nil},
	{"dark without one", "dark", "", `<img src="` + kitLogoURL + `" alt="">`, nil},
	{"automatic with a dark logo", "auto", kitDarkLogoURL, `<img src="` + kitLogoURL + `" alt="">`,
		[]string{`<source srcset="` + kitDarkLogoURL + `" media="(prefers-color-scheme: dark)">`}},
	{"automatic without one", "auto", "", `<img src="` + kitLogoURL + `" alt="">`, nil},
}

func TestRender_TheConsolesCardDrawsTheLogoOfItsModeAboveTheName(t *testing.T) {
	for _, p := range []consolePage{homeConsolePage, errorConsolePage} {
		for _, tc := range logoModeCases {
			t.Run(p.name+" "+tc.name, func(t *testing.T) {
				brand := kitBrand(tc.appearance)
				brand.DarkLogoURL = tc.darkLogo

				out := renderConsolePage(t, p, brand)

				logo, hasLogo, name, hasName := cardMarks(t, out)
				require.True(t, hasLogo, "the card draws the logo")
				assert.Equal(t, []string{tc.wantImage}, logo.images, "one image, the alt empty beside the name")
				assert.Equal(t, tc.wantSources, logo.sources)
				assert.True(t, hasName)
				assert.Equal(t, "Acme Portal", name)
				assert.Less(t, strings.Index(out, `<div class="auth-logo">`), strings.Index(out, `<p class="auth-brand">`),
					"the logo sits above the name")
			})
		}
	}
}

func TestRender_TheConsolesHeaderDrawsTheLogoOfItsModeBeforeTheName(t *testing.T) {
	for _, p := range []consolePage{adminConsolePage, accountConsolePage} {
		for _, tc := range logoModeCases {
			t.Run(p.name+" "+tc.name, func(t *testing.T) {
				brand := kitBrand(tc.appearance)
				brand.DarkLogoURL = tc.darkLogo

				out := renderConsolePage(t, p, brand)

				for _, mark := range headerMarks(t, out) {
					assert.Equal(t, []string{tc.wantImage}, mark.images, "one image, the alt empty beside the name")
					assert.Equal(t, tc.wantSources, mark.sources)
					assert.Equal(t, "Acme Portal", mark.text, "the name is the link's text")
					assert.Less(t, strings.Index(mark.html, "<img"), strings.Index(mark.html, "Acme Portal"),
						"the logo sits before the name")
				}
			})
		}
	}
}

// While the switch hides the name, the logo stands in for it: its alt is the app name, which is
// then the header link's accessible name, and the name's text is drawn nowhere.
func TestRender_TheSwitchHidesTheNameAndTheLogoTakesItsAlt(t *testing.T) {
	brand := kitBrand("light")
	brand.HideAppName = true
	wantImage := `<img src="` + kitLogoURL + `" alt="Acme Portal">`

	for _, p := range []consolePage{homeConsolePage, errorConsolePage} {
		t.Run(p.name, func(t *testing.T) {
			out := renderConsolePage(t, p, brand)

			logo, hasLogo, _, hasName := cardMarks(t, out)
			require.True(t, hasLogo)
			assert.Equal(t, []string{wantImage}, logo.images)
			assert.False(t, hasName, "the name's text is hidden")
		})
	}
	for _, p := range []consolePage{adminConsolePage, accountConsolePage} {
		t.Run(p.name, func(t *testing.T) {
			out := renderConsolePage(t, p, brand)

			for _, mark := range headerMarks(t, out) {
				assert.Equal(t, []string{wantImage}, mark.images)
				assert.Empty(t, mark.text, "the name's text is hidden")
			}
		})
	}
}

// Without a logo the switch has no effect, so the name never disappears with nothing in its place,
// and no image is drawn: a page is drawn as before the kit.
func TestRender_WithoutALogoTheNameIsDrawnWhateverTheSwitch(t *testing.T) {
	for _, brand := range map[string]*api.PublicBrandResponse{
		"a brand without a logo, the switch on": {Appearance: "auto", StylesheetURL: kitStylesheetURL,
			ColorsStylesheetURL: kitColorsStylesheetURL, HideAppName: true},
		"no brand": nil,
	} {
		for _, p := range []consolePage{homeConsolePage, errorConsolePage} {
			out := renderConsolePage(t, p, brand)

			_, hasLogo, name, hasName := cardMarks(t, out)
			assert.False(t, hasLogo)
			assert.True(t, hasName)
			assert.Equal(t, "Acme Portal", name)
		}
		for _, p := range []consolePage{adminConsolePage, accountConsolePage} {
			out := renderConsolePage(t, p, brand)

			for _, mark := range headerMarks(t, out) {
				assert.Empty(t, mark.images)
				assert.Equal(t, "Acme Portal", mark.text)
			}
		}
	}
}
