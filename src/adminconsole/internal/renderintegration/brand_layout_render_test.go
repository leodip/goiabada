package renderintegration

import (
	"regexp"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every console page is drawn in the default brand the auth server publishes, as the auth server's
// own pages are: the html element carries data-theme for a light or dark brand and none for an
// automatic one, the color-scheme meta follows, and the brand's stylesheet is linked after main.css,
// at the URL the auth server gave, so its tokens win over main.css's (#810 decision 3).

// brandStylesheetURL is a stylesheet URL as the auth server publishes one: absolute, on its own
// origin, and opaque to the console, which links it as given. Its host is not auth.…, which
// rawKeyRe would read as a catalog key leaked into the page.
const brandStylesheetURL = "https://id.example.test/brand/7/stylesheet.css?v=0123456789ab"

// consolePageHead is what a console page's head says about its look.
type consolePageHead struct {
	dataTheme    string
	hasDataTheme bool
	colorScheme  string
	stylesheets  []string
}

var (
	htmlTagRe        = regexp.MustCompile(`<html[^>]*>`)
	dataThemeAttrRe  = regexp.MustCompile(`\sdata-theme="([^"]*)"`)
	colorSchemeRe    = regexp.MustCompile(`<meta name="color-scheme" content="([^"]*)">`)
	stylesheetLinkRe = regexp.MustCompile(`<link rel="stylesheet" href="([^"]*)">`)
)

func readConsolePageHead(t *testing.T, page string) consolePageHead {
	t.Helper()
	var head consolePageHead
	htmlTag := htmlTagRe.FindString(page)
	require.NotEmpty(t, htmlTag, "the page has no html element")
	if m := dataThemeAttrRe.FindStringSubmatch(htmlTag); m != nil {
		head.dataTheme, head.hasDataTheme = m[1], true
	}
	if m := colorSchemeRe.FindStringSubmatch(page); m != nil {
		head.colorScheme = m[1]
	}
	for _, m := range stylesheetLinkRe.FindAllStringSubmatch(page, -1) {
		head.stylesheets = append(head.stylesheets, m[1])
	}
	return head
}

// consoleLayouts are the console's two layouts, each with a page drawn in it.
var consoleLayouts = []struct {
	layout, path, page string
	bind               map[string]interface{}
}{
	{"/layouts/menu_layout.html", "/account/phone", "/account_phone.html", map[string]interface{}{
		"selectedPhoneCountryUniqueId": "",
		"phoneNumber":                  "",
		"phoneCountries":               []phonecountries.PhoneCountry{},
		"savedSuccessfully":            false,
	}},
	{"/layouts/no_menu_layout.html", "/account/logout", "/account_logout_confirm.html", nil},
}

func TestRender_ConsoleLayoutsAreDrawnInTheDefaultBrand(t *testing.T) {
	for _, layout := range consoleLayouts {
		for _, tc := range []struct {
			name            string
			appearance      string
			wantDataTheme   string
			wantColorScheme string
		}{
			{"a dark brand", "dark", "dark", "dark"},
			{"a light brand", "light", "light", "light"},
			{"an automatic brand", "auto", "", "light dark"},
		} {
			t.Run(layout.layout+" "+tc.name, func(t *testing.T) {
				settings := &api.PublicSettingsResponse{AppName: "Test", SMTPEnabled: true,
					Brand: &api.PublicBrandResponse{Appearance: tc.appearance, StylesheetURL: brandStylesheetURL}}

				out := renderPageWith(t, layout.path, layout.layout, layout.page, layout.bind, nil, "pt-BR", settings)

				head := readConsolePageHead(t, out)
				if tc.wantDataTheme == "" {
					assert.False(t, head.hasDataTheme, "an automatic page carries no data-theme, got %q", head.dataTheme)
				} else {
					assert.Equal(t, tc.wantDataTheme, head.dataTheme)
				}
				assert.Equal(t, tc.wantColorScheme, head.colorScheme)
				require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
				assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])
				assert.Equal(t, brandStylesheetURL, head.stylesheets[1])
			})
		}
	}
}

// A console given no brand, as by an auth server older than brands during a rollout, or one that
// could not read its default brand, still draws its pages: automatic, in main.css's colors, with no
// brand stylesheet. An appearance the console does not know is drawn automatic too, its stylesheet
// still linked.
func TestRender_AConsolePageGivenNoBrandIsDrawnAutomatic(t *testing.T) {
	for _, layout := range consoleLayouts {
		for _, tc := range []struct {
			name            string
			brand           *api.PublicBrandResponse
			wantStylesheets int
		}{
			{"no brand", nil, 1},
			{"an appearance the console does not know", &api.PublicBrandResponse{Appearance: "sepia", StylesheetURL: brandStylesheetURL}, 2},
		} {
			t.Run(layout.layout+" "+tc.name, func(t *testing.T) {
				settings := &api.PublicSettingsResponse{AppName: "Test", SMTPEnabled: true, Brand: tc.brand}

				out := renderPageWith(t, layout.path, layout.layout, layout.page, layout.bind, nil, "pt-BR", settings)

				head := readConsolePageHead(t, out)
				assert.False(t, head.hasDataTheme, "got data-theme %q", head.dataTheme)
				assert.Equal(t, "light dark", head.colorScheme)
				require.Len(t, head.stylesheets, tc.wantStylesheets)
				assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])
			})
		}
	}
}
