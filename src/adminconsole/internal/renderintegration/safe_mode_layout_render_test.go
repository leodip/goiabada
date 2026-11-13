package renderintegration

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// While the console session is in safe mode, every console page is drawn from the safe links the
// auth server publishes beside the brand's own: an admin page links the safe colors-only stylesheet
// and every other page the safe full one. The logo and favicon stay. An admin page says that safe
// mode is on, and how to leave it, whether the session or the auth server's switch turned it on
// (#816 decisions 1 and 2).

const (
	kitSafeStylesheetURL       = "https://id.example.test/brand/7/safe-stylesheet.css?v=5afe5afe5afe"
	kitSafeColorsStylesheetURL = "https://id.example.test/brand/7/safe-colors.css?v=c010c010c010"

	sessionNotice = "Safe mode is on: these pages leave out the brand&#39;s custom CSS, custom palette and " +
		"uploaded font, which stay saved as they are. Sign out to leave safe mode."
	switchNotice = "Safe mode is on for every page, by GOIABADA_AUTHSERVER_BRAND_SAFE_MODE: pages leave out " +
		"every brand&#39;s custom CSS, custom palette and uploaded font, which stay saved as they are. Unset it " +
		"and restart the auth server to leave safe mode."
)

var safeModeNoticeRe = regexp.MustCompile(`<p class="notice notice-caution mb-6" role="status">([^<]*)</p>`)

// safeKitBrand is kitBrand publishing its safe links too.
func safeKitBrand() *api.PublicBrandResponse {
	brand := kitBrand("auto")
	brand.SafeStylesheetURL = kitSafeStylesheetURL
	brand.SafeColorsStylesheetURL = kitSafeColorsStylesheetURL
	return brand
}

// renderConsolePageSafe draws p in brand for a request whose console session is, or is not, in
// safe mode.
func renderConsolePageSafe(t *testing.T, p consolePage, brand *api.PublicBrandResponse, safe bool) string {
	t.Helper()
	settings := &api.PublicSettingsResponse{AppName: "Acme Portal", SMTPEnabled: true, Brand: brand}
	req := httptest.NewRequest(http.MethodGet, p.path, nil)
	ctx := reqctx.WithSettings(req.Context(), settings)
	ctx = reqctx.WithSafeMode(ctx, safe)
	ctx = i18n.WithLocale(ctx, true, "en")
	w := httptest.NewRecorder()
	require.NoError(t, render.New(web.TemplateFS(), web.StaticFS()).RenderTemplate(w, req.WithContext(ctx), p.layout, p.page, p.bind()))
	return w.Body.String()
}

func TestRender_APageInSafeModeLinksTheSafeStylesheet(t *testing.T) {
	for _, tc := range []struct {
		page consolePage
		want string
	}{
		{adminConsolePage, kitSafeColorsStylesheetURL},
		{accountConsolePage, kitSafeStylesheetURL},
		{homeConsolePage, kitSafeStylesheetURL},
		{errorConsolePage, kitSafeStylesheetURL},
	} {
		t.Run(tc.page.name, func(t *testing.T) {
			out := renderConsolePageSafe(t, tc.page, safeKitBrand(), true)

			head := readConsolePageHead(t, out)
			require.Len(t, head.stylesheets, 2, "main.css, then one brand stylesheet")
			assert.Equal(t, tc.want, head.stylesheets[1])
			assert.Contains(t, out, `<img src="`+kitLogoURL+`"`, "the logo stays")
		})
	}
	t.Run("the favicon stays", func(t *testing.T) {
		out := renderConsolePageSafe(t, accountConsolePage, safeKitBrand(), true)
		assert.Equal(t, brandFaviconIcons, iconLinkRe.FindAllString(out, -1))
	})
}

// Out of safe mode, the same brand is drawn from its own links.
func TestRender_APageOutOfSafeModeLinksTheBrandsOwnStylesheet(t *testing.T) {
	for _, tc := range []struct {
		page consolePage
		want string
	}{
		{adminConsolePage, kitColorsStylesheetURL},
		{accountConsolePage, kitStylesheetURL},
	} {
		t.Run(tc.page.name, func(t *testing.T) {
			head := readConsolePageHead(t, renderConsolePageSafe(t, tc.page, safeKitBrand(), false))
			require.Len(t, head.stylesheets, 2)
			assert.Equal(t, tc.want, head.stylesheets[1])
		})
	}
}

// An auth server that publishes no safe links, as an older one does during a rolling upgrade, leaves
// a page in safe mode with no brand stylesheet at all, rather than the brand's own.
func TestRender_APageInSafeModeLinksNoBrandStylesheetWithoutSafeLinks(t *testing.T) {
	for _, p := range []consolePage{adminConsolePage, accountConsolePage} {
		t.Run(p.name, func(t *testing.T) {
			head := readConsolePageHead(t, renderConsolePageSafe(t, p, kitBrand("auto"), true))
			assert.Len(t, head.stylesheets, 1, "main.css alone")
		})
	}
}

// The notice is on admin pages alone, from either source. The switch's wins over the session's,
// since signing out does not end it.
func TestRender_AnAdminPageSaysSafeModeIsOn(t *testing.T) {
	switchedOn := func() *api.PublicBrandResponse {
		brand := safeKitBrand()
		brand.SafeMode = true
		return brand
	}
	for _, tc := range []struct {
		name  string
		page  consolePage
		brand *api.PublicBrandResponse
		safe  bool
		want  []string
	}{
		{"the session's", adminConsolePage, safeKitBrand(), true, []string{sessionNotice}},
		{"the switch's", adminConsolePage, switchedOn(), false, []string{switchNotice}},
		{"both", adminConsolePage, switchedOn(), true, []string{switchNotice}},
		{"neither", adminConsolePage, safeKitBrand(), false, nil},
		{"the session's, with no brand", adminConsolePage, nil, true, []string{sessionNotice}},
		{"the session's on an Account page", accountConsolePage, safeKitBrand(), true, nil},
		{"the switch's on an Account page", accountConsolePage, switchedOn(), false, nil},
		{"the session's on the home page", homeConsolePage, safeKitBrand(), true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderConsolePageSafe(t, tc.page, tc.brand, tc.safe)

			var notices []string
			for _, m := range safeModeNoticeRe.FindAllStringSubmatch(out, -1) {
				notices = append(notices, m[1])
			}
			assert.Equal(t, tc.want, notices)
		})
	}
}
