package renderintegration

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawKeyRe matches a leaked catalog key (dotted, in visible HTML).
var rawKeyRe = regexp.MustCompile(`\b(adminconsole|common|auth|account|admin|consent|validator|handler|email|system)\.[a-z0-9_]+(?:\.[a-z0-9_]+)+`)

func renderMenuPage(t *testing.T, page string, bind map[string]interface{}) string {
	t.Helper()
	return renderWithLayout(t, "/layouts/menu_layout.html", page, bind)
}

// renderWithLayout is renderMenuPage with the layout named, for the one page that is not a menu page: the
// logout form binding renders under no_menu_layout, the same layout the 404 and 500 pages use.
func renderWithLayout(t *testing.T, layout, page string, bind map[string]interface{}) string {
	t.Helper()
	return renderWithLayoutAs(t, layout, page, bind, nil)
}

// renderWithLayoutAs is renderWithLayout with an ID token on the context, which is how every
// authenticated page reaches the renderer in production: middleware.SessionHandler puts an oauthclient.JwtInfo
// there and render.Renderer.RenderTemplate turns its claims into the `loggedInUser` bind that
// menu_layout.html reads for the dropdown label. Passing nil claims is the anonymous request, which
// is what every other case in this package renders and why the label is blank in all of them.
func renderWithLayoutAs(t *testing.T, layout, page string, bind map[string]interface{},
	idTokenClaims jwt.MapClaims) string {

	t.Helper()
	return renderPage(t, layout, page, bind, idTokenClaims, "pt-BR", true)
}

// renderMenuPageIn is renderMenuPage in the locale named and with email on or off, which every page
// reads from the auth server's public settings as smtpEnabled.
func renderMenuPageIn(t *testing.T, page string, bind map[string]interface{}, locale string, smtpEnabled bool) string {
	t.Helper()
	return renderPage(t, "/layouts/menu_layout.html", page, bind, nil, locale, smtpEnabled)
}

func renderPage(t *testing.T, layout, page string, bind map[string]interface{},
	idTokenClaims jwt.MapClaims, locale string, smtpEnabled bool) string {

	t.Helper()
	return renderPageAt(t, "/", layout, page, bind, idTokenClaims, locale, smtpEnabled)
}

// renderMenuPageAt is renderMenuPage requested at the path named, which the menus read as urlPath to
// mark the page the user is on.
func renderMenuPageAt(t *testing.T, path, page string, bind map[string]interface{}) string {
	t.Helper()
	return renderPageAt(t, path, "/layouts/menu_layout.html", page, bind, nil, "pt-BR", true)
}

func renderPageAt(t *testing.T, path, layout, page string, bind map[string]interface{},
	idTokenClaims jwt.MapClaims, locale string, smtpEnabled bool) string {

	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	settings := &api.PublicSettingsResponse{AppName: "Test", UITheme: "dark", SMTPEnabled: smtpEnabled}
	req = req.WithContext(reqctx.WithSettings(req.Context(), settings))
	if idTokenClaims != nil {
		jwtInfo := oauthclient.JwtInfo{IdToken: &oauth.JwtToken{Claims: idTokenClaims}}
		req = req.WithContext(reqctx.WithJwtInfo(req.Context(), jwtInfo))
	}
	req = req.WithContext(i18n.WithLocale(req.Context(), true, locale))

	h := render.New(web.TemplateFS(), web.StaticFS())
	w := httptest.NewRecorder()
	err := h.RenderTemplate(w, req, layout, page, bind)
	require.NoErrorf(t, err, "render %s in %s (template referenced data the bind lacks?)", page, locale)

	out := w.Body.String()
	// <html lang> must reflect the active locale.
	assert.Containsf(t, out, `lang="`+locale+`"`, "%s: <html lang> not localized", page)
	// No raw catalog key should leak into visible HTML (scripts hold the JS
	// bootstrap keys legitimately, so strip them first).
	visible := regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(out, "")
	if leak := rawKeyRe.FindString(visible); leak != "" {
		t.Errorf("%s: raw i18n key leaked into visible HTML: %q", page, leak)
	}
	return out
}

// assertSendsTheLoadedPermissionIds is the check both permission pages owe: the page takes the ids
// of the grants it rendered once, after they are in assignedPermissions, sends that copy with every
// save as expectedPermissionIds, and never edits it. A copy taken later, or edited, would send the
// administrator's edited set as the loaded one and every save would pass the check (#428).
func assertSendsTheLoadedPermissionIds(t *testing.T, out string) {
	t.Helper()
	const copyTaken = "const loadedPermissionIds = Object.keys(assignedPermissions).map(function(key) { return parseInt(key, 10); });"
	loaded := regexp.MustCompile(`var assignedPermissions = \{\s*3\s*: \{\s*"Scope": "some-resource:read"\s*\},\s*4\s*: \{\s*"Scope": "some-resource:write"\s*\}\s*\};`).FindStringIndex(out)
	require.NotNil(t, loaded, "the page renders the loaded grants into assignedPermissions")
	copyAt := strings.Index(out, copyTaken)
	require.NotEqual(t, -1, copyAt, "the page keeps the ids of the loaded grants")
	assert.Greater(t, copyAt, loaded[1]-1, "the copy is taken after the loaded grants are in the object")

	assert.Contains(t, out, `"expectedPermissionIds": loadedPermissionIds`)
	assert.NotRegexp(t, `loadedPermissionIds\.(push|splice|pop|shift|unshift)\(`, out)
	assert.NotRegexp(t, `loadedPermissionIds\s*=[^=]`, strings.Replace(out, copyTaken, "", 1))
}
