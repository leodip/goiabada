package renderintegration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The 404 page, end to end: the real render.Renderer.NotFound over the real embedded template FS, at the
// HTTP seam. Everything else in this package renders a bind through RenderTemplate and reads only
// the body; this one reads the status too, because the status is half of what decision 11 changed
// and the console is invisible to the integration tier, which drives the auth server and only ever
// mentions the console's base URL as a string to assert against (#279).
func TestRender_NotFoundPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/clients/not-a-number/settings", nil)
	settings := &api.PublicSettingsResponse{AppName: "Test", UITheme: "dark", SMTPEnabled: true}
	req = req.WithContext(reqctx.WithSettings(req.Context(), settings))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))

	w := httptest.NewRecorder()
	render.New(web.TemplateFS()).NotFound(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	require.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))

	out := w.Body.String()
	assert.Containsf(t, out, `lang="pt-BR"`, "the 404 page's <html lang> is not localized")
	assert.Contains(t, out, "Não encontrado (404)")

	visible := regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(out, "")
	if leak := rawKeyRe.FindString(visible); leak != "" {
		t.Errorf("raw i18n key leaked into the 404 page: %q", leak)
	}

	// Nothing of the rejected URL reaches the page, and no request id: there is no log line for one
	// to join it to, which is the whole of decision 11's "no log line".
	assert.NotContains(t, out, "not-a-number")
}

// TestRender_JSBootstrapNoKeyLeak guards the window.i18n bootstrap: every value
// must be a real string, never its own key. A value == key means JSBootstrap
// failed to resolve a message (the {{param}}-placeholder bug where T executed
// the string as a template and leaked the key).
func TestRender_JSBootstrapNoKeyLeak(t *testing.T) {
	bind := map[string]interface{}{
		"selectedPhoneCountryUniqueId": "",
		"phoneNumber":                  "",
		"phoneCountries":               []api.PhoneCountryResponse{},
		"savedSuccessfully":            false,
	}
	out := renderMenuPage(t, "/account_phone.html", bind)

	m := regexp.MustCompile(`window\.i18n=(\{.*?\});`).FindStringSubmatch(out)
	require.Len(t, m, 2, "window.i18n bootstrap script not found in output")
	var kv map[string]string
	require.NoError(t, json.Unmarshal([]byte(m[1]), &kv))
	require.NotEmpty(t, kv)

	for k, v := range kv {
		assert.NotEqualf(t, k, v, "js bootstrap key %q leaked (value == key): JSBootstrap could not resolve it", k)
	}
}

// menuLabelRe captures the dropdown label in menu_layout.html: everything between the opening
// <span class="inline-block text-sm align-middle"> and the chevron <svg> that closes it. That is
// the whole of what a signed-in administrator reads at the top right of every admin and account
// page, and reading it back off a rendered page is the only way to see it, because the layout is a
// file no handler test ever executes.
var menuLabelRe = regexp.MustCompile(`(?s)<span class="inline-block text-sm align-middle">(.*?)<svg`)

func menuLabel(t *testing.T, out string) string {
	t.Helper()
	m := menuLabelRe.FindStringSubmatch(out)
	require.Lenf(t, m, 2, "the dropdown label span is not in the rendered page at all")
	return strings.TrimSpace(m[1])
}

// tagRe strips markup, so a case can assert on what an administrator actually reads rather than on
// the elements carrying it. The subject-only case needs the distinction: the guard on a one-key map
// is still true, so the inner <span> is emitted and only its text is empty.
var tagRe = regexp.MustCompile(`<[^>]*>`)

func menuLabelText(t *testing.T, out string) string {
	t.Helper()
	return strings.TrimSpace(tagRe.ReplaceAllString(menuLabel(t, out), ""))
}

// TestRender_MenuLabelShowsTheLoggedInUser is the case the rest of this package could not see.
// Every other render here is an anonymous request, so `loggedInUser` is never bound and the dropdown
// label comes back empty — which reads as "no handler binds it" if the harness is mistaken for the
// product. The bind is real and it is central: render.Renderer.RenderTemplate builds it from the
// ID token's claims, and middleware.SessionHandler puts that token on the context ahead of every route in
// routes.go that renders a menu page. Rendering with a token is what distinguishes the two.
func TestRender_MenuLabelShowsTheLoggedInUser(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":         "a5f0c6b4-0000-4000-8000-000000000001",
		"email":       "alice@example.com",
		"given_name":  "Alice",
		"middle_name": "Q",
		"family_name": "Doe",
	}

	out := renderWithLayoutAs(t, "/layouts/menu_layout.html", "/admin_groups.html",
		map[string]interface{}{"groups": []api.GroupResponse{}}, claims)

	label := menuLabel(t, out)
	assert.Contains(t, label, "Alice Q Doe",
		"the full name assembled from the ID token's name claims must reach the dropdown")
	assert.Contains(t, label, "alice@example.com", "the email must reach the dropdown")
}

// The name claims are optional; the email is what an administrator always has. With no name, the
// label carries the email alone and no empty line above it.
func TestRender_MenuLabelWithNoNameClaimsShowsTheEmailAlone(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":   "a5f0c6b4-0000-4000-8000-000000000002",
		"email": "bob@example.com",
	}

	out := renderWithLayoutAs(t, "/layouts/menu_layout.html", "/admin_groups.html",
		map[string]interface{}{"groups": []api.GroupResponse{}}, claims)

	label := menuLabel(t, out)
	assert.Contains(t, label, "bob@example.com")
	assert.NotContains(t, label, "<br />", "with no name there is no line to break")
}

// The ID token carries the name and email claims only when IncludeOpenIDConnectClaimsInIdToken is
// on — the seeded default, but an administrator may turn it off globally or for the admin console's
// own client, and then `sub` is all that arrives. The guard on the map is still satisfied, since a
// one-key map is truthy, so the label renders with a missing `Email` key. A missing key on a
// map[string]interface{} is an untyped nil, which text/template prints as "<no value>"; this pins
// that the label degrades to blank instead of putting that string on every page.
func TestRender_MenuLabelWithSubjectOnlyIsBlankNotNoValue(t *testing.T) {
	claims := jwt.MapClaims{"sub": "a5f0c6b4-0000-4000-8000-000000000003"}

	out := renderWithLayoutAs(t, "/layouts/menu_layout.html", "/admin_groups.html",
		map[string]interface{}{"groups": []api.GroupResponse{}}, claims)

	assert.NotContains(t, out, "no value", "a missing claim must not print a template placeholder")
	assert.Empty(t, menuLabelText(t, out), "with only a subject there is nothing to show")
}

// The anonymous request, stated rather than left implicit: with no ID token on the context nothing
// is bound, the outer guard is false, and the label is blank. This is the shape every other render
// in this package has, and saying so here is what keeps the next reader from reading those blanks
// as a defect in the page.
func TestRender_MenuLabelWithNoTokenIsBlank(t *testing.T) {
	out := renderMenuPage(t, "/admin_groups.html", map[string]interface{}{"groups": []api.GroupResponse{}})
	assert.Empty(t, menuLabel(t, out), "an anonymous render binds no user, so not even the span is emitted")
}
