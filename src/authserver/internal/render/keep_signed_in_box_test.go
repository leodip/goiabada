package render

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keepSignedInInput is the box's input element on the password page.
var keepSignedInInput = regexp.MustCompile(`<input[^>]*name="keepSignedIn"[^>]*>`)

// renderPasswordPage renders the password page in English with the values the handler binds.
func renderPasswordPage(t *testing.T, bind map[string]interface{}) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/pwd", nil)
	req.Header.Set("Accept-Language", "en")
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
	req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
	buf, err := New(web.TemplateFS(), web.StaticFS(), nil).RenderTemplateToBuffer(req,
		"layouts/auth_layout.html", "auth_pwd.html", bind)
	require.NoError(t, err)
	return buf.String()
}

// Under Let each user choose the password page shows the Keep me signed in box, unticked, named by
// its label and described by its note, inside the form it is posted with (#743 decisions 2 and 4).
func TestPasswordPage_ShowsTheKeepMeSignedInBoxUnticked(t *testing.T) {
	page := renderPasswordPage(t, map[string]interface{}{"keepSignedInAsked": true, "keepSignedIn": false})

	input := keepSignedInInput.FindString(page)
	require.NotEmpty(t, input, "the box is on the page")
	assert.Contains(t, input, `type="checkbox"`)
	assert.Contains(t, input, `value="true"`)
	assert.NotContains(t, input, "checked", "the box starts unticked")
	assert.Contains(t, input, `aria-labelledby="keep-signed-in-label"`)
	assert.Contains(t, input, `aria-describedby="keep-signed-in-note"`)
	assert.Contains(t, page, `id="keep-signed-in-label">Keep me signed in</span>`)
	assert.Contains(t, page, `id="keep-signed-in-note">Uses a cookie to keep you signed in after you close the browser.</span>`)
	assert.Regexp(t, `(?s)<form method="post".*name="keepSignedIn".*</form>`, page, "posted with the password")
}

// A refusal draws the box again as the user left it.
func TestPasswordPage_RedrawsATickedBoxTicked(t *testing.T) {
	page := renderPasswordPage(t, map[string]interface{}{"keepSignedInAsked": true, "keepSignedIn": true})

	assert.Contains(t, keepSignedInInput.FindString(page), " checked")
}

// Under Always and Never the page asks nothing.
func TestPasswordPage_ShowsNoBoxUnlessAsked(t *testing.T) {
	page := renderPasswordPage(t, map[string]interface{}{"keepSignedInAsked": false, "keepSignedIn": false})

	assert.Empty(t, keepSignedInInput.FindString(page))
	assert.NotContains(t, page, "Keep me signed in")
}
