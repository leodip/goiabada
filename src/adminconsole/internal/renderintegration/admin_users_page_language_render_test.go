package renderintegration

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// An administrator sees and sets a user's Page language on the user's Profile page, beside Language
// and region (#631 decisions 9 and 10).

// storedUserAPI is the admin API as the user Profile page reaches it: one stored user, and a
// refusal, when set, answering every save.
type storedUserAPI struct {
	pageLanguage string
	refusal      error
}

func (a *storedUserAPI) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Email: "ana@example.com", Locale: "de", PageLanguage: a.pageLanguage}, nil
}

func (a *storedUserAPI) UpdateUserProfile(context.Context, string, int64, *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, a.refusal
}

// The select is labelled, offers Automatic first and then every built-in catalog, each named in
// itself and in English as Language and region names it, selects the user's stored choice, and is
// described by the administrator's hint, which says "client" where My Account says "application",
// all in the page's language.
func TestRender_AdminUserProfile_ThePageLanguageSelect(t *testing.T) {
	out := servePage(t, adminuserhandlers.HandleProfileGet(render.New(web.TemplateFS(), web.StaticFS()),
		newPageLanguageStore(t), &storedUserAPI{pageLanguage: "fr"}),
		http.MethodGet, "/admin/users/9/profile", handlertest.WithPathValue("userId", "9"))

	assert.Contains(t, out, `<label class="field-label" for="pageLanguage">Idioma das páginas</label>`)
	m := pageLanguageSelectRe.FindStringSubmatch(out)
	require.NotNil(t, m, "the Page language select is drawn")
	assert.Contains(t, m[1], `name="pageLanguage"`)
	assert.Contains(t, m[1], `aria-describedby="pageLanguageHint"`)
	assert.NotContains(t, m[1], "aria-invalid")
	options := regexp.MustCompile(`<option value="([^"]*)"( selected)?>([^<]*)</option>`).FindAllStringSubmatch(m[2], -1)
	var drawn []string
	for _, o := range options {
		drawn = append(drawn, o[1]+"|"+o[2]+"|"+o[3])
	}
	assert.Equal(t, []string{
		"||Automático",
		"en||en – English",
		"de||de – Deutsch (German)",
		"es||es – español (Spanish)",
		"fr| selected|fr – français (French)",
		"it||it – italiano (Italian)",
		"pt-BR||pt-BR – português (Brasil) (Portuguese (Brazil))",
	}, drawn)
	assert.Contains(t, out, `<p class="field-hint" id="pageLanguageHint">O idioma do console, das páginas de entrada `+
		`depois que o usuário digita a senha e dos e-mails enviados ao usuário. Automático usa o idioma que o cliente `+
		`ou o navegador pede e, nos e-mails, o idioma e a região.</p>`)
}

// A page language the auth server refuses marks the select, which names the notice beside its hint;
// the choice is drawn again as Automatic, the refused value naming no option, and the user's stored
// Language and region is not what is marked.
func TestRender_AdminUserProfile_ARefusedPageLanguageIsTheFieldMarked(t *testing.T) {
	users := &storedUserAPI{pageLanguage: "es", refusal: &apiclient.APIError{Code: i18n.ErrCodeProfilePageLanguageInvalid,
		Message: "Escolha um idioma da lista.", StatusCode: http.StatusBadRequest}}

	out := serveRefusal(t, adminuserhandlers.HandleProfilePost(render.New(web.TemplateFS(), web.StaticFS()),
		newPageLanguageStore(t), users, "https://console.example"),
		"/admin/users/9/profile", url.Values{"username": {"ana"}, "pageLanguage": {"xx"}},
		handlertest.WithPathValue("userId", "9"))

	m := pageLanguageSelectRe.FindStringSubmatch(out)
	require.NotNil(t, m, "the Page language select is drawn")
	assert.Contains(t, m[1], `aria-invalid="true"`)
	assert.Contains(t, m[1], `aria-describedby="profile-error pageLanguageHint"`)
	assert.Contains(t, m[2], `<option value="" selected>Automático</option>`)
	assert.NotContains(t, m[2], `<option value="es" selected>`, "the refused value is drawn, not the stored one")
	assert.Contains(t, out, "Escolha um idioma da lista.")
	assert.NotContains(t, regexp.MustCompile(`<select[^>]*id="locale"[^>]*>`).FindString(out), "aria-invalid")
}
