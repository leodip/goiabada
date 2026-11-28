package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three console forms that ask for a name draw the family name first, then the given name, then
// the middle name, on a Japanese or Simplified Chinese page, and the given, middle and family names
// in that order on every other; the order drawn is the tab order, and a refused name is the field
// that takes the focus whichever order it is drawn in. The fields keep their names, so what is
// posted does not change (#662 decision 11, #663 decision 2).

// nameFormAPI is the auth server as the three name forms reach it: the user named 山田 太郎 as
// stored, and every save refused with the refusal of one name field.
type nameFormAPI struct {
	refusal error
}

func (*nameFormAPI) stored() *api.UserResponse {
	return &api.UserResponse{ID: 9, Email: "taro@example.com", GivenName: "太郎", MiddleName: "M", FamilyName: "山田"}
}

func (a *nameFormAPI) GetUserByID(context.Context, string, int64) (*api.UserResponse, error) {
	return a.stored(), nil
}

func (a *nameFormAPI) UpdateUserProfile(context.Context, string, int64, *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, a.refusal
}

func (a *nameFormAPI) GetAccountProfile(context.Context, string) (*api.UserResponse, error) {
	return a.stored(), nil
}

func (a *nameFormAPI) UpdateAccountProfile(context.Context, string, *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, a.refusal
}

func (a *nameFormAPI) CreateUserAdmin(context.Context, string, *api.CreateUserAdminRequest) (*api.CreateUserResponse, error) {
	return nil, a.refusal
}

// nameForm is one of the three forms: its page drawn fresh and its page drawn again for a refusal.
type nameForm struct {
	name    string
	target  string
	options []handlertest.Option
	get     func(t *testing.T, apiClient *nameFormAPI) http.HandlerFunc
	post    func(t *testing.T, apiClient *nameFormAPI) http.HandlerFunc
}

func nameForms() []nameForm {
	renderer := render.New(web.TemplateFS(), web.StaticFS())
	return []nameForm{
		{
			name:   "Account > Profile",
			target: "/account/profile",
			get: func(t *testing.T, a *nameFormAPI) http.HandlerFunc {
				return accounthandlers.HandleProfileGet(renderer, newRenderSessionStore(t), a)
			},
			post: func(t *testing.T, a *nameFormAPI) http.HandlerFunc {
				return accounthandlers.HandleProfilePost(renderer, newRenderSessionStore(t), a, "https://console.example")
			},
		},
		{
			name:    "Users > Profile",
			target:  "/admin/users/9/profile",
			options: []handlertest.Option{handlertest.WithPathValue("userId", "9")},
			get: func(t *testing.T, a *nameFormAPI) http.HandlerFunc {
				return adminuserhandlers.HandleProfileGet(renderer, newRenderSessionStore(t), a)
			},
			post: func(t *testing.T, a *nameFormAPI) http.HandlerFunc {
				return adminuserhandlers.HandleProfilePost(renderer, newRenderSessionStore(t), a, "https://console.example")
			},
		},
		{
			name:   "Users > New",
			target: "/admin/users/new",
			get: func(*testing.T, *nameFormAPI) http.HandlerFunc {
				return adminuserhandlers.HandleNewGet(renderer)
			},
			post: func(t *testing.T, a *nameFormAPI) http.HandlerFunc {
				return adminuserhandlers.HandleNewPost(renderer, newRenderSessionStore(t), a, "https://console.example")
			},
		},
	}
}

// serveNameForm serves the request in the language tag names and returns the page it draws.
func serveNameForm(t *testing.T, handler http.HandlerFunc, method, target, tag string, options ...handlertest.Option) string {
	t.Helper()
	options = append([]handlertest.Option{handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}),
		handlertest.WithLocale(tag)}, options...)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, handlertest.Request(method, target, options...))
	require.Equal(t, http.StatusOK, rec.Code, "the page is drawn, not redirected: %s", rec.Body.String())
	return rec.Body.String()
}

// nameLabelRe matches a name field's label, capturing the field it labels and its text.
var nameLabelRe = regexp.MustCompile(`<label class="field-label" for="(givenName|middleName|familyName)">([^<]*)</label>`)

// nameInputRe matches a name field's input, capturing its id.
var nameInputRe = regexp.MustCompile(`<input[^>]* id="(givenName|middleName|familyName)"[^>]*>`)

// autofocusRe matches an element's autofocus attribute.
var autofocusRe = regexp.MustCompile(`\sautofocus[\s>]`)

// nameOrders are the two orders, with the languages that draw each and the labels they draw them
// with, as each catalog writes them.
var nameOrders = []struct {
	tag    string
	labels [][2]string
}{
	{"ja-JP", [][2]string{{"familyName", "姓"}, {"givenName", "名"}, {"middleName", "ミドルネーム"}}},
	{"zh-Hans", [][2]string{{"familyName", "姓"}, {"givenName", "名"}, {"middleName", "中间名"}}},
	{"en", [][2]string{{"givenName", "Given name"}, {"middleName", "Middle name"}, {"familyName", "Family name"}}},
}

// drawnNameFields answers the name fields' labels in the order the page draws them, and holds each
// field's input to coming in that same order, under the label it follows, with its own name and
// no tabindex, so the tab order is the drawn order.
func drawnNameFields(t *testing.T, out string) [][2]string {
	t.Helper()
	var labels [][2]string
	for _, m := range nameLabelRe.FindAllStringSubmatch(out, -1) {
		labels = append(labels, [2]string{m[1], m[2]})
	}
	var inputs []string
	for _, m := range nameInputRe.FindAllStringSubmatch(out, -1) {
		inputs = append(inputs, m[1])
		assert.Contains(t, m[0], `name="`+m[1]+`"`, "the %s input posts under its own name", m[1])
		assert.NotContains(t, m[0], "tabindex", "the %s input takes no tab order of its own", m[1])
	}
	require.Len(t, labels, 3, "the three name fields are drawn")
	require.Len(t, inputs, 3, "with their three inputs")
	for i, label := range labels {
		assert.Equal(t, label[0], inputs[i], "input %d is the field its label names", i)
	}
	return labels
}

func TestRender_NameForms_DrawTheNamesInThePagesOrder(t *testing.T) {
	for _, form := range nameForms() {
		for _, order := range nameOrders {
			t.Run(form.name+", "+order.tag, func(t *testing.T) {
				out := serveNameForm(t, form.get(t, &nameFormAPI{}), http.MethodGet, form.target, order.tag, form.options...)

				assert.Equal(t, order.labels, drawnNameFields(t, out))
			})
		}
	}
}

// Each form writes out both orders, so each name's input is drawn the same in both: only the order
// and the labels' language differ.
func TestRender_NameForms_DrawEachNameTheSameInBothOrders(t *testing.T) {
	for _, form := range nameForms() {
		t.Run(form.name, func(t *testing.T) {
			japanese := serveNameForm(t, form.get(t, &nameFormAPI{}), http.MethodGet, form.target, "ja-JP", form.options...)
			english := serveNameForm(t, form.get(t, &nameFormAPI{}), http.MethodGet, form.target, "en", form.options...)

			for _, id := range []string{"givenName", "middleName", "familyName"} {
				input := inputRe(id).FindString(english)
				require.NotEmpty(t, input, "the %s input is drawn", id)
				assert.Equal(t, input, inputRe(id).FindString(japanese), "the %s input in both orders", id)
			}
		})
	}
}

// A profile drawn in Japanese puts each stored name in its own field, whichever is drawn first.
func TestRender_NameForms_AJapaneseProfileKeepsEachNameInItsField(t *testing.T) {
	for _, form := range nameForms()[:2] {
		t.Run(form.name, func(t *testing.T) {
			out := serveNameForm(t, form.get(t, &nameFormAPI{}), http.MethodGet, form.target, "ja-JP", form.options...)

			assert.Contains(t, inputRe("familyName").FindString(out), `value="山田"`)
			assert.Contains(t, inputRe("givenName").FindString(out), `value="太郎"`)
			assert.Contains(t, inputRe("middleName").FindString(out), `value="M"`)
		})
	}
}

func TestRender_NameForms_ARefusedNameTakesTheFocusInEitherOrder(t *testing.T) {
	refusals := map[string]string{
		"givenName":  i18n.ErrCodeProfileGivenNameInvalid,
		"middleName": i18n.ErrCodeProfileMiddleNameInvalid,
		"familyName": i18n.ErrCodeProfileFamilyNameInvalid,
	}
	form := url.Values{"email": {"taro@example.com"}, "givenName": {"太郎"}, "middleName": {"M"},
		"familyName": {"山田"}, "setPasswordType": {"now"}, "password": {"a-long-password-2026"}}
	for _, page := range nameForms() {
		for _, order := range nameOrders {
			for field, code := range refusals {
				t.Run(page.name+", "+order.tag+", "+field, func(t *testing.T) {
					refusal := &apiclient.APIError{Code: code, Message: "refused", StatusCode: http.StatusBadRequest}
					out := serveNameForm(t, page.post(t, &nameFormAPI{refusal: refusal}), http.MethodPost, page.target,
						order.tag, append(page.options, handlertest.WithForm(form))...)

					assert.Equal(t, order.labels, drawnNameFields(t, out), "the refused form keeps the page's order")
					assert.Contains(t, inputRe(field).FindString(out), "autofocus", "the refused %s takes the focus", field)
					assert.Contains(t, inputRe(field).FindString(out), `aria-invalid="true"`, "and is marked")
					assert.Len(t, autofocusRe.FindAllString(out, -1), 1, "and nothing else asks for the focus")
				})
			}
		}
	}
}
