package renderintegration

// The console's three pages that set a password, Account > Change password, Admin > Users > New
// user and a user's Authentication tab, show under the new password's field the hint the auth
// server's registration, activation and reset forms show for the stored policy, built from the rules
// the public settings carry, on the first draw and on a refused one alike (#550 decision 11).

import (
	"context"
	"html"
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

// nistPasswordHint is #550 decision 10's hint, word for word.
const nistPasswordHint = "At least 15 characters. A few unrelated words make a long password that's easy to " +
	"remember. Common passwords, and the account's email address or the app's name, are refused."

// nistRules are the rules the public settings carry for the nist policy.
var nistRules = api.PasswordRulesResponse{MinLength: 15, RefusesCommon: true, RefusesAccountWords: true}

// tooCommon is the auth server refusing a new password as common.
var tooCommon = &apiclient.APIError{Code: "validator.password.too_common", Message: "Choose another.",
	StatusCode: http.StatusBadRequest}

// passwordPage is the auth server as the three pages reach it: the user being edited, and every
// password write refused as common.
type passwordPage struct{}

func (passwordPage) UpdateAccountPassword(context.Context, string, *api.UpdateAccountPasswordRequest) (*api.UserResponse, error) {
	return nil, tooCommon
}

func (passwordPage) CreateUserAdmin(context.Context, string, *api.CreateUserAdminRequest) (*api.UserResponse, error) {
	return nil, tooCommon
}

func (passwordPage) GetUserById(context.Context, string, int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 7, Email: "jane.doe@example.com"}, nil
}

func (passwordPage) UpdateUserOTP(context.Context, string, int64, *api.UpdateUserOTPRequest) (*api.UserResponse, error) {
	return nil, nil
}

func (passwordPage) UpdateUserPassword(context.Context, string, int64, *api.UpdateUserPasswordRequest) (*api.UserResponse, error) {
	return nil, tooCommon
}

// passwordPageCase is one draw of one of the three pages: the handler, the request and the
// password input the hint belongs under.
type passwordPageCase struct {
	name    string
	handler func(t *testing.T) http.HandlerFunc
	method  string
	target  string
	options []handlertest.Option
	field   string
}

func passwordPageCases() []passwordPageCase {
	renderer := render.New(web.TemplateFS(), web.StaticFS())
	weak := url.Values{"currentPassword": {"the-old-one"}, "newPassword": {"PasswordPassword"},
		"newPasswordConfirmation": {"PasswordPassword"}, "email": {"jane.doe@example.com"},
		"setPasswordType": {"now"}, "password": {"PasswordPassword"}}
	user := []handlertest.Option{handlertest.WithPathValue("userId", "7")}
	return []passwordPageCase{
		{"change password", func(t *testing.T) http.HandlerFunc {
			return accounthandlers.HandleChangePasswordGet(renderer, newRenderSessionStore(t), passwordPage{})
		}, http.MethodGet, "/account/change-password", nil, "newPassword"},
		{"change password refused", func(t *testing.T) http.HandlerFunc {
			return accounthandlers.HandleChangePasswordPost(renderer, newRenderSessionStore(t), passwordPage{}, "https://console.example")
		}, http.MethodPost, "/account/change-password", []handlertest.Option{handlertest.WithForm(weak)}, "newPassword"},
		{"new user", func(*testing.T) http.HandlerFunc {
			return adminuserhandlers.HandleNewGet(renderer)
		}, http.MethodGet, "/admin/users/new", nil, "password"},
		{"new user refused", func(t *testing.T) http.HandlerFunc {
			return adminuserhandlers.HandleNewPost(renderer, newRenderSessionStore(t), passwordPage{}, "https://console.example")
		}, http.MethodPost, "/admin/users/new", []handlertest.Option{handlertest.WithForm(weak)}, "password"},
		{"authentication tab", func(t *testing.T) http.HandlerFunc {
			return adminuserhandlers.HandleAuthenticationGet(renderer, newRenderSessionStore(t), passwordPage{})
		}, http.MethodGet, "/admin/users/7/authentication", user, "newPassword"},
		{"authentication tab refused", func(t *testing.T) http.HandlerFunc {
			return adminuserhandlers.HandleAuthenticationPost(renderer, newRenderSessionStore(t), passwordPage{}, "https://console.example")
		}, http.MethodPost, "/admin/users/7/authentication",
			append([]handlertest.Option{handlertest.WithForm(weak)}, user...), "newPassword"},
	}
}

// servePasswordPage draws one of the three pages in English, the stored policy's rules on the
// public settings, and returns the page.
func servePasswordPage(t *testing.T, tc passwordPageCase, rules api.PasswordRulesResponse) string {
	t.Helper()
	options := append([]handlertest.Option{handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark", PasswordRules: rules})},
		tc.options...)
	req := handlertest.Request(tc.method, tc.target, options...)
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "en"))
	rec := httptest.NewRecorder()

	tc.handler(t).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "the page is drawn, not redirected: %s", rec.Body.String())
	return rec.Body.String()
}

// describedBy answers the ids the input with id names in its aria-describedby.
func describedBy(t *testing.T, out, id string) string {
	t.Helper()
	input := inputRe(id).FindString(out)
	require.NotEmpty(t, input, "the %s input is drawn", id)
	return regexp.MustCompile(`aria-describedby="([^"]*)"`).FindStringSubmatch(input + ` aria-describedby=""`)[1]
}

func TestRender_PasswordPages_ShowTheNistHintUnderTheField(t *testing.T) {
	hint := `<p class="field-hint" id="password-rules">` + html.EscapeString(nistPasswordHint) + `</p>`
	for _, tc := range passwordPageCases() {
		t.Run(tc.name, func(t *testing.T) {
			out := servePasswordPage(t, tc, nistRules)

			assert.Regexp(t, regexp.QuoteMeta(inputRe(tc.field).FindString(out))+`\s*`+regexp.QuoteMeta(hint), out,
				"the hint is drawn right under the new password's input")
			assert.Contains(t, " "+describedBy(t, out, tc.field)+" ", " password-rules ",
				"the input names the hint in its aria-describedby")
		})
	}
}

// A refused draw marks the field invalid and names the notice first, then the hint.
func TestRender_PasswordPages_ARefusalNamesTheNoticeBesideTheHint(t *testing.T) {
	notices := map[string]string{
		"change password refused":    "password-error",
		"new user refused":           "user-error",
		"authentication tab refused": "authentication-error",
	}
	for _, tc := range passwordPageCases() {
		notice, refused := notices[tc.name]
		if !refused {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			out := servePasswordPage(t, tc, nistRules)

			assert.Contains(t, out, "Choose another.")
			assert.Contains(t, inputRe(tc.field).FindString(out), `aria-invalid="true"`)
			assert.Regexp(t, `^`+notice+` password-rules\b`, describedBy(t, out, tc.field))
		})
	}
}

// The Authentication tab keeps saying a blank field keeps the current password, beside the rules.
func TestRender_AdminUsersAuthentication_KeepsTheBlankFieldHintBesideTheRules(t *testing.T) {
	for _, tc := range passwordPageCases() {
		if tc.target != "/admin/users/7/authentication" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			out := servePasswordPage(t, tc, nistRules)

			assert.Contains(t, out, `<p class="field-hint" id="newPasswordHint">Leave it blank to keep the current password.</p>`)
			assert.Contains(t, " "+describedBy(t, out, tc.field)+" ", " newPasswordHint ")
		})
	}
}

// A policy asking for a single character needs no telling, so no hint is drawn and the input names
// none.
func TestRender_PasswordPages_NoHintWhenThePolicyAsksNothing(t *testing.T) {
	for _, tc := range passwordPageCases() {
		t.Run(tc.name, func(t *testing.T) {
			out := servePasswordPage(t, tc, api.PasswordRulesResponse{MinLength: 1})

			assert.NotContains(t, out, `id="password-rules"`)
			assert.NotContains(t, describedBy(t, out, tc.field), "password-rules")
		})
	}
}

// The hint follows the stored policy, whatever it is.
func TestRender_PasswordPages_TheHintFollowsTheStoredPolicy(t *testing.T) {
	high := api.PasswordRulesResponse{MinLength: 10, RequiresLowercase: true, RequiresUppercase: true,
		RequiresNumber: true, RequiresSymbol: true}
	for _, tc := range passwordPageCases() {
		t.Run(tc.name, func(t *testing.T) {
			out := servePasswordPage(t, tc, high)

			assert.Contains(t, out, `<p class="field-hint" id="password-rules">At least 10 characters, with a lowercase `+
				`letter, an uppercase letter, a number and a symbol.</p>`)
		})
	}
}
