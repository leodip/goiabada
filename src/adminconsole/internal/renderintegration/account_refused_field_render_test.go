package renderintegration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refusal marks the field it is about, invalid and naming the notice, through the handler and the
// real renderer: a required field sent blank, which the admin API answers as VALIDATION_ERROR and
// names no field, and an address another account took at the write, which it answers as
// EMAIL_ALREADY_EXISTS (#617).

// refusingPasswordAPI is the auth server as the change-password page reaches it: a change it refuses.
type refusingPasswordAPI struct {
	refusal error
}

func (a *refusingPasswordAPI) UpdateAccountPassword(context.Context, string, *api.UpdateAccountPasswordRequest) (*api.UserResponse, error) {
	return nil, a.refusal
}

// refusingEmailAPI is the auth server as the email page reaches it: the profile, and a change it
// refuses.
type refusingEmailAPI struct {
	refusal error
}

func (*refusingEmailAPI) GetAccountProfile(context.Context, string) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 7, Email: "someone@example.com"}, nil
}

func (a *refusingEmailAPI) UpdateAccountEmail(context.Context, string, *api.UpdateAccountEmailRequest) (*api.UserResponse, error) {
	return nil, a.refusal
}

func validationError(message string) error {
	return &apiclient.APIError{Code: "VALIDATION_ERROR", Message: message, StatusCode: http.StatusBadRequest}
}

// assertMarked holds the input with id to being the refused one, and every other input of ids to
// being unmarked.
func assertMarked(t *testing.T, out, id, notice string, ids ...string) {
	t.Helper()
	for _, other := range ids {
		input := inputRe(other).FindString(out)
		require.NotEmpty(t, input, "the %s input is drawn", other)
		if other == id {
			assert.Contains(t, input, `aria-invalid="true"`, "the refused field is marked")
			assert.Contains(t, input, `aria-describedby="`+notice+`"`, "and names the notice")
		} else {
			assert.NotContains(t, input, "aria-invalid", "%s is not the refused field", other)
		}
	}
}

func TestRender_AccountChangePassword_ABlankFieldIsTheOneMarked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		form    url.Values
		message string
		marked  string
	}{
		{"the current password", url.Values{"newPassword": {"A-new-password-2026!"}, "newPasswordConfirmation": {"A-new-password-2026!"}},
			"Informe sua senha atual.", "currentPassword"},
		{"the new password", url.Values{"currentPassword": {"the-old-one"}}, "Informe a nova senha.", "newPassword"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := serveRefusal(t,
				accounthandlers.HandleChangePasswordPost(render.New(web.TemplateFS(), web.StaticFS()), nil,
					&refusingPasswordAPI{refusal: validationError(tc.message)}, "https://console.example"),
				"/account/change-password", tc.form)

			assert.Contains(t, out, tc.message)
			assertMarked(t, out, tc.marked, "password-error", "currentPassword", "newPassword", "newPasswordConfirmation")
		})
	}
}

func TestRender_AccountEmail_TheRefusedFieldIsMarked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		form    url.Values
		refusal error
		marked  string
	}{
		{"a blank current password", url.Values{"email": {"new@example.com"}, "emailConfirmation": {"new@example.com"}},
			validationError("Informe sua senha atual."), "currentPassword"},
		{"an address taken at the write", url.Values{"email": {"taken@example.com"}, "emailConfirmation": {"taken@example.com"},
			"currentPassword": {"the-password"}},
			&apiclient.APIError{Code: "EMAIL_ALREADY_EXISTS", Message: "Este e-mail já está em uso.", StatusCode: http.StatusConflict},
			"email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := serveRefusal(t,
				accounthandlers.HandleEmailPost(render.New(web.TemplateFS(), web.StaticFS()), nil,
					&refusingEmailAPI{refusal: tc.refusal}, "https://console.example"),
				"/account/email", tc.form)

			assertMarked(t, out, tc.marked, "email-error", "email", "emailConfirmation", "currentPassword")
		})
	}
}
