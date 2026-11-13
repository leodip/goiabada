package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// setupEmailUserNewAPI is the auth server creating user 7 and answering setupEmailSent as given,
// nil being an answer without the member.
type setupEmailUserNewAPI struct {
	setupEmailSent *bool
}

func (a setupEmailUserNewAPI) CreateUserAdmin(context.Context, string, *api.CreateUserAdminRequest) (*api.CreateUserResponse, error) {
	return &api.CreateUserResponse{User: api.UserResponse{Id: 7}, SetupEmailSent: a.setupEmailSent}, nil
}

// A new user whose setup email could not be sent is shown with a warning on its details page, once
// (#725 decision 12). The answer's member decides it: false warns, and true or an answer with no
// member, as with email disabled, does not.
func TestHandleNewPost_ASetupEmailNotSentIsShownOnTheNewUsersPage(t *testing.T) {
	sent, notSent := true, false
	for _, tc := range []struct {
		name           string
		setupEmailSent *bool
		wantWarning    bool
	}{
		{"the email was not sent", &notSent, true},
		{"the email was sent", &sent, false},
		{"no email was asked for", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFlashTestStore()
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)

			req := handlertest.Request(http.MethodPost, "/admin/users/new",
				handlertest.WithAccessToken(),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Goiabada", SMTPEnabled: true}),
				handlertest.WithForm(url.Values{"email": {"jane.doe@example.com"}, "setPasswordType": {"email"}}))
			rec := httptest.NewRecorder()
			HandleNewPost(httpHelper, store, setupEmailUserNewAPI{setupEmailSent: tc.setupEmailSent}, "https://console.example").
				ServeHTTP(rec, req)

			require.Equal(t, http.StatusFound, rec.Code)
			cookies := rec.Result().Cookies()
			require.Len(t, cookies, 1)

			bind, shown := renderDetails(t, store, cookies[0])
			assert.Equal(t, true, bind["userCreated"])
			assert.Equal(t, tc.wantWarning, bind["setupEmailNotSent"])

			// The warning is taken with the page that showed it, so a reload does not show it again.
			next := cookies[0]
			if saved := shown.Result().Cookies(); len(saved) > 0 {
				next = saved[0]
			}
			reloaded, _ := renderDetails(t, store, next)
			assert.Equal(t, false, reloaded["setupEmailNotSent"], "on reload")
		})
	}
}
