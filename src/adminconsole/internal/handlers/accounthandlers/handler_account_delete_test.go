package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
)

// The Delete account page (#783 decisions 6, 8 and 9): drawn only while the public settings say
// deletion is on, it sends the password and the one second factor shown, draws each refusal on the
// form, and after the deletion ends the console's own session and sends the browser to the static
// /account/deleted page with a 303.

const accountDeletePath = "/account/delete"

// deleteAccountAPI answers the page's port: the profile, for whether two-factor authentication is
// on, and the deletion, which records what it was sent and answers refusal.
type deleteAccountAPI struct {
	otpEnabled bool
	refusal    error

	sent       *api.DeleteAccountRequest
	sentBearer string
	deletions  int
}

func (a *deleteAccountAPI) GetAccountProfile(_ context.Context, _ string) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 7, Email: "someone@example.com", OTPEnabled: a.otpEnabled}, nil
}

func (a *deleteAccountAPI) DeleteAccount(_ context.Context, accessToken string, request *api.DeleteAccountRequest) error {
	a.deletions++
	a.sent = request
	a.sentBearer = accessToken
	return a.refusal
}

func deletionSettings(enabled bool) *api.PublicSettingsResponse {
	return &api.PublicSettingsResponse{AppName: "Goiabada", AccountDeletionEnabled: enabled}
}

func deletePostRequest(form url.Values, opts ...handlertest.Option) *http.Request {
	opts = append([]handlertest.Option{handlertest.WithAccessToken(),
		handlertest.WithSettings(deletionSettings(true)), handlertest.WithForm(form)}, opts...)
	return handlertest.Request(http.MethodPost, accountDeletePath, opts...)
}

// While the public settings say deletion is off, the page isn't there, by GET or by POST, as the
// Email verification page isn't there with email off; nothing is asked of the auth server.
func TestHandleDeleteAccount_IsNotFoundWhileTheSettingIsOff(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		httpHelper.On("NotFound", mock.Anything, mock.Anything).Once()

		HandleDeleteAccountGet(httpHelper, &deleteAccountAPI{}).ServeHTTP(httptest.NewRecorder(),
			handlertest.Request(http.MethodGet, accountDeletePath, handlertest.WithAccessToken(),
				handlertest.WithSettings(deletionSettings(false))))
	})
	t.Run("POST", func(t *testing.T) {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		httpHelper.On("NotFound", mock.Anything, mock.Anything).Once()

		client := &deleteAccountAPI{}
		rec := httptest.NewRecorder()
		HandleDeleteAccountPost(httpHelper, newFlashTestStore(), client, consoleBaseURL).ServeHTTP(rec,
			deletePostRequest(url.Values{"password": {"P4ss!word"}},
				handlertest.WithSettings(deletionSettings(false))))

		assert.Zero(t, client.deletions, "nothing is deleted through a page that isn't there")
		assert.Empty(t, rec.Header().Get("Location"))
	})
}

// The page asks for the second factor only while two-factor authentication is on, and opens on the
// authentication code, not the recovery code.
func TestHandleDeleteAccountGet_AsksForASecondFactorOnlyWithTwoFactorOn(t *testing.T) {
	for _, otpEnabled := range []bool{true, false} {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_delete.html").Once()

		HandleDeleteAccountGet(httpHelper, &deleteAccountAPI{otpEnabled: otpEnabled}).ServeHTTP(httptest.NewRecorder(),
			handlertest.Request(http.MethodGet, accountDeletePath, handlertest.WithAccessToken(),
				handlertest.WithSettings(deletionSettings(true))))

		bind := handlertest.Bind(t, httpHelper)
		assert.Equal(t, otpEnabled, bind["otpEnabled"], "two-factor authentication on: %v", otpEnabled)
		assert.Equal(t, false, bind["useRecoveryCode"], "the page opens on the authentication code")
		assert.Nil(t, bind["error"])
	}
}

// What the user typed reaches the endpoint as typed, the code they chose in its own field and the
// other one absent, on the user's own access token.
func TestHandleDeleteAccountPost_SendsThePasswordAndTheCodeShown(t *testing.T) {
	testCases := []struct {
		name string
		form url.Values
		want api.DeleteAccountRequest
	}{
		{"the password alone", url.Values{"password": {"P4ss!word"}},
			api.DeleteAccountRequest{Password: "P4ss!word"}},
		{"with an authentication code", url.Values{"password": {"P4ss!word"}, "otp": {"123456"}},
			api.DeleteAccountRequest{Password: "P4ss!word", OtpCode: "123456"}},
		{"with a recovery code", url.Values{"password": {"P4ss!word"}, "recoveryCode": {"7kq2-m9xh-4trw-b3np-j6vd-egac"}},
			api.DeleteAccountRequest{Password: "P4ss!word", RecoveryCode: "7kq2-m9xh-4trw-b3np-j6vd-egac"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)

			client := &deleteAccountAPI{otpEnabled: true}
			HandleDeleteAccountPost(httpHelper, newFlashTestStore(), client, consoleBaseURL).ServeHTTP(
				httptest.NewRecorder(), deletePostRequest(tc.form))

			require.Equal(t, 1, client.deletions)
			assert.Equal(t, tc.want, *client.sent)
			assert.Equal(t, handlertest.AccessToken, client.sentBearer)
		})
	}
}

// A deletion the auth server accepted ends the console's own session, its row and its cookie, and
// sends the browser to /account/deleted with a 303, so a reload of where it lands resubmits
// nothing (decision 8).
func TestHandleDeleteAccountPost_EndsTheConsoleSessionAndSendsTheBrowserToTheDeletedPage(t *testing.T) {
	store := newFlashTestStore()

	// The browser's console session, holding something a later request would find.
	seed := httptest.NewRecorder()
	seedReq := handlertest.Request(http.MethodGet, "/account/profile")
	sess, err := store.Get(seedReq, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	sess.Values["marker"] = "signed-in"
	require.NoError(t, store.Save(seedReq, seed, sess))
	jar := newCookieJar()
	jar.keep(seed)
	require.NotEmpty(t, jar.cookies)

	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	rec := httptest.NewRecorder()
	HandleDeleteAccountPost(httpHelper, store, &deleteAccountAPI{}, consoleBaseURL).ServeHTTP(rec,
		jar.send(deletePostRequest(url.Values{"password": {"P4ss!word"}})))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "https://console.example.test/account/deleted", rec.Header().Get("Location"))

	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == store.CookieName(builtin.AdminConsoleSessionName) && c.MaxAge < 0 {
			cleared = true
		}
	}
	assert.True(t, cleared, "the session cookie is expired")

	// The old cookie names no session any more: a request carrying it finds a new, empty one.
	after, err := store.Get(jar.send(handlertest.Request(http.MethodGet, "/account/profile")), builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	assert.True(t, after.IsNew, "the session's row is gone")
	assert.Nil(t, after.Values["marker"])
}

// Each refusal the user can act on is drawn on the form with the API's own sentence, already in the
// request's language, and marks the field it is about; the console's session is left as it was.
func TestHandleDeleteAccountPost_EachRefusalIsShownOnTheForm(t *testing.T) {
	testCases := []struct {
		name        string
		code        string
		status      int
		form        url.Values
		wantField   string
		wantRecover bool
	}{
		{"a wrong password", "AUTHENTICATION_FAILED", http.StatusBadRequest,
			url.Values{"password": {"wrong"}}, "password", false},
		{"no code", "OTP_CODE_REQUIRED", http.StatusBadRequest,
			url.Values{"password": {"P4ss!word"}, "otp": {""}}, "otp", false},
		{"no recovery code", "OTP_CODE_REQUIRED", http.StatusBadRequest,
			url.Values{"password": {"P4ss!word"}, "recoveryCode": {""}}, "recoveryCode", true},
		{"a wrong authentication code", "INVALID_OTP_CODE", http.StatusBadRequest,
			url.Values{"password": {"P4ss!word"}, "otp": {"000000"}}, "otp", false},
		{"a code from the next step", "OTP_CLOCK_AHEAD", http.StatusBadRequest,
			url.Values{"password": {"P4ss!word"}, "otp": {"123456"}}, "otp", false},
		{"a wrong or used recovery code", "INVALID_RECOVERY_CODE", http.StatusBadRequest,
			url.Values{"password": {"P4ss!word"}, "recoveryCode": {"aaaa-bbbb-cccc-dddd-eeee-ffff"}}, "recoveryCode", true},
		{"both codes", "VALIDATION_ERROR", http.StatusBadRequest,
			url.Values{"password": {"P4ss!word"}, "otp": {"123456"}, "recoveryCode": {"aaaa-bbbb-cccc-dddd-eeee-ffff"}}, "", true},
		{"the last administrator", "LAST_ADMINISTRATOR", http.StatusConflict,
			url.Values{"password": {"P4ss!word"}}, "", false},
		{"deletion turned off since the settings were read", "ACCOUNT_DELETION_DISABLED", http.StatusForbidden,
			url.Values{"password": {"P4ss!word"}}, "", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_delete.html").Once()

			client := &deleteAccountAPI{otpEnabled: true, refusal: &apiclient.APIError{
				Code: tc.code, Message: "the sentence for " + tc.name, StatusCode: tc.status}}
			rec := httptest.NewRecorder()
			HandleDeleteAccountPost(httpHelper, newFlashTestStore(), client, consoleBaseURL).ServeHTTP(rec,
				deletePostRequest(tc.form))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "the sentence for "+tc.name, bind["error"])
			assert.Equal(t, tc.wantField, bind["errorField"])
			assert.Equal(t, true, bind["otpEnabled"], "the form is drawn as the account is now")
			assert.Equal(t, tc.wantRecover, bind["useRecoveryCode"], "the second factor the user chose stays shown")
			assert.Empty(t, rec.Header().Get("Location"), "drawn again, not redirected")
			assert.Empty(t, rec.Result().Cookies(), "the console's session is left alone")
		})
	}
}

// Too many wrong guesses is the user's to wait out, drawn on the form in the page's language with
// the console's own sentence, as the other account forms draw it (#559 decision 10).
func TestHandleDeleteAccountPost_ARateLimitIsShownOnTheForm(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_delete.html").Once()

	client := &deleteAccountAPI{refusal: &apiclient.APIError{Code: "TOO_MANY_REQUESTS",
		Message: "Too many requests. Please try again later.", StatusCode: http.StatusTooManyRequests}}
	HandleDeleteAccountPost(httpHelper, newFlashTestStore(), client, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		deletePostRequest(url.Values{"password": {"wrong"}}, handlertest.WithLocale("pt-BR")))

	assert.Equal(t, "Chegaram muitas solicitações deste navegador, ou para esta conta, em pouco tempo. Aguarde alguns minutos e tente novamente.",
		handlertest.Bind(t, httpHelper)["error"])
}

// A refusal the user can't act on, such as the auth server refusing the console's own client, is
// a fault: it goes to the error classifier and the form is not drawn with it.
func TestHandleDeleteAccountPost_AnyOtherRefusalIsNotDrawnOnTheForm(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	client := &deleteAccountAPI{refusal: &apiclient.APIError{Code: "CLIENT_NOT_ALLOWED",
		Message: "This operation is not available to this client.", StatusCode: http.StatusForbidden}}
	rec := httptest.NewRecorder()
	HandleDeleteAccountPost(httpHelper, newFlashTestStore(), client, consoleBaseURL).ServeHTTP(rec,
		deletePostRequest(url.Values{"password": {"P4ss!word"}}))

	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			assert.NotEqual(t, "/account_delete.html", call.Arguments.Get(3), "the form is not drawn with a fault")
		}
	}
	assert.Empty(t, rec.Header().Get("Location"))
}

// /account/deleted is the same page for anyone who opens it, on the layout without a menu: it reads
// no session and asks the auth server nothing (decision 8).
func TestHandleAccountDeletedGet_DrawsTheStaticPageWithoutAMenu(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/no_menu_layout.html", "/account_deleted.html").Once()

	rec := httptest.NewRecorder()
	HandleAccountDeletedGet(httpHelper).ServeHTTP(rec, handlertest.Request(http.MethodGet, "/account/deleted",
		handlertest.WithSettings(deletionSettings(false))))

	assert.Empty(t, rec.Result().Cookies())
}
