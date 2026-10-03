package accounthandlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// The account email page asks for the current password, since the auth server refuses the change
// without it (#404). These cases own the console's half: the password is read from the form body
// only, it reaches the API in the request, and no re-render of the form carries it back.

const accountEmailFormPassword = "My-Current-P4ss"

// emailRecordingApiClient records the email change the handler sent and answers it with refusal,
// or with success when refusal is nil.
type emailRecordingApiClient struct {
	sent    []*api.UpdateAccountEmailRequest
	refusal error
}

func (*emailRecordingApiClient) GetAccountProfile(context.Context, string) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 11, Email: "old@example.com", EmailVerified: true}, nil
}

func (c *emailRecordingApiClient) UpdateAccountEmail(_ context.Context, _ string,
	request *api.UpdateAccountEmailRequest) (*api.UserResponse, error) {
	c.sent = append(c.sent, request)
	if c.refusal != nil {
		return nil, c.refusal
	}
	return &api.UserResponse{Id: 11, Email: request.Email}, nil
}

// requireNoPasswordInBind fails when any value the page was rendered with carries the password.
func requireNoPasswordInBind(t *testing.T, httpHelper *mocks_handlers.HttpHelper) {
	t.Helper()
	for key, value := range handlertest.Bind(t, httpHelper) {
		assert.NotContains(t, fmt.Sprint(value), accountEmailFormPassword,
			"the form was re-rendered with the password under %q", key)
	}
}

func TestHandleAccountEmailPost_SendsTheCurrentPasswordFromTheFormBody(t *testing.T) {
	apiClient := &emailRecordingApiClient{}
	form := url.Values{
		"email":             {"New@Example.com"},
		"emailConfirmation": {"new@example.com"},
		"currentPassword":   {accountEmailFormPassword},
	}
	req := handlertest.Request(http.MethodPost, "/account/email",
		handlertest.WithAccessToken(), handlertest.WithForm(form))
	rr := httptest.NewRecorder()

	HandleAccountEmailPost(mocks_handlers.NewHttpHelper(t), newFlashTestStore(), apiClient).ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code, "a successful change redirects")
	require.Len(t, apiClient.sent, 1)
	assert.Equal(t, "new@example.com", apiClient.sent[0].Email)
	assert.Equal(t, accountEmailFormPassword, apiClient.sent[0].CurrentPassword)
}

// TestHandleAccountEmailPost_SendsTheCurrentPasswordAsTyped holds the console to forwarding the
// password whole: surrounding whitespace is part of a password the auth server accepts and
// compares intact, so a trimmed one would be refused as wrong and charged to the account's budget.
func TestHandleAccountEmailPost_SendsTheCurrentPasswordAsTyped(t *testing.T) {
	const password = "  " + accountEmailFormPassword + "  "
	apiClient := &emailRecordingApiClient{}
	form := url.Values{
		"email":             {"new@example.com"},
		"emailConfirmation": {"new@example.com"},
		"currentPassword":   {password},
	}
	req := handlertest.Request(http.MethodPost, "/account/email",
		handlertest.WithAccessToken(), handlertest.WithForm(form))
	rr := httptest.NewRecorder()

	HandleAccountEmailPost(mocks_handlers.NewHttpHelper(t), newFlashTestStore(), apiClient).ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code, "a successful change redirects")
	require.Len(t, apiClient.sent, 1)
	assert.Equal(t, password, apiClient.sent[0].CurrentPassword)
}

// TestHandleAccountEmailPost_IgnoresACurrentPasswordInTheQuery is the credential rule (#202): a
// password in a request target reaches browser history, Referers and proxy logs, so one there is
// never read. The API then refuses the blank password itself, which is why it is still called.
func TestHandleAccountEmailPost_IgnoresACurrentPasswordInTheQuery(t *testing.T) {
	apiClient := &emailRecordingApiClient{refusal: &apiclient.APIError{
		StatusCode: http.StatusBadRequest, Code: "VALIDATION_ERROR", Message: "Current password is required."}}
	httpHelper := mocks_handlers.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_email.html").Once()
	form := url.Values{"email": {"new@example.com"}, "emailConfirmation": {"new@example.com"}}
	req := handlertest.Request(http.MethodPost, "/account/email?currentPassword="+accountEmailFormPassword,
		handlertest.WithAccessToken(), handlertest.WithForm(form))

	HandleAccountEmailPost(httpHelper, newFlashTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

	require.Len(t, apiClient.sent, 1)
	assert.Empty(t, apiClient.sent[0].CurrentPassword, "a password in the query must not be read")
	assert.Equal(t, "Current password is required.", handlertest.Bind(t, httpHelper)["error"])
}

func TestHandleAccountEmailPost_ARefusedPasswordReRendersWithoutIt(t *testing.T) {
	apiClient := &emailRecordingApiClient{refusal: &apiclient.APIError{
		StatusCode: http.StatusBadRequest, Code: "AUTHENTICATION_FAILED",
		Message: "Authentication failed. Check your current password and try again."}}
	httpHelper := mocks_handlers.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_email.html").Once()
	form := url.Values{
		"email":             {"new@example.com"},
		"emailConfirmation": {"new@example.com"},
		"currentPassword":   {accountEmailFormPassword},
	}
	req := handlertest.Request(http.MethodPost, "/account/email",
		handlertest.WithAccessToken(), handlertest.WithForm(form))

	HandleAccountEmailPost(httpHelper, newFlashTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "Authentication failed. Check your current password and try again.", bind["error"])
	assert.Equal(t, "new@example.com", bind["email"], "the address the user typed is kept")
	requireNoPasswordInBind(t, httpHelper)
}

func TestHandleAccountEmailPost_AConfirmationMismatchReRendersWithoutThePassword(t *testing.T) {
	apiClient := &emailRecordingApiClient{}
	httpHelper := mocks_handlers.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_email.html").Once()
	form := url.Values{
		"email":             {"new@example.com"},
		"emailConfirmation": {"other@example.com"},
		"currentPassword":   {accountEmailFormPassword},
	}
	req := handlertest.Request(http.MethodPost, "/account/email",
		handlertest.WithAccessToken(), handlertest.WithForm(form))

	HandleAccountEmailPost(httpHelper, newFlashTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(), req)

	assert.Empty(t, apiClient.sent, "a mismatch is refused before the API is called")
	requireNoPasswordInBind(t, httpHelper)
}
