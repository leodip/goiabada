package accounthandlers

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

const accountPasswordFormCurrent = "My-Current-P4ss"
const accountPasswordFormNew = "N3w-Pass-word!"

// passwordRecordingApiClient records the password change the handler sent.
type passwordRecordingApiClient struct {
	sent []*api.UpdateAccountPasswordRequest
}

func (c *passwordRecordingApiClient) UpdateAccountPassword(_ context.Context, _ string,
	request *api.UpdateAccountPasswordRequest) (*api.UserResponse, error) {
	c.sent = append(c.sent, request)
	return &api.UserResponse{Id: 7}, nil
}

// TestHandleChangePasswordPost_SendsPasswordsAsTyped holds the console to forwarding
// both passwords whole: surrounding whitespace is part of a password the auth server
// accepts and compares intact (#472), matching the email page (#404).
func TestHandleChangePasswordPost_SendsPasswordsAsTyped(t *testing.T) {
	const current = "  " + accountPasswordFormCurrent + "  "
	const next = "  " + accountPasswordFormNew + "  "
	apiClient := &passwordRecordingApiClient{}
	form := url.Values{
		"currentPassword":         {current},
		"newPassword":             {next},
		"newPasswordConfirmation": {next},
	}
	req := handlertest.Request(http.MethodPost, "/account/change-password",
		handlertest.WithAccessToken(), handlertest.WithForm(form))
	rr := httptest.NewRecorder()

	HandleChangePasswordPost(handlersmocks.NewHttpHelper(t), newFlashTestStore(), apiClient, consoleBaseURL).
		ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code, "a successful change redirects")
	require.Len(t, apiClient.sent, 1)
	assert.Equal(t, current, apiClient.sent[0].CurrentPassword)
	assert.Equal(t, next, apiClient.sent[0].NewPassword)
}
