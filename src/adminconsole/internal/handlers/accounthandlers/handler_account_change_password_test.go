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

// passwordRecordingApiClient records the password change the handler sent and answers it with
// success.
type passwordRecordingApiClient struct {
	sent []*api.UpdateAccountPasswordRequest
}

func (c *passwordRecordingApiClient) UpdateAccountPassword(_ context.Context, _ string,
	request *api.UpdateAccountPasswordRequest) (*api.UserResponse, error) {
	c.sent = append(c.sent, request)
	return &api.UserResponse{Id: 7}, nil
}

// TestHandleChangePasswordPost_SendsBothPasswordsAsTyped holds the console to forwarding both
// passwords whole (#472): surrounding whitespace is part of a password the sign-in, registration
// and reset flows accept intact, so a trimmed current password would be refused as wrong and
// charged to the account's budget, and a trimmed new password would differ from the one the user
// typed and confirmed.
func TestHandleChangePasswordPost_SendsBothPasswordsAsTyped(t *testing.T) {
	const currentPassword = "  My-Current-P4ss  "
	const newPassword = " My-New-P4ss-Word\t"
	apiClient := &passwordRecordingApiClient{}
	form := url.Values{
		"currentPassword":         {currentPassword},
		"newPassword":             {newPassword},
		"newPasswordConfirmation": {newPassword},
	}
	req := handlertest.Request(http.MethodPost, "/account/change-password",
		handlertest.WithAccessToken(), handlertest.WithForm(form))
	rr := httptest.NewRecorder()

	HandleChangePasswordPost(handlersmocks.NewHttpHelper(t), newFlashTestStore(), apiClient, consoleBaseURL).ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code, "a successful change redirects")
	require.Len(t, apiClient.sent, 1)
	assert.Equal(t, currentPassword, apiClient.sent[0].CurrentPassword)
	assert.Equal(t, newPassword, apiClient.sent[0].NewPassword)
}
