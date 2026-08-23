package adminsettingshandlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/oauth"
)

// stubApiClient embeds apiclient.ApiClient so its hundred-odd other methods come for free
// and any of them that a test does not stub panics on a nil interface, which is the right
// outcome for a call the test did not expect. There is no generated mock: adminconsole has
// no .mockery.yaml. Same shape as adminclienthandlers' stub, for the same reason.
type stubApiClient struct {
	apiclient.ApiClient
	rotateErr error
}

func (s *stubApiClient) RotateSettingsKeys(accessToken string) error {
	return s.rotateErr
}

// TestHandleAdminSettingsKeysRotatePost_APIErrorReachesTheBrowser owns the wiring between
// the rotate handler and HandleAPIErrorJson. The helper's own forwarding is pinned next
// door in api_error_helper_test.go, but that test cannot see which of the two error paths
// this handler calls: swapping HandleAPIErrorJson back to a direct JsonError leaves the
// helper's tests and the whole admin console suite green while putting the 409 back behind
// "An unexpected server error has occurred" and a request id.
//
// That sentence is the entire point of the change. The auth server answers 409
// ROTATION_IN_PROGRESS when another rotation won the race, which is a fact about the
// administrator's own request and something they can act on, and the modal that
// sendAjaxRequest opens shows error_description verbatim (#251).
//
// The rows for the other statuses are what keeps the forwarding narrow: a genuine server
// fault must stay a generic 500 with its detail in the log rather than on the screen.
func TestHandleAdminSettingsKeysRotatePost_APIErrorReachesTheBrowser(t *testing.T) {

	const refusal = "Another key rotation is in progress"

	const generic = "An unexpected server error has occurred"

	testCases := []struct {
		name            string
		apiErr          error
		wantStatus      int
		wantError       string
		wantDescription string
	}{
		{
			name:            "a 409 is forwarded with its status and description",
			apiErr:          &apiclient.APIError{Code: "ROTATION_IN_PROGRESS", Message: refusal, StatusCode: http.StatusConflict},
			wantStatus:      http.StatusConflict,
			wantError:       "ROTATION_IN_PROGRESS",
			wantDescription: refusal,
		},
		{
			name:            "a 400 is forwarded too, which is what #122 established",
			apiErr:          &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "bad request", StatusCode: http.StatusBadRequest},
			wantStatus:      http.StatusBadRequest,
			wantError:       "VALIDATION_ERROR",
			wantDescription: "bad request",
		},
		{
			name:            "an incomplete key set stays generic, since 500 is not the administrator's mistake",
			apiErr:          &apiclient.APIError{Code: "KEY_SET_INCOMPLETE", Message: "Expected current and next keys to exist", StatusCode: http.StatusInternalServerError},
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
		{
			name:            "a transport error stays generic",
			apiErr:          errors.New("connection refused"),
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// templateFS is nil because JsonError renders no template. This is the real
			// helper rather than a mock so the assertions below are on the bytes the
			// browser receives.
			httpHelper := handlerhelpers.NewHttpHelper(nil)

			req := httptest.NewRequest(http.MethodPost, "/admin/settings/keys/rotate", nil)
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

			rec := httptest.NewRecorder()

			handler := HandleAdminSettingsKeysRotatePost(httpHelper, &stubApiClient{rotateErr: tc.apiErr})
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			var response map[string]string
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, tc.wantError, response["error"])
			assert.Contains(t, response["error_description"], tc.wantDescription)

			if tc.wantStatus == http.StatusInternalServerError {
				// The generic branch must not leak the API's message either: that is
				// what sends it to the log rather than the screen.
				assert.NotContains(t, response["error_description"], tc.apiErr.Error())
			}
		})
	}
}

// TestHandleAdminSettingsKeysRotatePost_SuccessIsUnchanged is here so that routing the
// failure path through a different helper cannot alter what a successful rotation answers.
func TestHandleAdminSettingsKeysRotatePost_SuccessIsUnchanged(t *testing.T) {

	httpHelper := handlerhelpers.NewHttpHelper(nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/settings/keys/rotate", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

	rec := httptest.NewRecorder()

	handler := HandleAdminSettingsKeysRotatePost(httpHelper, &stubApiClient{rotateErr: nil})
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response struct {
		Success bool
	}
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
}
