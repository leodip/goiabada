package adminclienthandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/oauth"
)

// stubApiClient embeds apiclient.ApiClient so its hundred-odd other methods come for free
// and any of them that a test does not stub panics on a nil interface, which is the right
// outcome for a call the test did not expect. There is no generated mock: adminconsole has
// no .mockery.yaml.
type stubApiClient struct {
	apiclient.ApiClient
	updateErr error
}

func (s *stubApiClient) UpdateClientRedirectURIs(accessToken string, clientId int64,
	request *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error) {
	return nil, s.updateErr
}

// The auth server refuses a redirect URI with a 400 whose description names the offending
// value. The administrator has to be able to read that sentence: it is the only thing that
// says which of their URIs was rejected and why, and the page's own new URL() check accepts
// values the server now refuses, so this is a first-try path rather than an edge case (#122).
//
// The rows for the other statuses are what keeps the forwarding narrow: a genuine server
// fault must stay a generic 500 with its detail in the log, not be reported to the
// administrator as their own mistake.
func TestHandleAdminClientRedirectURIsPost_APIErrorReachesTheBrowser(t *testing.T) {

	const refusal = "Redirect URI must be an absolute URI (a scheme is required, a fragment " +
		"is not permitted, percent-escapes must be well formed, and an http or https URI must " +
		"name a host): https:///evil.example/cb"

	const generic = "An unexpected server error has occurred"

	testCases := []struct {
		name            string
		apiErr          error
		wantStatus      int
		wantError       string
		wantDescription string
	}{
		{
			name:            "a 400 is forwarded with its status and description",
			apiErr:          &apiclient.APIError{Code: "VALIDATION_ERROR", Message: refusal, StatusCode: http.StatusBadRequest},
			wantStatus:      http.StatusBadRequest,
			wantError:       "VALIDATION_ERROR",
			wantDescription: refusal,
		},
		{
			name:            "a 500 from the API stays generic",
			apiErr:          &apiclient.APIError{Code: "SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
		{
			name:            "a 403 from the API stays generic",
			apiErr:          &apiclient.APIError{Code: "FORBIDDEN", Message: "insufficient permissions", StatusCode: http.StatusForbidden},
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

			body := `{"clientId":1,"redirectURIs":["https:///evil.example/cb"]}`
			req := httptest.NewRequest(http.MethodPost, "/admin/clients/1/redirect-uris",
				bytes.NewBufferString(body))
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))

			rec := httptest.NewRecorder()

			// httpSession is nil: every case here returns before the session is touched.
			handler := HandleAdminClientRedirectURIsPost(httpHelper, nil, &stubApiClient{updateErr: tc.apiErr})
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			var response map[string]string
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, tc.wantError, response["error"])
			assert.Contains(t, response["error_description"], tc.wantDescription)

			if tc.wantStatus != http.StatusBadRequest {
				// The generic branch must not leak the API's message either: that is
				// what sends it to the log rather than the screen.
				assert.NotContains(t, response["error_description"], tc.apiErr.Error())
			}
		})
	}
}
