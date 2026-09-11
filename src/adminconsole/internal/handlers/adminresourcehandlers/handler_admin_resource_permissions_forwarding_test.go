package adminresourcehandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// Decision 13 on the save itself, which is where the console's own sweep stopped one guard short.
//
// The other ten guards on this page were routed through the classifier, and this one kept a branch
// of its own: an *apiclient.APIError carrying 400 was turned into HTTP 200 with
// SavePermissionsResult{Success: false, Error: <the API's sentence>}. The comment on it argued the
// page needed a 200 because it draws the message from result.Error. That was not true.
// sendAjaxRequest in web/static/utils.js shows error_description from any non-2xx in the same
// modal0 the callback uses, and escapes it on the way in, where the 200 path handed the value
// straight to showModalDialog, which assigns innerHTML. So the 200 bought nothing and cost two
// things: every reader of the status was told a save had succeeded when it had not, and the one
// path that skipped escaping was the one carrying a value the API had echoed back.
//
// The handler is exercised through the real HttpHelper rather than the mock, because the status on
// the wire is the whole of what this pins; NewHttpHelper(nil) never reaches a template on a
// JsonError path carrying a status.
type savePermissionsApiClient struct {
	apiclient.ApiClient
	resource  *models.Resource
	updateErr error
}

func (c *savePermissionsApiClient) GetResourceById(accessToken string, resourceId int64) (*models.Resource, error) {
	return c.resource, nil
}

func (c *savePermissionsApiClient) UpdateResourcePermissions(accessToken string, resourceId int64,
	req *api.UpdateResourcePermissionsRequest) error {
	return c.updateErr
}

func TestResourcePermissionsPost_ForwardsTheApisStatus(t *testing.T) {
	testCases := []struct {
		name            string
		updateErr       error
		wantStatus      int
		wantCode        string
		wantDescription string
	}{
		{
			// The case that regressed: a permission identifier or description the API refused.
			name: "a value the API refused arrives as a 400 with its own sentence",
			updateErr: &apiclient.APIError{
				Code:       "VALIDATION_ERROR",
				Message:    "Permission read-audit-log is duplicated.",
				StatusCode: http.StatusBadRequest,
			},
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "Permission read-audit-log is duplicated.",
		},
		{
			name: "a resource deleted while the page was open",
			updateErr: &apiclient.APIError{
				Code:       "NOT_FOUND",
				Message:    "Resource not found",
				StatusCode: http.StatusNotFound,
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "not_found",
		},
		{
			name: "a conflict the API reports, forwarded with its own sentence",
			updateErr: &apiclient.APIError{
				Code:       "PERMISSION_IN_USE",
				Message:    "That permission is still assigned",
				StatusCode: http.StatusConflict,
			},
			wantStatus:      http.StatusConflict,
			wantCode:        "PERMISSION_IN_USE",
			wantDescription: "That permission is still assigned",
		},
		{
			// A server fault stays a server fault: the API's sentence goes to the log and the
			// browser gets the generic one with a request id.
			name: "a server fault is not forwarded",
			updateErr: &apiclient.APIError{
				Code:       "INTERNAL_SERVER_ERROR",
				Message:    "the database is on fire",
				StatusCode: http.StatusInternalServerError,
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "server_error",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			body, err := json.Marshal(SavePermissionsInput{
				ResourceId:  3,
				Permissions: []Permission{{Identifier: "read-audit-log", Description: "Reads it"}},
			})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/admin/resources/3/permissions", bytes.NewReader(body))
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}}))
			rec := httptest.NewRecorder()

			router := chi.NewRouter()
			router.Post("/admin/resources/{resourceId}/permissions",
				HandleAdminResourcePermissionsPost(
					handlerhelpers.NewHttpHelper(nil),
					nil,
					&savePermissionsApiClient{
						resource:  &models.Resource{Id: 3},
						updateErr: testCase.updateErr,
					}))
			router.ServeHTTP(rec, req)

			assert.Equal(t, testCase.wantStatus, rec.Code,
				"the API's status is what the browser has to see; a 200 here reports a save that did not happen")

			var answer struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
				// Present only if the handler fell back to the success envelope, which is the
				// shape this test exists to refuse.
				Success *bool `json:"Success"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))

			assert.Nil(t, answer.Success, "a failure must not arrive in the success envelope")
			assert.Equal(t, testCase.wantCode, answer.Error)
			if testCase.wantDescription != "" {
				assert.Equal(t, testCase.wantDescription, answer.ErrorDescription,
					"sendAjaxRequest reads error_description; this is the sentence the administrator sees")
			}
		})
	}
}
