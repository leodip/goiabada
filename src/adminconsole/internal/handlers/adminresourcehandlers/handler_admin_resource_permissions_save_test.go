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
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	adminmiddleware "github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/core/api"
)

// resourcePermissionsSaveApiClient records the request the save hands the API and answers it with
// err.
type resourcePermissionsSaveApiClient struct {
	apiclient.ApiClient
	err  error
	sent *api.UpdateResourcePermissionsRequest
}

func (s *resourcePermissionsSaveApiClient) GetResourceById(_ context.Context, _ string, resourceId int64) (*api.ResourceResponse, error) {
	return &api.ResourceResponse{Id: resourceId}, nil
}

func (s *resourcePermissionsSaveApiClient) UpdateResourcePermissions(_ context.Context, _ string, _ int64, request *api.UpdateResourcePermissionsRequest) error {
	s.sent = request
	return s.err
}

// serveResourcePermissionsSave posts body to the save through a router, so the resource id reaches
// the handler as it does in production.
func serveResourcePermissionsSave(stub *resourcePermissionsSaveApiClient, body string) *httptest.ResponseRecorder {
	req := handlertest.Request(http.MethodPost, "/admin/resources/3/permissions",
		handlertest.WithAccessToken(),
		handlertest.WithBody(bytes.NewBufferString(body)),
	)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Post("/admin/resources/{resourceId}/permissions",
		HandleAdminResourcePermissionsPost(handlerhelpers.NewHttpHelper(nil, adminmiddleware.SettingsReader{}), nil, stub))
	router.ServeHTTP(rec, req)
	return rec
}

// The page posts the list as it loaded it beside the list it wants, and the handler hands the
// loaded one to the API as sent: the auth server compares each entry with the stored one exactly,
// so the handler trims the wanted entries and not the loaded ones (#428). The empty and absent
// rows pin the distinction the API reads: [] is a page that loaded no permissions and must reach
// the wire as [], and a body without the field must reach it as null, which the API refuses,
// rather than be defaulted to a list that would pass.
func TestHandleAdminResourcePermissionsPost_SendsTheLoadedList(t *testing.T) {
	testCases := []struct {
		name         string
		body         string
		wantExpected []api.ResourcePermissionUpsert
		wantWire     string
	}{
		{
			name: "the loaded list passes through as sent beside the wanted one",
			body: `{"resourceId":3,"permissions":[{"id":9,"permissionIdentifier":" ler ","description":"Ler"}],` +
				`"expectedPermissions":[{"id":9,"permissionIdentifier":"ler","description":" Ler faturas "}]}`,
			wantExpected: []api.ResourcePermissionUpsert{{Id: 9, PermissionIdentifier: "ler", Description: " Ler faturas "}},
			wantWire:     `"expectedPermissions":[{"id":9,"permissionIdentifier":"ler","description":" Ler faturas "}]`,
		},
		{
			name:         "an empty loaded list stays an empty list",
			body:         `{"resourceId":3,"permissions":[],"expectedPermissions":[]}`,
			wantExpected: []api.ResourcePermissionUpsert{},
			wantWire:     `"expectedPermissions":[]`,
		},
		{
			name:         "an absent loaded list stays absent",
			body:         `{"resourceId":3,"permissions":[]}`,
			wantExpected: nil,
			wantWire:     `"expectedPermissions":null`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// The API refuses, so the handler returns before the nil session is touched; the
			// request it sent is what is under test.
			stub := &resourcePermissionsSaveApiClient{err: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "refused", StatusCode: http.StatusBadRequest}}
			serveResourcePermissionsSave(stub, tc.body)

			require.NotNil(t, stub.sent)
			assert.Equal(t, tc.wantExpected, stub.sent.ExpectedPermissions)
			wire, err := json.Marshal(stub.sent)
			require.NoError(t, err)
			assert.Contains(t, string(wire), tc.wantWire)
		})
	}

	t.Run("the wanted entries are trimmed as before", func(t *testing.T) {
		stub := &resourcePermissionsSaveApiClient{err: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "refused", StatusCode: http.StatusBadRequest}}
		serveResourcePermissionsSave(stub, testCases[0].body)

		require.NotNil(t, stub.sent)
		assert.Equal(t, []api.ResourcePermissionUpsert{{Id: 9, PermissionIdentifier: "ler", Description: "Ler"}}, stub.sent.Permissions)
	})
}

// A save from an outdated page reaches the administrator as the API's own sentence and status,
// telling them to reload, rather than the generic error (#428).
func TestHandleAdminResourcePermissionsPost_AConflictReachesTheBrowser(t *testing.T) {
	const sentence = "The list was changed by another save after it was loaded."
	stub := &resourcePermissionsSaveApiClient{err: &apiclient.APIError{Code: "CONCURRENT_UPDATE", Message: sentence, StatusCode: http.StatusConflict}}

	rec := serveResourcePermissionsSave(stub, `{"resourceId":3,"permissions":[],"expectedPermissions":[]}`)

	assert.Equal(t, http.StatusConflict, rec.Code)
	var answer struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))
	assert.Equal(t, "CONCURRENT_UPDATE", answer.Error)
	assert.Equal(t, sentence, answer.ErrorDescription, "sendAjaxRequest reads error_description; this is the sentence the administrator sees")
}
