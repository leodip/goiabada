package admingrouphandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	adminmiddleware "github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/core/api"
)

// groupPermissionsSaveApiClient records the request the save hands the API and answers it with err.
type groupPermissionsSaveApiClient struct {
	apiclient.ApiClient
	err  error
	sent *api.UpdateGroupPermissionsRequest
}

func (s *groupPermissionsSaveApiClient) UpdateGroupPermissions(_ context.Context, _ string, _ int64, request *api.UpdateGroupPermissionsRequest) error {
	s.sent = request
	return s.err
}

// The page posts the set as it loaded it beside the set it wants, and the handler hands both to
// the API unchanged, as the user permission page does (#428). [] reaches the wire as [], and an
// absent field as the null the API refuses.
func TestHandleAdminGroupPermissionsPost_SendsTheLoadedList(t *testing.T) {
	testCases := []struct {
		name         string
		body         string
		wantWanted   []int64
		wantExpected []int64
		wantWire     string
	}{
		{
			name:         "the loaded set passes through beside the wanted one",
			body:         `{"groupId":5,"assignedPermissionsIds":[4,6],"expectedPermissionIds":[3,4]}`,
			wantWanted:   []int64{4, 6},
			wantExpected: []int64{3, 4},
			wantWire:     `"expectedPermissionIds":[3,4]`,
		},
		{
			name:         "an empty loaded set stays an empty list",
			body:         `{"groupId":5,"assignedPermissionsIds":[6],"expectedPermissionIds":[]}`,
			wantWanted:   []int64{6},
			wantExpected: []int64{},
			wantWire:     `"expectedPermissionIds":[]`,
		},
		{
			name:         "an absent loaded set stays absent",
			body:         `{"groupId":5,"assignedPermissionsIds":[6]}`,
			wantWanted:   []int64{6},
			wantExpected: nil,
			wantWire:     `"expectedPermissionIds":null`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlerhelpers.NewHttpHelper(nil, adminmiddleware.SettingsReader{})
			req := handlertest.Request(http.MethodPost, "/admin/groups/5/permissions",
				handlertest.WithAccessToken(),
				handlertest.WithBody(bytes.NewBufferString(tc.body)),
			)

			// The API refuses, so the handler returns before the nil session is touched.
			stub := &groupPermissionsSaveApiClient{err: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "refused", StatusCode: http.StatusBadRequest}}
			HandleAdminGroupPermissionsPost(httpHelper, nil, stub).ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, stub.sent)
			assert.Equal(t, tc.wantWanted, stub.sent.PermissionIds)
			assert.Equal(t, tc.wantExpected, stub.sent.ExpectedPermissionIds)
			wire, err := json.Marshal(stub.sent)
			require.NoError(t, err)
			assert.Contains(t, string(wire), tc.wantWire)
		})
	}
}

// A save from an outdated page reaches the administrator as the API's own sentence and status,
// telling them to reload, rather than the generic error (#428).
func TestHandleAdminGroupPermissionsPost_AConflictReachesTheBrowser(t *testing.T) {
	const sentence = "The list was changed by another save after it was loaded."
	httpHelper := handlerhelpers.NewHttpHelper(nil, adminmiddleware.SettingsReader{})
	req := handlertest.Request(http.MethodPost, "/admin/groups/5/permissions",
		handlertest.WithAccessToken(),
		handlertest.WithBody(bytes.NewBufferString(`{"groupId":5,"assignedPermissionsIds":[6],"expectedPermissionIds":[3]}`)),
	)
	rec := httptest.NewRecorder()

	stub := &groupPermissionsSaveApiClient{err: &apiclient.APIError{Code: "CONCURRENT_UPDATE", Message: sentence, StatusCode: http.StatusConflict}}
	HandleAdminGroupPermissionsPost(httpHelper, nil, stub).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
	var response map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, "CONCURRENT_UPDATE", response["error"])
	assert.Equal(t, sentence, response["error_description"])
}
