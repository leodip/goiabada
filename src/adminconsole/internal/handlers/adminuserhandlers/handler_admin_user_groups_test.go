package adminuserhandlers

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

// userGroupsSaveApiClient records the request the save hands the API and answers it with err.
type userGroupsSaveApiClient struct {
	apiclient.ApiClient
	err  error
	sent *api.UpdateUserGroupsRequest
}

func (s *userGroupsSaveApiClient) UpdateUserGroups(_ context.Context, _ string, _ int64, request *api.UpdateUserGroupsRequest) (*api.UserResponse, []api.GroupResponse, error) {
	s.sent = request
	return nil, nil, s.err
}

// The page posts the set as it loaded it beside the set it wants, and the handler hands both to
// the API unchanged: the auth server compares the loaded set with the stored memberships and
// refuses a save from an outdated page (#428). The empty and absent rows pin the distinction the
// API reads: [] is a page that loaded no groups and must reach the wire as [], and a body without
// the field must reach it as null, which the API refuses, rather than be defaulted to a set that
// would pass.
func TestHandleAdminUserGroupsPost_SendsTheLoadedList(t *testing.T) {
	testCases := []struct {
		name         string
		body         string
		wantWanted   []int64
		wantExpected []int64
		wantWire     string
	}{
		{
			name:         "the loaded set passes through beside the wanted one",
			body:         `{"assignedGroupsIds":[4,6],"expectedGroupIds":[3,4]}`,
			wantWanted:   []int64{4, 6},
			wantExpected: []int64{3, 4},
			wantWire:     `"expectedGroupIds":[3,4]`,
		},
		{
			name:         "an empty loaded set stays an empty list",
			body:         `{"assignedGroupsIds":[6],"expectedGroupIds":[]}`,
			wantWanted:   []int64{6},
			wantExpected: []int64{},
			wantWire:     `"expectedGroupIds":[]`,
		},
		{
			name:         "an absent loaded set stays absent",
			body:         `{"assignedGroupsIds":[6]}`,
			wantWanted:   []int64{6},
			wantExpected: nil,
			wantWire:     `"expectedGroupIds":null`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlerhelpers.NewHttpHelper(nil, adminmiddleware.SettingsReader{})
			req := handlertest.Request(http.MethodPost, "/admin/users/5/groups",
				handlertest.WithAccessToken(),
				handlertest.WithRouteParam("userId", "5"),
				handlertest.WithBody(bytes.NewBufferString(tc.body)),
			)

			// The API refuses, so the handler returns before the nil session is touched; the
			// request it sent is what is under test.
			stub := &userGroupsSaveApiClient{err: &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "refused", StatusCode: http.StatusBadRequest}}
			HandleAdminUserGroupsPost(httpHelper, nil, stub).ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, stub.sent)
			assert.Equal(t, tc.wantWanted, stub.sent.GroupIds)
			assert.Equal(t, tc.wantExpected, stub.sent.ExpectedGroupIds)
			wire, err := json.Marshal(stub.sent)
			require.NoError(t, err)
			assert.Contains(t, string(wire), tc.wantWire)
		})
	}
}

// A save from an outdated page reaches the administrator as the API's own sentence and status,
// telling them to reload, rather than the generic error (#428).
func TestHandleAdminUserGroupsPost_AConflictReachesTheBrowser(t *testing.T) {
	const sentence = "The list was changed by another save after it was loaded."
	httpHelper := handlerhelpers.NewHttpHelper(nil, adminmiddleware.SettingsReader{})
	req := handlertest.Request(http.MethodPost, "/admin/users/5/groups",
		handlertest.WithAccessToken(),
		handlertest.WithRouteParam("userId", "5"),
		handlertest.WithBody(bytes.NewBufferString(`{"assignedGroupsIds":[6],"expectedGroupIds":[3]}`)),
	)
	rec := httptest.NewRecorder()

	stub := &userGroupsSaveApiClient{err: &apiclient.APIError{Code: "CONCURRENT_UPDATE", Message: sentence, StatusCode: http.StatusConflict}}
	HandleAdminUserGroupsPost(httpHelper, nil, stub).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
	var response map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, "CONCURRENT_UPDATE", response["error"])
	assert.Equal(t, sentence, response["error_description"])
}
