package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the user's groups: both endpoints swallowed a failed count and published 0.
// requireCountFailureAnswered500 is handler_api_groups_test.go's.

// loadGroupsOnto answers UserLoadGroups by setting the user's groups, as commondb does.
func loadGroupsOnto(groups ...models.Group) func(mock.Arguments) {
	return func(args mock.Arguments) {
		args.Get(2).(*models.User).Groups = groups
	}
}

// usergroups/get-count.
func TestHandleAPIUserGroupsGet_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetUserById", mock.Anything, mock.Anything, int64(42)).
		Return(&models.User{Id: 42, Subject: "sub-42"}, nil).Once()
	database.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).
		Run(loadGroupsOnto(models.Group{Id: 5, GroupIdentifier: "admins"})).Return(nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(0, errCountFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIUserGroupsGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/users/42/groups", "42"))

	requireCountFailureAnswered500(t, rr, capture, 5)
	require.Equal(t, int64(42), capture.Records()[0].Attrs["user_id"])
}

// usergroups/put-count: the membership is written and audited before the response is counted, so
// the 500 answers a request whose effect stands. What the case pins is that the response does not
// then claim the group has no members.
func TestHandleAPIUserGroupsPut_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	database.On("GetUserById", mock.Anything, mock.Anything, int64(42)).
		Return(&models.User{Id: 42, Subject: "sub-42"}, nil).Once()
	database.On("GetGroupsByIds", mock.Anything, mock.Anything, []int64{5}).
		Return([]models.Group{{Id: 5, GroupIdentifier: "admins"}}, nil).Once()
	// The user holds no group before the request and the one it names after it.
	database.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).
		Run(loadGroupsOnto()).Return(nil).Once()
	database.On("CreateUserGroup", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.AuditUserAddedToGroup, mock.Anything).Return().Once()
	database.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).
		Run(loadGroupsOnto(models.Group{Id: 5, GroupIdentifier: "admins"})).Return(nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(0, errCountFailed).Once()

	body, err := json.Marshal(api.UpdateUserGroupsRequest{GroupIds: []int64{5}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/groups", bytes.NewReader(body))
	req = setChiURLParam(req, "id", "42")

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIUserGroupsPut(database, auditLogger).ServeHTTP(rr, req)

	requireCountFailureAnswered500(t, rr, capture, 5)
	require.Equal(t, int64(42), capture.Records()[0].Attrs["user_id"])
}
