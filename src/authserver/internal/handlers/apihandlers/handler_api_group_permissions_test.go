package apihandlers

import (
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/mock"
)

// groupperms/count, the fourth swallowing site and the one #425 itself did not list: the group
// shown beside its permissions was published with 0 members on a failed count.
// requireCountFailureAnswered500 is handler_api_groups_test.go's.
//
// The save's cases are in grant_list_saves_test.go, run once for it and once for the user save.
// The two #425 cases that stood here pinned nil results from lookups the save no longer makes: it
// reads the grants once, on its transaction, and deletes by the ids that read returned (#406, #428).
func TestHandleAPIGroupPermissionsGet_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetGroupById", mock.Anything, mock.Anything, int64(5)).
		Return(&models.Group{Id: 5, GroupIdentifier: "admins"}, nil).Once()
	database.On("GroupLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(0, errCountFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIGroupPermissionsGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/groups/5/permissions", "5"))

	requireCountFailureAnswered500(t, rr, capture, 5)
}
