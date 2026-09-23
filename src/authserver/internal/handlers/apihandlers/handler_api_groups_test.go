package apihandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the member counts. Four endpoints swallowed a failed CountGroupMembers and
// published 0, which renders a group as empty when the server never learned how many members it
// has. Each now answers the one 500 through countGroupMembers (decision 4), and every case here
// asserts the same three things: the 500 envelope, no group in the body, and one record naming
// the group whose count failed.

// errCountFailed stands in for the database refusing the count.
var errCountFailed = errs.New("the member count query failed")

// requireCountFailureAnswered500 asserts what every count failure on this surface owes: the one
// 500 envelope, with nothing of the groups in it, and one Error record carrying the failure and
// the group it was counting.
func requireCountFailureAnswered500(t *testing.T, rr *httptest.ResponseRecorder, capture *testutil.SlogCapture, groupId int64) {
	t.Helper()

	require.Equal(t, http.StatusInternalServerError, rr.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "INTERNAL_SERVER_ERROR", body["error_code"])
	assert.NotContains(t, body, "groups", "a failed count publishes no group list")
	assert.NotContains(t, body, "group", "a failed count publishes no group")

	records := capture.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].Level)
	logged := fmt.Sprint(records[0].Attrs["error"])
	assert.Contains(t, logged, errCountFailed.Error())
	assert.Contains(t, logged, fmt.Sprintf("unable to count the members of group %d", groupId))
}

func TestCountGroupMembers_CountsEveryGroup(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(2, nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(6)).Return(0, nil).Once()

	counts, err := countGroupMembers(context.Background(), database, []models.Group{{Id: 5}, {Id: 6}})

	require.NoError(t, err)
	assert.Equal(t, map[int64]int{5: 2, 6: 0}, counts)
}

// The first failure ends the walk: no count is returned for any group, so a caller cannot publish
// the ones that succeeded beside a 0 for the one that did not, and the group after it is never
// asked.
func TestCountGroupMembers_StopsAtTheFirstFailureAndNamesTheGroup(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(2, nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(6)).Return(0, errCountFailed).Once()

	counts, err := countGroupMembers(context.Background(), database, []models.Group{{Id: 5}, {Id: 6}, {Id: 7}})

	require.ErrorIs(t, err, errCountFailed)
	assert.Contains(t, err.Error(), "unable to count the members of group 6")
	assert.Nil(t, counts)
	database.AssertNotCalled(t, "CountGroupMembers", mock.Anything, mock.Anything, int64(7))
}

func TestCountGroupMembers_NoGroupsIsAnEmptyMap(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	counts, err := countGroupMembers(context.Background(), database, nil)

	require.NoError(t, err)
	assert.Empty(t, counts)
}

// groups/list-count: the list used to render the failed group with 0 members.
func TestHandleAPIGroupsGet_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetAllGroups", mock.Anything, mock.Anything).
		Return([]models.Group{{Id: 5, GroupIdentifier: "admins"}, {Id: 6, GroupIdentifier: "staff"}}, nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(2, nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(6)).Return(0, errCountFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIGroupsGet(database).ServeHTTP(rr, apiRequestCarryingId("/api/v1/admin/groups"))

	requireCountFailureAnswered500(t, rr, capture, 6)
}

// The accept arm beside it: every count reaches its own group in the body.
func TestHandleAPIGroupsGet_PublishesEachGroupsOwnCount(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetAllGroups", mock.Anything, mock.Anything).
		Return([]models.Group{{Id: 5, GroupIdentifier: "admins"}, {Id: 6, GroupIdentifier: "staff"}}, nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(2, nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(6)).Return(7, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIGroupsGet(database).ServeHTTP(rr, apiRequestCarryingId("/api/v1/admin/groups"))

	require.Equal(t, http.StatusOK, rr.Code)
	var body struct {
		Groups []struct {
			Id          int64 `json:"id"`
			MemberCount int   `json:"memberCount"`
		} `json:"groups"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Len(t, body.Groups, 2)
	assert.Equal(t, 2, body.Groups[0].MemberCount)
	assert.Equal(t, 7, body.Groups[1].MemberCount)
}

// groups/get-count already answered 500; it now does so through the same helper.
func TestHandleAPIGroupGet_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetGroupById", mock.Anything, mock.Anything, int64(5)).
		Return(&models.Group{Id: 5, GroupIdentifier: "admins"}, nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(0, errCountFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIGroupGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/groups/5", "5"))

	requireCountFailureAnswered500(t, rr, capture, 5)
}
