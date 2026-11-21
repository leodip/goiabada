package admingrouphandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
)

// membersRemoveRecordingAPIClient records the ids the one write was asked for.
type membersRemoveRecordingAPIClient struct {
	calls           int
	groupID, userID int64
}

func (c *membersRemoveRecordingAPIClient) RemoveUserFromGroup(_ context.Context, _ string, groupID int64, userID int64) error {
	c.calls++
	c.groupID, c.userID = groupID, userID
	return nil
}

// The route binds two path values, and the handler hands each to the API in its own place: the
// group named by {groupId} loses the user named by {userId}. Two different numbers, so reading
// either value under the other's name sends the wrong pair.
func TestHandleMembersRemoveUserPost_RemovesTheUserItsPathNamesFromTheGroupItsPathNames(t *testing.T) {
	apiClient := &membersRemoveRecordingAPIClient{}
	req := handlertest.Request(http.MethodPost, "/admin/groups/5/members/42/remove",
		handlertest.WithAccessToken(),
		handlertest.WithPathValue("groupId", "5"),
		handlertest.WithPathValue("userId", "42"),
	)
	rec := httptest.NewRecorder()

	HandleMembersRemoveUserPost(render.New(nil, nil), apiClient).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 1, apiClient.calls)
	assert.Equal(t, int64(5), apiClient.groupID)
	assert.Equal(t, int64(42), apiClient.userID)
}
