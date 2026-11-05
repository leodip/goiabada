package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every audit row records the user it is about and the user whose access token made the request
// (#780 decisions 1 and 2). These tests change a user through the admin API and read the row that
// change stored, so what they observe is the logger and the session guard together, as deployed.

// createUserToChange creates an enabled user for an administrator to change, deleted when the test
// ends.
func createUserToChange(t *testing.T) *record.User {
	t.Helper()
	user := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("audit-columns@user.test"),
		GivenName:     "Audit",
		FamilyName:    "Columns",
		EmailVerified: true,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user
}

// disableUserUnderRequestId disables user through the admin API with accessToken, under a request
// id of its own, and answers that id.
func disableUserUnderRequestId(t *testing.T, accessToken string, user *record.User) string {
	t.Helper()
	body, err := json.Marshal(api.UpdateUserEnabledRequest{Enabled: false})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut,
		appConfig.AuthServer.BaseURL+"/api/v1/admin/users/"+strconv.FormatInt(user.Id, 10)+"/enabled",
		bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	requestId := "user-columns-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return requestId
}

// storedRow is the one row of event that request requestId stored.
func storedRow(t *testing.T, event, requestId string) record.AuditLog {
	t.Helper()
	rows, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10,
		record.AuditLogFilter{AuditEvent: event, RequestId: requestId})
	require.NoError(t, err)
	require.Equal(t, 1, total, "one %s row for request %s", event, requestId)
	return rows[0]
}

func TestAuditLogUserColumns_AChangeMadeWithAUsersToken(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, administrator := createUserAccessTokenWithScope(t,
		builtin.AuthServerResourceIdentifier+":"+builtin.ManageUsersPermissionIdentifier)
	changed := createUserToChange(t)
	require.NotEqual(t, administrator.Id, changed.Id)

	requestId := disableUserUnderRequestId(t, adminToken, changed)

	row := storedRow(t, "updated_user_details", requestId)
	assert.Equal(t, sql.NullInt64{Int64: changed.Id, Valid: true}, row.UserId,
		"user_id is the user the change was made to")
	assert.Equal(t, sql.NullInt64{Int64: administrator.Id, Valid: true}, row.LoggedInUserId,
		"logged_in_user_id is the administrator whose token made the change")

	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.Details), &details))
	assert.Equal(t, map[string]any{
		"user_id":        float64(changed.Id),
		"logged_in_user": administrator.Subject,
	}, details, "the details are written as before")
}

func TestAuditLogUserColumns_AChangeMadeWithAClientCredentialsToken(t *testing.T) {
	requireDatabaseAuditLogs(t)
	clientToken, client := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	changed := createUserToChange(t)

	requestId := disableUserUnderRequestId(t, clientToken, changed)

	row := storedRow(t, "updated_user_details", requestId)
	assert.Equal(t, sql.NullInt64{Int64: changed.Id, Valid: true}, row.UserId,
		"user_id is the user the change was made to")
	assert.False(t, row.LoggedInUserId.Valid, "a client credentials token has no user, so logged_in_user_id is NULL")
}
