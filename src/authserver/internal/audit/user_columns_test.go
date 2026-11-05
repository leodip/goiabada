package audit

import (
	"context"
	"database/sql"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// actingUserKey is where these tests put the acting user on a context, standing in for the session
// guard's own key, which only reqctx can write.
type actingUserKey struct{}

// fakeActingUser is the acting-user port as the production adapter behaves: it answers the user
// the context carries, so a logger that asked it with another context than the caller's would
// find none.
type fakeActingUser struct{}

func (fakeActingUser) ActingUserId(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(actingUserKey{}).(int64)
	return id, ok
}

// actingAs is a request's context once the session guard has found userId's token live.
func actingAs(userId int64) context.Context {
	return context.WithValue(context.Background(), actingUserKey{}, userId)
}

// rowWritten logs one event with the database target on and answers the row CreateAuditLog was
// handed.
func rowWritten(t *testing.T, actingUser actingUserSource, ctx context.Context, details map[string]interface{}) *record.AuditLog {
	t.Helper()
	var row *record.AuditLog
	mockDB := datamocks.NewDatabase(t)
	mockDB.On("CreateAuditLog", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { row = args.Get(2).(*record.AuditLog) }).
		Return(nil).Once()

	NewLogger(mockDB, databaseOnly(), actingUser).Log(ctx, "updated_user_details", details)

	require.NotNil(t, row, "the row handed to CreateAuditLog")
	return row
}

func userColumn(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }

var noUser = sql.NullInt64{}

// The row records the user the event is about, copied from the details' user_id, and the user
// whose token made the request, from the acting-user port; NULL for each when there is none
// (#780 decisions 1 and 2).
func TestLogger_TheRowRecordsTheUserItIsAboutAndTheUserWhoActed(t *testing.T) {
	tests := []struct {
		label          string
		ctx            context.Context
		details        map[string]interface{}
		userId         sql.NullInt64
		loggedInUserId sql.NullInt64
	}{
		{
			label:          "an administrator acting on another user",
			ctx:            actingAs(7),
			details:        map[string]interface{}{"user_id": int64(42), "logged_in_user": "admin-subject"},
			userId:         userColumn(42),
			loggedInUserId: userColumn(7),
		},
		{
			label:          "a user acting on their own account",
			ctx:            actingAs(42),
			details:        map[string]interface{}{"user_id": int64(42)},
			userId:         userColumn(42),
			loggedInUserId: userColumn(42),
		},
		{
			label:          "a browser sign-in, which has no token",
			ctx:            context.Background(),
			details:        map[string]interface{}{"user_id": int64(42)},
			userId:         userColumn(42),
			loggedInUserId: noUser,
		},
		{
			label:          "an event about no user, made with a user's token",
			ctx:            actingAs(7),
			details:        map[string]interface{}{"client_id": int64(3), "logged_in_user": "admin-subject"},
			userId:         noUser,
			loggedInUserId: userColumn(7),
		},
		{
			label:          "an event about no user, made with no user's token",
			ctx:            context.Background(),
			details:        map[string]interface{}{"logged_in_user": "integration-client"},
			userId:         noUser,
			loggedInUserId: noUser,
		},
		{
			label:          "no details at all",
			ctx:            context.Background(),
			details:        nil,
			userId:         noUser,
			loggedInUserId: noUser,
		},
		{
			// A payload naming user 0 asserts a row that does not exist.
			label:          "a user_id of 0",
			ctx:            context.Background(),
			details:        map[string]interface{}{"user_id": int64(0)},
			userId:         noUser,
			loggedInUserId: noUser,
		},
		{
			label:          "a negative user_id",
			ctx:            context.Background(),
			details:        map[string]interface{}{"user_id": int64(-5)},
			userId:         noUser,
			loggedInUserId: noUser,
		},
		{
			label:          "a user_id held as an int",
			ctx:            context.Background(),
			details:        map[string]interface{}{"user_id": 9},
			userId:         userColumn(9),
			loggedInUserId: noUser,
		},
		{
			// A subject or any other string is not a row id.
			label:          "a user_id that is not a number",
			ctx:            context.Background(),
			details:        map[string]interface{}{"user_id": "42"},
			userId:         noUser,
			loggedInUserId: noUser,
		},
		{
			// cross_user_session_replaced names two users; the column is what user_id says, and
			// the previous user stays in the details (#780 decision 4).
			label: "a handover naming the previous user",
			ctx:   context.Background(),
			details: map[string]interface{}{
				"user_id":          int64(42),
				"previous_user_id": int64(8),
			},
			userId:         userColumn(42),
			loggedInUserId: noUser,
		},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			row := rowWritten(t, fakeActingUser{}, tc.ctx, tc.details)
			assert.Equal(t, tc.userId, row.UserId, "user_id, the user the event is about")
			assert.Equal(t, tc.loggedInUserId, row.LoggedInUserId, "logged_in_user_id, the user who acted")
		})
	}
}

// The columns are the database's alone: the details stored beside them, and the details the
// console record carries, are the caller's map, unchanged.
func TestLogger_TheColumnsLeaveTheDetailsAsTheyAre(t *testing.T) {
	row := rowWritten(t, fakeActingUser{}, actingAs(7),
		map[string]interface{}{"user_id": int64(42), "logged_in_user": "admin-subject"})
	assert.JSONEq(t, `{"user_id":42,"logged_in_user":"admin-subject"}`, row.Details)
}

// A logger built without an acting-user port records the event, with no acting user, rather than
// losing it.
func TestLogger_WithoutAnActingUserPortTheActorIsNull(t *testing.T) {
	row := rowWritten(t, nil, actingAs(7), map[string]interface{}{"user_id": int64(42)})
	assert.Equal(t, userColumn(42), row.UserId)
	assert.Equal(t, noUser, row.LoggedInUserId)
}
