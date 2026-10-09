package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The last-administrator guard on real engines (#402 decisions 10 and 11). An administrator remains
// while at least one enabled user holds authserver:manage, directly or through a group, and a write
// that would bring that count to zero is refused. What a mock cannot show is what the count reads
// on each engine, and that two removals of the last two administrators at the same instant end with
// one committed and one refused rather than both committed.

// newHolder creates an enabled or disabled user on db, with nothing granted.
func newHolder(t *testing.T, db data.Database, enabled bool) *record.User {
	t.Helper()
	user := &record.User{Subject: fake.UUID(), Enabled: enabled, Email: fake.Email(), GivenName: fake.FirstName()}
	require.NoError(t, db.CreateUser(context.Background(), nil, user))
	return user
}

func grantToUser(t *testing.T, db data.Database, userId, permissionId int64) {
	t.Helper()
	require.NoError(t, db.CreateUserPermission(context.Background(), nil, &record.UserPermission{UserId: userId, PermissionId: permissionId}))
}

func grantToGroup(t *testing.T, db data.Database, groupId, permissionId int64) {
	t.Helper()
	require.NoError(t, db.CreateGroupPermission(context.Background(), nil, &record.GroupPermission{GroupId: groupId, PermissionId: permissionId}))
}

func joinGroup(t *testing.T, db data.Database, userId, groupId int64) {
	t.Helper()
	require.NoError(t, db.CreateUserGroup(context.Background(), nil, &record.UserGroup{UserId: userId, GroupId: groupId}))
}

// What the guard counts: the enabled users holding the permission, directly or through any of
// their groups, each once. A permission of the test's own, so the shared database's other rows
// cannot reach the count.
func TestCountEnabledUsersHoldingPermission(t *testing.T) {
	ctx := context.Background()
	resource := createTestResource(t)
	held := createTestPermission(t, resource)
	other := createTestPermission(t, resource)

	giving := createTestGroup(t)
	grantToGroup(t, database, giving.Id, held.Id)
	ordinary := createTestGroup(t)
	grantToGroup(t, database, ordinary.Id, other.Id)

	direct := newHolder(t, database, true)
	grantToUser(t, database, direct.Id, held.Id)

	throughGroup := newHolder(t, database, true)
	joinGroup(t, database, throughGroup.Id, giving.Id)

	both := newHolder(t, database, true)
	grantToUser(t, database, both.Id, held.Id)
	joinGroup(t, database, both.Id, giving.Id)

	disabledDirect := newHolder(t, database, false)
	grantToUser(t, database, disabledDirect.Id, held.Id)

	disabledThroughGroup := newHolder(t, database, false)
	joinGroup(t, database, disabledThroughGroup.Id, giving.Id)

	holdsAnotherPermission := newHolder(t, database, true)
	grantToUser(t, database, holdsAnotherPermission.Id, other.Id)
	joinGroup(t, database, holdsAnotherPermission.Id, ordinary.Id)

	count, err := database.CountEnabledUsersHoldingPermission(ctx, nil, held.Id)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "direct, through the group, and both counted once; the disabled and the other permission's holders not at all")

	t.Run("on a transaction, the count reads the transaction's own writes", func(t *testing.T) {
		tx := beginTx(t)
		directGrant, err := database.GetUserPermissionByUserIdAndPermissionId(ctx, tx, direct.Id, held.Id)
		require.NoError(t, err)
		require.NotNil(t, directGrant)
		require.NoError(t, database.DeleteUserPermission(ctx, tx, directGrant.Id))
		membership, err := database.GetUserGroupByUserIdAndGroupId(ctx, tx, both.Id, giving.Id)
		require.NoError(t, err)
		require.NotNil(t, membership)
		require.NoError(t, database.DeleteUserGroup(ctx, tx, membership.Id))

		count, err := database.CountEnabledUsersHoldingPermission(ctx, tx, held.Id)
		require.NoError(t, err)
		assert.Equal(t, 2, count, "direct lost its only grant; both still holds it directly")
		require.NoError(t, database.RollbackTransaction(ctx, tx))
	})

	t.Run("a permission nobody holds counts zero", func(t *testing.T) {
		nobody := createTestPermission(t, resource)
		count, err := database.CountEnabledUsersHoldingPermission(ctx, nil, nobody.Id)
		require.NoError(t, err)
		assert.Zero(t, count)
	})

	t.Run("an already cancelled context is refused, not a count of zero", func(t *testing.T) {
		_, err := database.CountEnabledUsersHoldingPermission(cancelled(), nil, held.Id)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// parkedAfterTheRemovalCounted parks a user deletion at the end of its transaction body: after it
// took the lock, decided, counted, deleted and counted again, and before it commits. That is the
// widest window two removals can overlap in, the one where each has seen the other administrator
// still there.
type parkedAfterTheRemovalCounted struct {
	data.Database
	b       *barrier
	deleted bool
}

func (d *parkedAfterTheRemovalCounted) DeleteUser(ctx context.Context, tx *sql.Tx, userId int64) error {
	err := d.Database.DeleteUser(ctx, tx, userId)
	if tx != nil {
		d.deleted = true
	}
	return err
}

func (d *parkedAfterTheRemovalCounted) CountEnabledUsersHoldingPermission(ctx context.Context, tx *sql.Tx, permissionId int64) (int, error) {
	count, err := d.Database.CountEnabledUsersHoldingPermission(ctx, tx, permissionId)
	if tx != nil && d.deleted {
		d.b.arriveBefore(tx)
	}
	return count, err
}

// serveAsManage serves one admin API request through handler, with no router, under a validated
// token carrying authserver:manage, the only token that reaches the guard. The body arrives
// encoded, because the callers serve from a worker goroutine and an encoding failure has to stop
// the test on its own goroutine.
func serveAsManage(handler http.HandlerFunc, method, target string, params map[string]string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	for key, value := range params {
		rctx.URLParams.Add(key, value)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = reqctx.WithSettings(ctx, &record.Settings{Id: 1})
	ctx = reqctx.WithValidatedToken(ctx, oauth.JwtToken{Claims: map[string]interface{}{
		"sub":   "last-administrator-test",
		"scope": builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier,
	}})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req.WithContext(ctx))
	return rr
}

// Two removals of the last two administrators at the same instant: one deletes A, the other
// disables B, two different writes on two different rows that share nothing but the manage
// permission row both take first. The deletion is parked at the end of its transaction, having
// counted B still there; the disable then waits for it on that row rather than counting A still
// there, and once the deletion commits it counts what is left, finds that disabling B leaves no
// one, and is refused 409 LAST_ADMINISTRATOR with nothing written. Without the shared row each
// would count the other and both would commit.
//
// MySQL, PostgreSQL and SQL Server only: SQLite has one connection, so two removals never overlap.
// An isolated database, because the count is of every holder of the real manage permission, which
// the shared database's other tests grant freely.
func TestLastAdministrator_TwoConcurrentRemovalsOfTheLastTwoEndWithOneRefused(t *testing.T) {
	skipWhereRemovalsCannotOverlap(t)
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	resource := &record.Resource{ResourceIdentifier: builtin.AuthServerResourceIdentifier, Description: "Authorization server (system-level)"}
	require.NoError(t, h.DB.CreateResource(ctx, nil, resource))
	manage := &record.Permission{PermissionIdentifier: builtin.ManagePermissionIdentifier, Description: "Manage the authorization server", ResourceId: resource.Id}
	require.NoError(t, h.DB.CreatePermission(ctx, nil, manage))

	a := newHolder(t, h.DB, true)
	grantToUser(t, h.DB, a.Id, manage.Id)
	b := newHolder(t, h.DB, true)
	admins := &record.Group{GroupIdentifier: "admins-" + fake.LetterN(6), Description: "Administrators"}
	require.NoError(t, h.DB.CreateGroup(ctx, nil, admins))
	grantToGroup(t, h.DB, admins.Id, manage.Id)
	joinGroup(t, h.DB, b.Id, admins.Id)

	auditLogger := &countingAuditLogger{}
	parked := newBarrier(t, "the deletion of administrator A")
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		aId := strconv.FormatInt(a.Id, 10)
		first <- serveAsManage(apihandlers.HandleUserDelete(&parkedAfterTheRemovalCounted{Database: h.DB, b: parked}, auditLogger),
			http.MethodDelete, "/api/v1/admin/users/"+aId, map[string]string{"id": aId}, nil)
	}()
	holder := parked.awaitParked(t)

	disable, err := json.Marshal(map[string]bool{"enabled": false})
	require.NoError(t, err)
	second := goBlocked(t, "the disabling of administrator B", holder, func(reached func()) *httptest.ResponseRecorder {
		bId := strconv.FormatInt(b.Id, 10)
		reached()
		return serveAsManage(apihandlers.HandleUserEnabledPut(h.DB, auditLogger),
			http.MethodPut, "/api/v1/admin/users/"+bId+"/enabled", map[string]string{"id": bId}, disable)
	})
	second.requireBlocked(t)
	second.requireStillWaiting(t)

	parked.releaseParked()
	firstRR := awaitWorker(t, "the deletion of administrator A", first)
	require.Equal(t, http.StatusOK, firstRR.Code, "the first removal leaves B: %s", firstRR.Body.String())

	secondRR := second.await(t)
	require.Equal(t, http.StatusConflict, secondRR.Code, "the second removal would leave no one: %s", secondRR.Body.String())
	var envelope struct {
		ErrorCode        string `json:"error_code"`
		ErrorDescription string `json:"error_description"`
	}
	require.NoError(t, json.Unmarshal(secondRR.Body.Bytes(), &envelope))
	assert.Equal(t, "LAST_ADMINISTRATOR", envelope.ErrorCode)

	gone, err := h.DB.GetUserById(ctx, nil, a.Id)
	require.NoError(t, err)
	assert.Nil(t, gone, "A's deletion committed")
	kept, err := h.DB.GetUserById(ctx, nil, b.Id)
	require.NoError(t, err)
	require.NotNil(t, kept)
	assert.True(t, kept.Enabled, "B's disable was rolled back")
	count, err := h.DB.CountEnabledUsersHoldingPermission(ctx, nil, manage.Id)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "one administrator remains")
}
