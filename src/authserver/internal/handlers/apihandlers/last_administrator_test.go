package apihandlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The last-administrator guard on the strict mock: each of the writes that can remove a holder of
// authserver:manage takes the administrators' lock as its transaction's first statement, decides
// from rows read on that transaction, counts the holders before and after its write, and when the
// write would bring the count to zero hands errLastAdministrator back to the helper, which rolls it
// back, and answers 409 LAST_ADMINISTRATOR with nothing audited (#402 decisions 10 to 12). The
// integration tier shows the same against a real store; what only a mock shows is the order inside
// the transaction and that the refusal is the body's own error.

// lastAdministratorRemoval is one guarded write, served as an authserver:manage caller, against an
// administrator it would remove.
type lastAdministratorRemoval struct {
	name string
	// tx is the transaction the stub hands the write's body.
	tx *sql.Tx
	// expectBeforeTheTransaction registers what the write reads before it opens its transaction.
	expectBeforeTheTransaction func(database *datamocks.Database)
	// expectDecision registers the reads, on tx after the lock, the guard decides from: they find
	// that the write takes manage from someone.
	expectDecision func(database *datamocks.Database)
	// expectWrite registers the write itself, on tx, which succeeds and is then rolled back.
	expectWrite func(database *datamocks.Database)
	serve       func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder
}

// adminHoldingManageId is the user the user-side cases would disable or delete, who holds manage
// directly.
const adminHoldingManageId = int64(42)

func expectUserHoldsManageDirectly(tx *sql.Tx) func(database *datamocks.Database) {
	return func(database *datamocks.Database) {
		database.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, tx, adminHoldingManageId, permManage).
			Return(&record.UserPermission{Id: 77, UserId: adminHoldingManageId, PermissionId: permManage}, nil).Once()
	}
}

var lastAdministratorRemovals = []lastAdministratorRemoval{
	{
		name: "PUT /users/{id}/permissions revoking manage",
		tx:   grantsTx,
		expectBeforeTheTransaction: func(database *datamocks.Database) {
			grantSaves[0].expectOwner(database)
			expectAuthServerPermissions(database)
		},
		expectDecision: func(database *datamocks.Database) {
			database.On("GetUserPermissionsByUserId", mock.Anything, grantsTx, grantOwnerId).
				Return([]record.UserPermission{{Id: 21, UserId: grantOwnerId, PermissionId: permManage}}, nil).Once()
		},
		expectWrite: func(database *datamocks.Database) {
			database.On("DeleteUserPermission", mock.Anything, grantsTx, int64(21)).Return(nil).Once()
		},
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			return grantSaves[0].serve(database, auditLogger, `{"permissionIds":[],"expectedPermissionIds":[11]}`)
		},
	},
	{
		name: "PUT /groups/{id}/permissions revoking manage",
		tx:   grantsTx,
		expectBeforeTheTransaction: func(database *datamocks.Database) {
			grantSaves[1].expectOwner(database)
			expectAuthServerPermissions(database)
		},
		expectDecision: func(database *datamocks.Database) {
			database.On("GetGroupPermissionsByGroupId", mock.Anything, grantsTx, grantOwnerId).
				Return([]record.GroupPermission{{Id: 21, GroupId: grantOwnerId, PermissionId: permManage}}, nil).Once()
		},
		expectWrite: func(database *datamocks.Database) {
			database.On("DeleteGroupPermission", mock.Anything, grantsTx, int64(21)).Return(nil).Once()
		},
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			return grantSaves[1].serve(database, auditLogger, `{"permissionIds":[],"expectedPermissionIds":[11]}`)
		},
	},
	{
		name: "PUT /users/{id}/groups leaving the group that gives manage",
		tx:   userGroupsTx,
		expectBeforeTheTransaction: func(database *datamocks.Database) {
			membershipChanges[1].expectReads(database, administrativeGroupId, false)
		},
		expectDecision: func(database *datamocks.Database) {
			expectStoredMemberships(database, membershipRow{id: ceilingMembershipRowId, groupId: administrativeGroupId})
			expectGroupPermissionsOn(database, userGroupsTx, administrativeGroupId)
		},
		expectWrite: func(database *datamocks.Database) {
			database.On("DeleteUserGroup", mock.Anything, userGroupsTx, ceilingMembershipRowId).Return(nil).Once()
		},
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			return membershipChanges[1].serve(database, auditLogger, administrativeGroupId, "authserver:manage")
		},
	},
	{
		name: "DELETE /groups/{id}/members/{userId} of the group that gives manage",
		tx:   guardTx,
		expectBeforeTheTransaction: func(database *datamocks.Database) {
			membershipChanges[3].expectReads(database, administrativeGroupId, false)
			membershipChanges[3].expectAlertReads(database, administrativeGroupId)
		},
		expectDecision: func(database *datamocks.Database) {
			expectGroupPermissionsOn(database, guardTx, administrativeGroupId)
		},
		expectWrite: func(database *datamocks.Database) {
			database.On("DeleteUserGroup", mock.Anything, guardTx, ceilingMembershipRowId).Return(nil).Once()
		},
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			return membershipChanges[3].serve(database, auditLogger, administrativeGroupId, "authserver:manage")
		},
	},
	{
		name: "DELETE /groups/{id} of the group that gives manage",
		tx:   guardTx,
		expectBeforeTheTransaction: func(database *datamocks.Database) {
			membershipChanges[4].expectReads(database, administrativeGroupId, false)
		},
		expectDecision: func(database *datamocks.Database) {
			expectGroupPermissionsOn(database, guardTx, administrativeGroupId)
		},
		expectWrite: func(database *datamocks.Database) {
			database.On("DeleteGroup", mock.Anything, guardTx, administrativeGroupId).Return(nil).Once()
		},
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			return membershipChanges[4].serve(database, auditLogger, administrativeGroupId, "authserver:manage")
		},
	},
	{
		name: "PUT /users/{id}/enabled disabling",
		tx:   apiRevokeTx,
		expectBeforeTheTransaction: func(database *datamocks.Database) {
			database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), adminHoldingManageId).
				Return(&record.User{Id: adminHoldingManageId, Enabled: true}, nil).Once()
		},
		expectDecision: expectUserHoldsManageDirectly(apiRevokeTx),
		expectWrite: func(database *datamocks.Database) {
			database.On("TrySetUserEnabled", mock.Anything, apiRevokeTx, adminHoldingManageId, true, false).Return(true, nil).Once()
		},
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			r := membershipRequest(http.MethodPut, "/api/v1/admin/users/42/enabled", `{"enabled":false}`, "authserver:manage", map[string]string{"id": "42"})
			rr := httptest.NewRecorder()
			HandleUserEnabledPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
	},
	{
		name: "DELETE /users/{id}",
		tx:   guardTx,
		expectBeforeTheTransaction: func(database *datamocks.Database) {
			database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), adminHoldingManageId).
				Return(&record.User{Id: adminHoldingManageId, Enabled: true}, nil).Once()
		},
		expectDecision: expectUserHoldsManageDirectly(guardTx),
		expectWrite: func(database *datamocks.Database) {
			database.On("DeleteUser", mock.Anything, guardTx, adminHoldingManageId).Return(nil).Once()
		},
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			r := membershipRequest(http.MethodDelete, "/api/v1/admin/users/42", "", "authserver:manage", map[string]string{"id": "42"})
			rr := httptest.NewRecorder()
			HandleUserDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
	},
}

// firstCallOn is the method of the first call the mock recorded on tx.
func firstCallOn(database *datamocks.Database, tx *sql.Tx) string {
	for _, call := range database.Calls {
		if len(call.Arguments) > 1 && call.Arguments.Get(1) == tx {
			return call.Method
		}
	}
	return ""
}

// The last holder: one enabled holder before the write and none after it. The write is made, on
// the transaction, and the body hands the helper errLastAdministrator, which is when the real one
// rolls it back; the answer is 409 with decision 12's sentence, and nothing is audited.
func TestLastAdministrator_TheLastHolderIsRefusedAndTheWriteRolledBack(t *testing.T) {
	for _, removal := range lastAdministratorRemovals {
		t.Run(removal.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			removal.expectBeforeTheTransaction(database)
			stub := datamocks.ExpectRunInTransaction(database, removal.tx)
			expectAdministratorsLock(database, removal.tx)
			removal.expectDecision(database)
			expectHoldersCounted(database, removal.tx, 1, 0)
			removal.expectWrite(database)

			rr := removal.serve(database, auditLogger)

			require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "LAST_ADMINISTRATOR", code)
			assert.Equal(t, "This change would leave no enabled user holding authserver:manage. Grant it to another user first.", description)
			require.ErrorIs(t, stub.BodyErr, errLastAdministrator, "the body refuses, so the helper rolls the write back")
			assert.Equal(t, "AcquireManagePermissionRow", firstCallOn(database, removal.tx), "the lock is the transaction's first statement")
			database.AssertExpectations(t)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// Counted before the write as well as after it, so a store where no enabled user held manage
// already, which an edit outside this server can leave, does not refuse a write that removes no one
// from the count: it was zero before and the write did not bring it there.
func TestLastAdministrator_AWriteWhereNoHolderWasLeftIsNotRefused(t *testing.T) {
	t.Run("DELETE /users/{id}", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		removal := lastAdministratorRemovals[6]

		removal.expectBeforeTheTransaction(database)
		stub := datamocks.ExpectRunInTransaction(database, removal.tx)
		expectAdministratorsLock(database, removal.tx)
		removal.expectDecision(database)
		expectHoldersCounted(database, removal.tx, 0, 0)
		removal.expectWrite(database)
		auditLogger.On("Log", mock.Anything, audit.EventDeletedUser, mock.Anything).Return().Once()

		rr := removal.serve(database, auditLogger)

		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.NoError(t, stub.BodyErr)
		database.AssertExpectations(t)
	})
}

// One of two: a holder remains after the write, which commits.
func TestLastAdministrator_OneOfTwoHoldersIsRemoved(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	removal := lastAdministratorRemovals[4]

	removal.expectBeforeTheTransaction(database)
	stub := datamocks.ExpectRunInTransaction(database, removal.tx)
	expectAdministratorsLock(database, removal.tx)
	removal.expectDecision(database)
	expectHoldersCounted(database, removal.tx, 2, 1)
	removal.expectWrite(database)
	auditLogger.On("Log", mock.Anything, audit.EventDeletedGroup, mock.Anything).Return().Once()

	rr := removal.serve(database, auditLogger)

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, stub.BodyErr)
	database.AssertExpectations(t)
}
