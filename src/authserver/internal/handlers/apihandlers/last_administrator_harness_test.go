package apihandlers

import (
	"database/sql"
	"slices"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/mock"
)

// guardTx is the transaction the stub hands the body of a write that ran outside any transaction
// before the last-administrator guard: a group deletion, a group member's removal, a user's
// deletion. Not nil, so a write expected on it cannot be matched by one made outside it.
var guardTx = &sql.Tx{}

// expectAdministratorsLock registers the acquisition every write the last-administrator guard
// covers makes as the first statement of its transaction, answering manage's id (#402 decision 11).
func expectAdministratorsLock(database *datamocks.Database, tx *sql.Tx) {
	database.On("AcquireManagePermissionRow", mock.Anything, tx).Return(permManage, nil).Once()
}

// expectHoldersCounted registers the guard's two counts of the enabled users holding manage, before
// the write and after it.
func expectHoldersCounted(database *datamocks.Database, tx *sql.Tx, before, after int) {
	database.On("CountEnabledUsersHoldingPermission", mock.Anything, tx, permManage).Return(before, nil).Once()
	database.On("CountEnabledUsersHoldingPermission", mock.Anything, tx, permManage).Return(after, nil).Once()
}

// expectGuardOfGroup registers what the guard reads, on tx, to decide whether leaving or deleting
// group removes a holder of manage, and, when the group gives manage, the two counts of a removal
// that leaves another administrator.
func expectGuardOfGroup(database *datamocks.Database, tx *sql.Tx, group int64) {
	expectGroupPermissionsOn(database, tx, group)
	if slices.Contains(groupPermissionRows[group], permManage) {
		expectHoldersCounted(database, tx, 2, 1)
	}
}

// expectGuardOfOrdinaryUser registers the administrators' lock on tx and the guard's reads of a user
// who holds manage neither directly nor through a group, so disabling or deleting them counts
// nothing.
func expectGuardOfOrdinaryUser(database *datamocks.Database, tx *sql.Tx, userId int64) {
	expectAdministratorsLock(database, tx)
	database.On("GetUserPermissionByUserIdAndPermissionId", mock.Anything, tx, userId, permManage).
		Return((*record.UserPermission)(nil), nil).Once()
	database.On("GetUserGroupsByUserId", mock.Anything, tx, userId).Return([]record.UserGroup{}, nil).Once()
}
