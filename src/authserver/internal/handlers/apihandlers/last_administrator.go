package apihandlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// The last-administrator guard. An administrator remains while at least one enabled user holds
// authserver:manage, directly or through a group; clients do not count, because the guard exists so
// that a person can still sign in to the admin console and repair things. Six writes can end that:
// revoking manage from a user or from a group, removing a user from a group that gives it (by either
// membership route), deleting such a group, disabling a user and deleting one. Each is refused, 409
// LAST_ADMINISTRATOR with nothing written and no audit record, only when it would bring the count to
// zero (#402 decisions 10 and 12).
//
// Each runs in a transaction whose first statement takes the manage permission's row, then decides
// under that lock, from rows read on the transaction, whether it removes a holder, and only then
// counts, writes and counts again. Two removals of the last two administrators touch no common row
// otherwise, and each would count the other still there: with the row taken first, the second
// waits, and every read it makes after the wait sees what the first committed. A decision taken
// from rows read before the lock could miss a grant of manage made between the read and the write
// (#402 decision 11).
//
// Counting after the write, on the transaction, counts what the write itself changed, whichever of
// the six it is, so the guard needs no model of each write's effect: a user who keeps manage through
// another group, or directly, is still counted. Counting before it is what tells "brings the count
// to zero" from "the count was zero already", which a database with no enabled holder left can
// reach by an edit outside this server; a write there removes no one and is not refused.

// lastAdministratorDatabase is what the guard reads: the lock, the count, and what the groups
// involved hold.
type lastAdministratorDatabase interface {
	AcquireManagePermissionRow(ctx context.Context, tx *sql.Tx) (int64, error)
	CountEnabledUsersHoldingPermission(ctx context.Context, tx *sql.Tx, permissionId int64) (int, error)
	GetGroupPermissionsByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.GroupPermission, error)
}

// userRemovalDatabase is what the guard reads to decide whether disabling or deleting a user removes
// a holder: beside the above, the user's direct grant and their groups.
type userRemovalDatabase interface {
	lastAdministratorDatabase
	GetUserGroupsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserGroup, error)
	GetUserPermissionByUserIdAndPermissionId(ctx context.Context, tx *sql.Tx, userId, permissionId int64) (*record.UserPermission, error)
}

// errLastAdministrator is what a guarded write's transaction returns when the write would leave no
// enabled user holding manage. The transaction is rolled back, and writeLastAdministrator answers it.
var errLastAdministrator = errors.New("the change would leave no enabled user holding authserver:manage")

// lastAdministratorDescription is the refusal's sentence, which the admin console shows as it is.
const lastAdministratorDescription = "This change would leave no enabled user holding authserver:manage. Grant it to another user first."

// writeLastAdministrator answers errLastAdministrator: 409, because RFC 9110 section 15.5.10 names a
// conflict "with the current state of the target resource" that "the user might be able to resolve
// ... and resubmit", and granting manage to another user first resolves it. Not audited: the caller
// holds manage and is authorized, and it is the state that forbids the change, as with the other
// 409s on this surface (#402 decision 12).
func writeLastAdministrator(w http.ResponseWriter) {
	writeJSONError(w, lastAdministratorDescription, "LAST_ADMINISTRATOR", http.StatusConflict)
}

// administratorRemoval is one guarded write's hold on the administrators, from the lock to the
// check after the write.
type administratorRemoval struct {
	database lastAdministratorDatabase
	tx       *sql.Tx
	// manageId is the manage permission's id, answered by the lock.
	manageId int64
	// removes is the decision: the write takes manage from someone, so the holders are counted.
	removes bool
	before  int
}

// lockAdministrators takes the manage permission's row on tx, which must be the transaction's first
// statement, and answers the hold the rest of the guard goes through.
func lockAdministrators(ctx context.Context, database lastAdministratorDatabase, tx *sql.Tx) (*administratorRemoval, error) {
	manageId, err := database.AcquireManagePermissionRow(ctx, tx)
	if err != nil {
		return nil, errs.Wrap(err, "unable to take the administrators' lock")
	}
	return &administratorRemoval{database: database, tx: tx, manageId: manageId}, nil
}

// decide records whether the write removes a holder of manage, decided by the caller from rows it
// read on the transaction after the lock, and, when it does, counts the holders before the write.
func (a *administratorRemoval) decide(ctx context.Context, removes bool) error {
	a.removes = removes
	if !removes {
		return nil
	}
	before, err := a.database.CountEnabledUsersHoldingPermission(ctx, a.tx, a.manageId)
	if err != nil {
		return errs.Wrap(err, "unable to count the administrators before the change")
	}
	a.before = before
	return nil
}

// leavesAnAdministrator counts the holders again after the write, on the transaction, and answers
// errLastAdministrator when the write brought the count to zero, which rolls it back.
func (a *administratorRemoval) leavesAnAdministrator(ctx context.Context) error {
	if !a.removes {
		return nil
	}
	after, err := a.database.CountEnabledUsersHoldingPermission(ctx, a.tx, a.manageId)
	if err != nil {
		return errs.Wrap(err, "unable to count the administrators after the change")
	}
	if a.before > 0 && after == 0 {
		return errLastAdministrator
	}
	return nil
}

// groupsGiveManage reports whether any of groupIds holds manage, read on the transaction.
func (a *administratorRemoval) groupsGiveManage(ctx context.Context, groupIds []int64) (bool, error) {
	if len(groupIds) == 0 {
		return false, nil
	}
	grants, err := a.database.GetGroupPermissionsByGroupIds(ctx, a.tx, groupIds)
	if err != nil {
		return false, errs.Wrap(err, "unable to read the groups' permissions for the last-administrator guard")
	}
	return slices.ContainsFunc(grants, func(grant record.GroupPermission) bool {
		return grant.PermissionId == a.manageId
	}), nil
}

// userHoldsManage reports whether the user holds manage, directly or through any of their groups,
// read on the transaction.
func (a *administratorRemoval) userHoldsManage(ctx context.Context, database userRemovalDatabase, userId int64) (bool, error) {
	direct, err := database.GetUserPermissionByUserIdAndPermissionId(ctx, a.tx, userId, a.manageId)
	if err != nil {
		return false, errs.Wrap(err, "unable to read the user's grant for the last-administrator guard")
	}
	if direct != nil {
		return true, nil
	}
	memberships, err := database.GetUserGroupsByUserId(ctx, a.tx, userId)
	if err != nil {
		return false, errs.Wrap(err, "unable to read the user's groups for the last-administrator guard")
	}
	groupIds := make([]int64, 0, len(memberships))
	for _, membership := range memberships {
		groupIds = append(groupIds, membership.GroupId)
	}
	return a.groupsGiveManage(ctx, groupIds)
}
