package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every write that can remove the last holder of authserver:manage takes the manage permission's
// row first, then decides and counts under it, so two removals of the last two administrators
// cannot each count two and both commit (#402 decision 11). What a mock cannot show is that the row
// is really held on each engine, that the acquisition finds that row and no other, and that a read
// taken after the wait sees what the holder committed; this file is that proof.

// managePermissionRow returns the authserver resource's manage permission in the shared database,
// creating the resource and the permission the first time: the tier's database is migrated but not
// seeded, and both identifiers are unique, so every test here shares the one row.
func managePermissionRow(t *testing.T) *record.Permission {
	t.Helper()
	ctx := context.Background()

	resource, err := database.GetResourceByResourceIdentifier(ctx, nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	if resource == nil {
		resource = &record.Resource{ResourceIdentifier: builtin.AuthServerResourceIdentifier, Description: "Authorization server (system-level)"}
		require.NoError(t, database.CreateResource(ctx, nil, resource))
	}

	permissions, err := database.GetPermissionsByResourceId(ctx, nil, resource.Id)
	require.NoError(t, err)
	for i := range permissions {
		if permissions[i].PermissionIdentifier == builtin.ManagePermissionIdentifier {
			return &permissions[i]
		}
	}

	manage := &record.Permission{PermissionIdentifier: builtin.ManagePermissionIdentifier, Description: "Manage the authorization server", ResourceId: resource.Id}
	require.NoError(t, database.CreatePermission(ctx, nil, manage))
	return manage
}

// skipWhereRemovalsCannotOverlap skips a forced interleaving on SQLite, whose pool is one connection:
// a deployment's two removals never overlap there, because the second waits for the connection, and
// a second handle on it fails at once with SQLITE_BUSY instead of waiting, a shape no deployment has.
func skipWhereRemovalsCannotOverlap(t *testing.T) {
	t.Helper()
	if dbType() == data.SQLite {
		t.Skip("SQLite's pool has one connection, so two administrator removals cannot overlap in a deployment")
	}
}

// AcquireManagePermissionRow's contract: it answers the manage permission's id, the one the guard
// counts holders of, writes nothing a reader can observe, and refuses rather than holding nothing.
func TestAcquireManagePermissionRow(t *testing.T) {
	ctx := context.Background()
	manage := managePermissionRow(t)

	// Two decoys an identifier match alone would also take: a permission named manage on another
	// resource, and another permission on the authserver resource.
	otherResource := createTestResource(t)
	decoyManage := &record.Permission{PermissionIdentifier: builtin.ManagePermissionIdentifier, Description: "Not the administrators'", ResourceId: otherResource.Id}
	require.NoError(t, database.CreatePermission(ctx, nil, decoyManage))
	authServer, err := database.GetResourceByResourceIdentifier(ctx, nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, authServer)
	decoySibling := createTestPermission(t, authServer)

	before, err := database.GetPermissionById(ctx, nil, manage.Id)
	require.NoError(t, err)
	require.NotNil(t, before)

	tx := beginTx(t)
	id, err := database.AcquireManagePermissionRow(ctx, tx)
	require.NoError(t, err)
	require.NoError(t, database.CommitTransaction(ctx, tx))

	assert.Equal(t, manage.Id, id, "the authserver resource's manage permission, not the decoys %d and %d", decoyManage.Id, decoySibling.Id)

	after, err := database.GetPermissionById(ctx, nil, manage.Id)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, before.PermissionIdentifier, after.PermissionIdentifier, "assigned to itself, so it does not move")
	assert.Equal(t, before.Description, after.Description)
	assert.Equal(t, before.ResourceId, after.ResourceId)
	assert.True(t, before.UpdatedAt.Time.Equal(after.UpdatedAt.Time),
		"taking the lock is not an edit of the permission: updated_at is %v and was %v", after.UpdatedAt.Time, before.UpdatedAt.Time)

	t.Run("without a transaction the statement would autocommit and release the row", func(t *testing.T) {
		_, err := database.AcquireManagePermissionRow(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("an already cancelled context is refused, not an acquisition of nothing", func(t *testing.T) {
		tx := beginTx(t)
		_, err := database.AcquireManagePermissionRow(cancelled(), tx)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// A database with no manage permission has no row to hold, and a lock that holds nothing would let
// the guard behind it count without serializing anything. It is refused instead, on a database that
// has no authserver resource at all and on one whose authserver resource has no manage permission.
func TestAcquireManagePermissionRow_RefusesWhereThereIsNoManagePermission(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	tx, err := h.DB.BeginTransaction(ctx)
	require.NoError(t, err)
	_, err = h.DB.AcquireManagePermissionRow(ctx, tx)
	assert.Error(t, err, "no authserver resource")
	require.NoError(t, h.DB.RollbackTransaction(ctx, tx))

	resource := &record.Resource{ResourceIdentifier: builtin.AuthServerResourceIdentifier, Description: "Authorization server (system-level)"}
	require.NoError(t, h.DB.CreateResource(ctx, nil, resource))
	require.NoError(t, h.DB.CreatePermission(ctx, nil, &record.Permission{PermissionIdentifier: builtin.AdminReadPermissionIdentifier, Description: "Read", ResourceId: resource.Id}))
	other := &record.Resource{ResourceIdentifier: "lock-decoy", Description: "Another resource"}
	require.NoError(t, h.DB.CreateResource(ctx, nil, other))
	require.NoError(t, h.DB.CreatePermission(ctx, nil, &record.Permission{PermissionIdentifier: builtin.ManagePermissionIdentifier, Description: "Not the administrators'", ResourceId: other.Id}))

	tx, err = h.DB.BeginTransaction(ctx)
	require.NoError(t, err)
	_, err = h.DB.AcquireManagePermissionRow(ctx, tx)
	assert.Error(t, err, "an authserver resource without manage, beside another resource's manage")
	require.NoError(t, h.DB.RollbackTransaction(ctx, tx))
}

// The acquisition holds the row until its transaction ends: a second acquisition on another
// connection waits for it. That is the whole of what serializes two removals of the last two
// administrators. The statement assigns a column to itself, and whether an engine takes a row lock
// for a write that changes nothing is the engine's to say, so this runs on every engine that can
// overlap.
func TestAcquireManagePermissionRow_HoldsTheRowUntilTheTransactionEnds(t *testing.T) {
	skipWhereRemovalsCannotOverlap(t)
	other := secondDatabase(t)
	manage := managePermissionRow(t)

	holder := beginTx(t)
	_, err := database.AcquireManagePermissionRow(context.Background(), holder)
	require.NoError(t, err)

	second := goBlocked(t, "a second acquisition", holder, func(reached func()) error {
		tx, err := other.BeginTransaction(context.Background())
		if err != nil {
			reached()
			return err
		}
		defer func() { _ = other.RollbackTransaction(context.Background(), tx) }()
		reached()
		id, err := other.AcquireManagePermissionRow(context.Background(), tx)
		if err != nil {
			return err
		}
		if id != manage.Id {
			t.Errorf("the second acquisition answered permission %d, not manage's %d", id, manage.Id)
		}
		return nil
	})
	second.requireBlocked(t)
	second.requireStillWaiting(t)

	require.NoError(t, database.CommitTransaction(context.Background(), holder))
	require.NoError(t, second.await(t), "the second acquisition goes through once the holder commits")
}

// And what the waiting removal then sees: a read taken on its transaction after the acquisition
// returns what the holder committed while it waited. This is why a guarded write decides under the
// lock and not from rows read before it: a grant of manage committed by the holder is counted.
func TestAcquireManagePermissionRow_AReadAfterTheWaitSeesWhatTheHolderCommitted(t *testing.T) {
	skipWhereRemovalsCannotOverlap(t)
	other := secondDatabase(t)
	manage := managePermissionRow(t)
	user := createTestUserOn(t, database)

	holder := beginTx(t)
	_, err := database.AcquireManagePermissionRow(context.Background(), holder)
	require.NoError(t, err)
	require.NoError(t, database.CreateUserPermission(context.Background(), holder,
		&record.UserPermission{UserId: user.Id, PermissionId: manage.Id}), "the holder grants manage under the lock")

	type seen struct {
		holdsManage bool
		err         error
	}
	waiter := goBlocked(t, "a removal deciding under the lock", holder, func(reached func()) seen {
		tx, err := other.BeginTransaction(context.Background())
		if err != nil {
			reached()
			return seen{err: err}
		}
		defer func() { _ = other.RollbackTransaction(context.Background(), tx) }()
		reached()
		if _, err = other.AcquireManagePermissionRow(context.Background(), tx); err != nil {
			return seen{err: err}
		}
		granted, err := other.GetUserPermissionByUserIdAndPermissionId(context.Background(), tx, user.Id, manage.Id)
		return seen{holdsManage: granted != nil, err: err}
	})
	waiter.requireBlocked(t)
	waiter.requireStillWaiting(t)

	require.NoError(t, database.CommitTransaction(context.Background(), holder))
	result := waiter.await(t)
	require.NoError(t, result.err)
	assert.True(t, result.holdsManage, "the grant the holder committed during the wait is visible to the read after it")
}
