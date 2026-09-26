package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A cancelled context against a real engine, seam 2 of #386, for the last batch of Database
// methods: groups, group attributes, group permissions, key pairs, settings, audit logs, the
// pre-registrations and the email-case pre-flight.
//
// Why this is a second file rather than more cases in cancellation_test.go: that file's preamble
// states the tier's argument once and its three opening cases are about BeginTransaction and
// RunInTransaction themselves, which no batch owns. Everything below is one batch's methods, and
// keeping it separate is what lets a reader see which methods a batch claimed to have covered.
//
// cancelled() is declared in cancellation_test.go and is the same already-over context: the one
// cancellation every engine and every driver answers identically, because database/sql refuses
// the call before the driver is reached at all, confirmed against all four engines (#386).

// TestGetGroupById_RefusesAnAlreadyCancelledContext is the plain read through getGroupCommon,
// the helper every group lookup shares.
func TestGetGroupById_RefusesAnAlreadyCancelledContext(t *testing.T) {
	group := createTestGroup(t)

	got, err := database.GetGroupById(cancelled(), nil, group.Id)

	require.Error(t, err, "a read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled, "and the reason must be matchable, not a sentence")
	assert.Nil(t, got, "no row is returned alongside the refusal")
}

// TestCreateGroup_RefusesAnAlreadyCancelledContextAndWritesNothing covers the insert, which on
// PostgreSQL and SQL Server goes through insertReturningId's QuerySql and on SQLite and MySQL
// through ExecSql's LastInsertId. The second half is the one that matters: a refusal that still
// wrote the row would be worse than no refusal at all, because the caller is gone and nobody is
// left to undo it.
func TestCreateGroup_RefusesAnAlreadyCancelledContextAndWritesNothing(t *testing.T) {
	identifier := "TestGroupCancelled_" + fake.LetterN(6)
	group := &models.Group{GroupIdentifier: identifier, Description: "never written"}

	err := database.CreateGroup(cancelled(), nil, group)

	require.Error(t, err, "an insert must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, group.Id, "no id came back, because no row was inserted")

	found, lookupErr := database.GetGroupByGroupIdentifier(context.Background(), nil, identifier)
	require.NoError(t, lookupErr)
	assert.Nil(t, found, "the refused insert left no row behind")
}

// TestGroupLoadPermissions_RefusesAnAlreadyCancelledContext is one of stage 1's five
// nil-transaction sites, whose two hops -- GetGroupPermissionsByGroupIds and then
// GetPermissionsByIds -- now both take the caller's context. Against a context that is already
// over the first hop is the one that refuses; the second has a case of its own in
// cancellation_test.go, for the reason recorded there.
func TestGroupLoadPermissions_RefusesAnAlreadyCancelledContext(t *testing.T) {
	resource := createTestResource(t)
	permission := createTestPermission(t, resource)
	group := createTestGroup(t)
	createTestGroupPermission(t, group.Id, permission.Id)

	err := database.GroupLoadPermissions(cancelled(), nil, group)

	require.Error(t, err, "a loader must not read on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, group.Permissions, "nothing is attached to the model alongside the refusal")
}

// TestGetGroupMembersPaginated_RefusesAnAlreadyCancelledContext is the two-statement shape: a
// page query and a count query, each its own QuerySql. It is what the admin console's group
// members page reads, and the zero total is the assertion that says the count statement did not
// run either.
func TestGetGroupMembersPaginated_RefusesAnAlreadyCancelledContext(t *testing.T) {
	group := createTestGroup(t)
	user := createTestUser(t)
	createTestUserGroupWithUserAndGroup(t, user.Id, group.Id)

	members, total, err := database.GetGroupMembersPaginated(cancelled(), nil, group.Id, 1, 10)

	require.Error(t, err, "a paged read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, members)
	assert.Zero(t, total, "the count statement did not run either")
}

// TestGetGroupAttributesByGroupId_RefusesAnAlreadyCancelledContext is group_attribute.go's read,
// the other half of what the userinfo endpoint and the token issuer load onto a user's groups.
func TestGetGroupAttributesByGroupId_RefusesAnAlreadyCancelledContext(t *testing.T) {
	group := createTestGroup(t)
	createTestGroupAttribute(t, group.Id)

	got, err := database.GetGroupAttributesByGroupId(cancelled(), nil, group.Id)

	require.Error(t, err, "a read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, got, "no rows are returned alongside the refusal")
}

// TestUpdateKeyPairState_RefusesAnAlreadyCancelledContext is this batch's compare-and-set, and
// one of the two places where the refusal HAS to be an error rather than a value. The rotator
// reads the bool as "somebody else made this transition", so a method that swallowed a
// cancellation into a false would tell a rotation it had lost a race it never entered, and #251
// is what happens when two rotations disagree about who moved which key.
func TestUpdateKeyPairState_RefusesAnAlreadyCancelledContext(t *testing.T) {
	keyPair := createKeyPairInState(t, models.KeyStateNext.String())

	moved, err := database.UpdateKeyPairState(cancelled(), nil, keyPair.Id,
		models.KeyStateNext.String(), models.KeyStateCurrent.String())

	require.Error(t, err, "the refusal must reach the caller as an error, not as a false")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, moved)

	after, readErr := database.GetKeyPairById(context.Background(), nil, keyPair.Id)
	require.NoError(t, readErr)
	require.NotNil(t, after)
	assert.Equal(t, models.KeyStateNext.String(), after.State, "the refused update moved nothing")
}

// TestTryClaimCleanupRun_RefusesAnAlreadyCancelledContext is the other of the two, and the
// worker's own. A false means "another instance holds this interval's claim", so a swallowed
// cancellation would be indistinguishable from a lost race and the worker would go quietly back
// to sleep having been told nothing.
func TestTryClaimCleanupRun_RefusesAnAlreadyCancelledContext(t *testing.T) {
	now := time.Now().UTC()

	claimed, err := database.TryClaimCleanupRun(cancelled(), nil, now, now.Add(-time.Hour))

	require.Error(t, err, "the refusal must reach the caller as an error, not as a false")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, claimed)
}

// TestScanEmailCase_RefusesAnAlreadyCancelledContext is the one method in the whole interface
// whose context is its ONLY parameter: the startup pre-flight reads the users table outside any
// transaction. Before this batch it had no parameter at all, so the case is also what says the
// signature change reached a method no tx argument could have carried it to.
func TestScanEmailCase_RefusesAnAlreadyCancelledContext(t *testing.T) {
	createTestUser(t)

	rows, err := database.ScanEmailCase(cancelled())

	require.Error(t, err, "the pre-flight must not read on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, rows, "no rows are returned alongside the refusal")
}

// TestDeleteOldAuditLogs_RefusesAnAlreadyCancelledContext is the method every one of the four
// engines overrides, because the delete-with-a-limit grammar differs on each. It is therefore
// the case that says the context reached the ADAPTER's body rather than a promoted one, on
// whichever engine this tier is running.
func TestDeleteOldAuditLogs_RefusesAnAlreadyCancelledContext(t *testing.T) {
	require.NoError(t, database.CreateAuditLog(context.Background(), nil,
		&models.AuditLog{AuditEvent: "cancellation_probe", Details: `{}`}))

	deleted, err := database.DeleteOldAuditLogs(cancelled(), nil, time.Now().UTC().Add(time.Hour), 10)

	require.Error(t, err, "a delete must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, deleted, "nothing was deleted alongside the refusal")
}

// TestGetAuditLogsPaginated_RefusesAnAlreadyCancelledContext is the other half of that: promoted
// from commondb on three engines and overridden on SQL Server, where the byte-exact request_id
// predicate and OFFSET/FETCH pagination need their own statement. Both bodies are two QuerySql
// calls, and whichever engine the tier is running is the one covered here.
func TestGetAuditLogsPaginated_RefusesAnAlreadyCancelledContext(t *testing.T) {
	require.NoError(t, database.CreateAuditLog(context.Background(), nil,
		&models.AuditLog{AuditEvent: "cancellation_probe", Details: `{}`}))

	logs, total, err := database.GetAuditLogsPaginated(cancelled(), nil, 1, 10, "", "")

	require.Error(t, err, "a paged read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, logs)
	assert.Zero(t, total, "the count statement did not run either")
}

// TestGetPreRegistrationByEmail_RefusesAnAlreadyCancelledContext is the self-registration read,
// the one pre_registration.go method the account handlers reach on an unauthenticated request.
func TestGetPreRegistrationByEmail_RefusesAnAlreadyCancelledContext(t *testing.T) {
	preRegistration := createTestPreRegistration(t)

	got, err := database.GetPreRegistrationByEmail(cancelled(), nil, preRegistration.Email)

	require.Error(t, err, "a read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, got, "no row is returned alongside the refusal")
}

// TestRotateEncryptionKeyIfNeeded_RefusesAnAlreadyCancelledContext reaches reencrypt.go, the one
// file in this batch whose exported method is not a query of its own: it reads the signing keys
// to find its canary and only then opens a transaction. The refusal therefore comes from the
// read, before any re-keying starts, which is the fail-closed direction -- a rotation that began
// and was then abandoned would leave secrets under a key the running process does not hold.
//
// Two DISTINCT 32-byte keys, because the method answers false and no error when the previous key
// is absent or equal to the current one, and would then never reach the database at all.
func TestRotateEncryptionKeyIfNeeded_RefusesAnAlreadyCancelledContext(t *testing.T) {
	current := make([]byte, 32)
	previous := make([]byte, 32)
	previous[0] = 1

	rotated, err := database.RotateEncryptionKeyIfNeeded(cancelled(), current, previous)

	require.Error(t, err, "the canary read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, rotated, "nothing was re-keyed alongside the refusal")
}

// TestIsEmpty_RefusesAnAlreadyCancelledContext is main's first question of a new database, asked
// through GetSettingsById. It is worth its own case because the answer is a bool and the caller
// acts on it: a swallowed cancellation would read as "this database is empty" and send a running
// process into the bootstrap seeder.
func TestIsEmpty_RefusesAnAlreadyCancelledContext(t *testing.T) {
	empty, err := database.IsEmpty(cancelled())

	require.Error(t, err, "the refusal must reach the caller as an error, not as a true")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, empty, "and the bool alongside the refusal must not read as an empty database")
}

// TestSchemadumpTables_RefusesAnAlreadyCancelledContext is the generator's half. schemadump is
// not on a request path -- it is reached from the schemadump command and from this tier -- but
// #386's guard refuses a bare Query anywhere under authserver/internal/data, and a parameter
// added to satisfy a guard and then not used is exactly the shape that guard cannot see. This
// is what says the seven calls it threads a context through actually issue with it.
func TestSchemadumpTables_RefusesAnAlreadyCancelledContext(t *testing.T) {
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Up(context.Background()), "migrate to head")

	names, err := schemadump.Tables(cancelled(), h.SQL, dumpDialect(t))

	require.Error(t, err, "a catalog read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled, "and the reason must be matchable, not a sentence")
	assert.Empty(t, names, "no table names are returned alongside the refusal")
}
