package main

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/builtin"
)

// recoverAuditRecorder is runRecover's audit logger in these tests: the events and payloads are
// the assertion, so they are captured rather than written to the database the way the running
// command does through audit.NewLogger.
type recoverAuditRecorder struct {
	events  []string
	details []map[string]interface{}
}

func (r *recoverAuditRecorder) Log(_ context.Context, auditEvent string, details map[string]interface{}) {
	r.events = append(r.events, auditEvent)
	r.details = append(r.details, details)
}

// newRecoverDatabase gives each test its own SQLite file database at the head of the real
// migration set, holding the rows recovery touches: the settings row, the auth server resource
// with its manage permission, and one user. Those are the parts of the seed the command reads,
// written through the data tier the same way the seed writes them, so the command is observed
// against what it will run against in production (#498).
func newRecoverDatabase(t *testing.T) (data.Database, *record.Permission) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "recover_test.db")
	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	require.NoError(t, m.Up(context.Background()))

	ctx := context.Background()
	settings := &record.Settings{
		AppName:                "recover test",
		Issuer:                 "https://localhost:8080",
		PasswordPolicy:         record.PasswordPolicyLow,
		AESEncryptionKeyLegacy: []byte{},
	}
	resource := &record.Resource{
		ResourceIdentifier: builtin.AuthServerResourceIdentifier,
		Description:        "The authorization server",
	}
	manage := &record.Permission{
		PermissionIdentifier: builtin.ManagePermissionIdentifier,
		Description:          "Manage the authorization server via the admin console",
	}
	user := &record.User{
		Subject:      "recover-subject",
		Username:     "recover",
		Email:        "admin@example.com",
		Enabled:      true,
		PasswordHash: "not-a-bcrypt-hash",
	}
	require.NoError(t, db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := db.CreateInitialSettings(ctx, tx, settings); err != nil {
			return err
		}
		if err := db.CreateResource(ctx, tx, resource); err != nil {
			return err
		}
		manage.ResourceId = resource.Id
		if err := db.CreatePermission(ctx, tx, manage); err != nil {
			return err
		}
		return db.CreateUser(ctx, tx, user)
	}))
	return db, manage
}

// runRecoverOn runs one invocation against the database and answers the exit code with what the
// command printed on each stream.
func runRecoverOn(t *testing.T, db data.Database, audit *recoverAuditRecorder, inv recoverInvocation) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runRecover(context.Background(), db, audit, inv, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestParseRecoverArgs(t *testing.T) {
	t.Run("reads the command's flags", func(t *testing.T) {
		inv, err := parseRecoverArgs([]string{
			"--email", "admin@example.com", "--grant-manage", "--remove-otp",
			"--password=alongenoughpassword",
		}, config.DatabaseConfig{Type: "sqlite"})
		require.NoError(t, err)
		assert.Equal(t, "admin@example.com", inv.email)
		assert.Equal(t, "alongenoughpassword", inv.password)
		assert.True(t, inv.grantManage)
		assert.True(t, inv.removeOTP)
		assert.False(t, inv.help)
		assert.Equal(t, "sqlite", inv.database.Type)
	})

	t.Run("an undefined flag names what recover accepts", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"--email", "a@example.com", "--grant"},
			config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--grant is not a flag recover accepts")
		assert.Contains(t, err.Error(), "--email, --password, --grant-manage and --remove-otp")
	})

	t.Run("a positional argument is refused", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"admin@example.com"}, config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a flag recover takes as a positional argument")
	})

	t.Run("the email is required", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"--remove-otp"}, config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--email is required")
	})
}

func TestRecover_RefusesAnUnknownUser(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}

	code, _, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "nobody@example.com", removeOTP: true,
	})

	assert.Equal(t, migrateExitError, code)
	assert.Contains(t, stderr, "refusing to recover: no user holds the address nobody@example.com")
	assert.Empty(t, recorder.events, "a refusal writes no audit event")
}

func TestRecover_RefusesADisabledUser(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}
	disabled := &record.User{
		Subject:      "disabled-subject",
		Username:     "disabled",
		Email:        "disabled@example.com",
		Enabled:      false,
		PasswordHash: "not-a-bcrypt-hash",
	}
	require.NoError(t, db.CreateUser(context.Background(), nil, disabled))

	code, _, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "disabled@example.com", removeOTP: true,
	})

	assert.Equal(t, migrateExitError, code)
	assert.Contains(t, stderr, "is disabled; enable the user first")
	assert.Empty(t, recorder.events, "a refusal writes no audit event")
}

func TestRecover_NeedsAnAction(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}

	code, _, stderr := runRecoverOn(t, db, recorder, recoverInvocation{email: "admin@example.com"})

	assert.Equal(t, migrateExitUsage, code)
	assert.Contains(t, stderr, "nothing to do")
	assert.Contains(t, stderr, "--grant-manage")
	assert.Empty(t, recorder.events, "a usage refusal writes no audit event")
}

func TestRecover_HoldsThePasswordToTheStoredPolicy(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}

	code, _, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "admin@example.com", password: "short",
	})

	assert.Equal(t, migrateExitError, code)
	assert.Contains(t, stderr, "the password is refused by the stored password policy")
	assert.Empty(t, recorder.events, "a refusal writes no audit event")
}

func TestRecover_AppliesEachAskedActionInOneRevocation(t *testing.T) {
	db, manage := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}
	ctx := context.Background()

	// The user holds an enrolled authenticator, the state --remove-otp clears.
	enrolled, err := db.GetUserByEmail(ctx, nil, "admin@example.com")
	require.NoError(t, err)
	enrolled.OTPEnabled = true
	enrolled.OTPSecretEncrypted = []byte("the-encrypted-seed")
	require.NoError(t, db.UpdateUser(ctx, nil, enrolled))

	code, stdout, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email:       "admin@example.com",
		password:    "alongenoughpassword",
		grantManage: true,
		removeOTP:   true,
	})

	assert.Equal(t, migrateExitOK, code, stderr)
	assert.Contains(t, stdout, "recovered admin@example.com")
	assert.Contains(t, stdout, "password set")
	assert.Contains(t, stdout, "otp authenticator removed")
	assert.Contains(t, stdout, "granted")
	assert.Contains(t, stdout, "authentication generation")

	after, err := db.GetUserByEmail(ctx, nil, "admin@example.com")
	require.NoError(t, err)

	// The password was set: the new one verifies and the stored one no longer does.
	assert.True(t, passwordhash.Verify(after.PasswordHash, "alongenoughpassword"),
		"the new password verifies against the stored hash")
	assert.False(t, passwordhash.Verify(after.PasswordHash, "not-a-bcrypt-hash"),
		"the password the user had before the recovery no longer verifies")

	// The authenticator is gone.
	assert.False(t, after.OTPEnabled, "the OTP authenticator was removed")

	// The permission is granted.
	grants, err := db.GetUserPermissionsByUserId(ctx, nil, after.Id)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, manage.Id, grants[0].PermissionId)

	// The audit trail names the command as the actor.
	assert.Equal(t, []string{
		audit.EventUpdatedUserAuthentication,
		audit.EventAddedUserPermission,
		audit.EventRevokedUserAuthState,
	}, recorder.events)
	revoked := recorder.details[len(recorder.details)-1]
	assert.Equal(t, revocation.ReasonRecoveryCommand, revoked["reason"])
	assert.Equal(t, recoverActor, revoked["logged_in_user"])
	assert.Equal(t, after.Id, revoked["user_id"])
}

func TestRecover_ReportsManageAlreadyHeldAndGrantsNothing(t *testing.T) {
	db, manage := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}
	ctx := context.Background()

	inv := recoverInvocation{email: "admin@example.com", grantManage: true}
	code, _, stderr := runRecoverOn(t, db, recorder, inv)
	require.Equal(t, migrateExitOK, code, stderr)

	recorder.events = nil
	code, stdout, stderr := runRecoverOn(t, db, recorder, inv)
	assert.Equal(t, migrateExitOK, code, stderr)
	assert.Contains(t, stdout, "was already held, so nothing was granted")

	user, err := db.GetUserByEmail(ctx, nil, "admin@example.com")
	require.NoError(t, err)
	grants, err := db.GetUserPermissionsByUserId(ctx, nil, user.Id)
	require.NoError(t, err)
	assert.Len(t, grants, 1, "the second run wrote no second grant")
	assert.Equal(t, manage.Id, grants[0].PermissionId)
	assert.Equal(t, []string{audit.EventRevokedUserAuthState}, recorder.events,
		"no permission event for a grant that did not happen")
}
