package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam F of #247: the two narrow writes behind the pending TOTP enrolment, exercised against the
// real implementation on all four engines rather than through a mock.
//
// The reason this tier owns them: a mock-backed case shows a method was HANDED a transaction, never
// that it used it, and the rollback cases below are the only place that distinction is observable.
// It is also the only tier that sees each engine's own blob and datetime handling, which the pair
// depends on completely: the ciphertext is a BLOB / longblob / bytea / VARBINARY(MAX) and the
// timestamp a DATETIME / datetime(6) / timestamp(6) / DATETIME2(6), and the clear writes a literal
// NULL into the first of those precisely because sqlbuilder's typed nil is refused by one of them.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// createEnrollableUser makes a user who can accept a pending enrolment: no authenticator, and no
// pending value. createTestUser randomises OTPEnabled, which every install case below depends on
// being false, so this is not a convenience.
func createEnrollableUser(t *testing.T) *models.User {
	t.Helper()
	user := createTestUser(t)
	user.OTPEnabled = false
	require.NoError(t, database.UpdateUser(nil, user), "UpdateUser to clear otp_enabled")
	return user
}

func reloadUser(t *testing.T, userId int64) *models.User {
	t.Helper()
	u, err := database.GetUserById(nil, userId)
	require.NoError(t, err, "reload user %d", userId)
	require.NotNil(t, u, "user %d vanished", userId)
	return u
}

// encryptedKeyURL is a stand-in for what the enrolment endpoint stores: the whole otpauth:// URL,
// encrypted, rather than the bare base32 seed. The exact string does not matter here; that it
// survives the round trip byte for byte, and decrypts back to what went in, does.
func encryptedKeyURL(t *testing.T, secret string) []byte {
	t.Helper()
	ct, err := encryption.EncryptData(
		"otpauth://totp/Goiabada:user@example.com?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=" + secret)
	require.NoError(t, err, "EncryptData")
	return ct
}

// TestTryInstallPendingOTPEnrollment_RoundTrip covers the happy path end to end: a value goes in,
// comes back byte-identical through the engine's blob handling, decrypts to what was encrypted, and
// clears back to the dormant NULL state.
func TestTryInstallPendingOTPEnrollment_RoundTrip(t *testing.T) {
	user := createEnrollableUser(t)
	bystander := createEnrollableUser(t)

	// Truncated to microseconds because that is the resolution three of the four engines store:
	// sqlite DATETIME, mysql datetime(6), postgres timestamp(6) and mssql DATETIME2(6). The rest
	// of this suite truncates for the same reason.
	issuedAt := time.Now().UTC().Truncate(time.Microsecond)
	ciphertext := encryptedKeyURL(t, "ZP2Z5KXRBAPPHWXEHH65PY5H7EKLVHRZ")

	installed, err := database.TryInstallPendingOTPEnrollment(nil, user.Id, ciphertext, issuedAt,
		issuedAt.Add(-15*time.Minute))
	require.NoError(t, err, "TryInstallPendingOTPEnrollment")
	assert.True(t, installed, "a user with nothing pending and no authenticator must accept one")

	after := reloadUser(t, user.Id)
	assert.Equal(t, ciphertext, after.OtpEnrollmentSecretEncrypted,
		"the ciphertext must survive the engine's blob column byte for byte")
	require.True(t, after.OtpEnrollmentIssuedAt.Valid, "issued_at must be set")
	assert.WithinDuration(t, issuedAt, after.OtpEnrollmentIssuedAt.Time.UTC(), time.Millisecond,
		"issued_at must survive the engine's datetime column")

	decrypted, err := encryption.DecryptData(after.OtpEnrollmentSecretEncrypted)
	require.NoError(t, err, "the stored ciphertext must decrypt under the process data cipher")
	assert.Contains(t, decrypted, "otpauth://totp/",
		"what is stored is the whole key URL, which is the only form the QR image can be rendered from")

	other := reloadUser(t, bystander.Id)
	assert.Nil(t, other.OtpEnrollmentSecretEncrypted,
		"the install is keyed on one user id and must not reach any other row")

	require.NoError(t, database.ClearPendingOTPEnrollment(nil, user.Id), "ClearPendingOTPEnrollment")

	cleared := reloadUser(t, user.Id)
	assert.Nil(t, cleared.OtpEnrollmentSecretEncrypted, "the clear must return the ciphertext to NULL")
	assert.False(t, cleared.OtpEnrollmentIssuedAt.Valid, "the clear must return issued_at to NULL")

	// Clearing a user with nothing pending is not a failure: nothing gates on the transition, and
	// both enable paths call it unconditionally.
	assert.NoError(t, database.ClearPendingOTPEnrollment(nil, bystander.Id),
		"clearing a user with nothing pending must succeed")
}

// TestTryInstallPendingOTPEnrollment_Idempotence is goal 7 at the layer that can prove it: while a
// pending enrolment is live, a second install loses and the first caller's seed is what remains. It
// is what stops a page reload handing the user a second QR code that silently invalidates the one
// they have already scanned.
func TestTryInstallPendingOTPEnrollment_Idempotence(t *testing.T) {
	user := createEnrollableUser(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	staleBefore := now.Add(-15 * time.Minute)

	winner := encryptedKeyURL(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	loser := encryptedKeyURL(t, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	installed, err := database.TryInstallPendingOTPEnrollment(nil, user.Id, winner, now, staleBefore)
	require.NoError(t, err)
	require.True(t, installed, "the first install must win")

	installed, err = database.TryInstallPendingOTPEnrollment(nil, user.Id, loser, now.Add(time.Second), staleBefore)
	require.NoError(t, err, "a losing install is not an error")
	assert.False(t, installed, "a live unexpired pending enrolment must refuse to be replaced")

	after := reloadUser(t, user.Id)
	assert.Equal(t, winner, after.OtpEnrollmentSecretEncrypted,
		"the loser must leave the winner's seed in place; if this is the loser's, two concurrent "+
			"enrolment requests would each invalidate the other's QR code")

	// An expired one, by contrast, is replaceable. staleBefore moves past the stored issued_at,
	// which is exactly what the handler's lifetime does as time passes.
	replacement := encryptedKeyURL(t, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	installed, err = database.TryInstallPendingOTPEnrollment(nil, user.Id, replacement,
		now.Add(time.Hour), now.Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, installed, "an expired pending enrolment must be replaceable")

	after = reloadUser(t, user.Id)
	assert.Equal(t, replacement, after.OtpEnrollmentSecretEncrypted)
}

// TestTryInstallPendingOTPEnrollment_RefusesAnEnabledAuthenticator covers the otp_enabled term. A
// user who already has an authenticator has nothing to enrol, and without this term a seed could be
// parked on the row to wait for the authenticator to be removed.
func TestTryInstallPendingOTPEnrollment_RefusesAnEnabledAuthenticator(t *testing.T) {
	user := createEnrollableUser(t)
	user.OTPEnabled = true
	require.NoError(t, database.UpdateUser(nil, user), "UpdateUser to set otp_enabled")

	now := time.Now().UTC().Truncate(time.Microsecond)
	installed, err := database.TryInstallPendingOTPEnrollment(nil, user.Id,
		encryptedKeyURL(t, "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"), now, now.Add(-15*time.Minute))
	require.NoError(t, err, "a refusal is not an error")
	assert.False(t, installed, "a user with an authenticator already must not accept a pending enrolment")

	after := reloadUser(t, user.Id)
	assert.Nil(t, after.OtpEnrollmentSecretEncrypted, "the refused call must not have written anything")
}

// TestPendingOTPEnrollment_RefusedArguments covers the three arguments that would otherwise do
// something quietly wrong rather than nothing.
func TestPendingOTPEnrollment_RefusedArguments(t *testing.T) {
	user := createEnrollableUser(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ciphertext := encryptedKeyURL(t, "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")

	_, err := database.TryInstallPendingOTPEnrollment(nil, 0, ciphertext, now, now)
	assert.Error(t, err, "user id 0 must be refused")

	// An empty ciphertext is the dormant value of every user with nothing pending, so installing
	// one would leave the row looking untouched while reporting success.
	_, err = database.TryInstallPendingOTPEnrollment(nil, user.Id, nil, now, now)
	assert.Error(t, err, "an empty pending enrolment must be refused")

	// A zero issued_at is worse than useless: every real staleBefore is after it, so the enrolment
	// would install and then be treated as expired by the very next call.
	_, err = database.TryInstallPendingOTPEnrollment(nil, user.Id, ciphertext, time.Time{}, now)
	assert.Error(t, err, "a zero issued at must be refused")

	assert.Error(t, database.ClearPendingOTPEnrollment(nil, 0), "user id 0 must be refused")

	after := reloadUser(t, user.Id)
	assert.Nil(t, after.OtpEnrollmentSecretEncrypted, "none of the refused calls may have written")
}

// TestUpdateUser_DoesNotClobberPendingOTPEnrollment is the dont-update tag's own case, the sibling
// of TestUpdateUser_DoesNotClobberOtpConfigGeneration.
//
// The hazard is the pair's whole reason for existing: fourteen production sites load a user and
// later write it back, and with these columns in the ordinary update set a model loaded before
// issuance would erase the seed that was installed in between, or a model loaded before the clear
// would resurrect one after the authenticator was established.
func TestUpdateUser_DoesNotClobberPendingOTPEnrollment(t *testing.T) {
	user := createEnrollableUser(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	ciphertext := encryptedKeyURL(t, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	installed, err := database.TryInstallPendingOTPEnrollment(nil, user.Id, ciphertext, now,
		now.Add(-15*time.Minute))
	require.NoError(t, err)
	require.True(t, installed)

	// A model that predates the install, which is what every one of those fourteen sites holds.
	stale := reloadUser(t, user.Id)
	stale.OtpEnrollmentSecretEncrypted = nil
	stale.OtpEnrollmentIssuedAt = sql.NullTime{}
	stale.GivenName = "Updated"
	require.NoError(t, database.UpdateUser(nil, stale), "UpdateUser")

	after := reloadUser(t, user.Id)
	assert.Equal(t, ciphertext, after.OtpEnrollmentSecretEncrypted,
		"UpdateUser must not carry otp_enrollment_secret_encrypted; is the dont-update tag missing?")
	assert.True(t, after.OtpEnrollmentIssuedAt.Valid,
		"UpdateUser must not carry otp_enrollment_issued_at; is the dont-update tag missing?")
	assert.Equal(t, "Updated", after.GivenName, "the rest of the update must still apply")
}

// TestPendingOTPEnrollment_EnlistsInTheCallersTransaction is the case that cannot be written at any
// other tier. Both writes are called inside a caller's transaction in production, and "was handed a
// *sql.Tx" is not the same claim as "used it": a method that ignored its argument and ran on the
// pool would satisfy every mock in the tree and break exactly this.
func TestPendingOTPEnrollment_EnlistsInTheCallersTransaction(t *testing.T) {
	user := createEnrollableUser(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ciphertext := encryptedKeyURL(t, "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")

	// The install, rolled back.
	tx, err := database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")
	installed, err := database.TryInstallPendingOTPEnrollment(tx, user.Id, ciphertext, now,
		now.Add(-15*time.Minute))
	require.NoError(t, err)
	require.True(t, installed, "inside the transaction the install reports that it won")
	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

	assert.Nil(t, reloadUser(t, user.Id).OtpEnrollmentSecretEncrypted,
		"a rolled back transaction must leave nothing installed; if this is set, the install ran "+
			"outside the caller's transaction and a failed request would strand a live seed")

	// The clear, rolled back over a committed install.
	installed, err = database.TryInstallPendingOTPEnrollment(nil, user.Id, ciphertext, now,
		now.Add(-15*time.Minute))
	require.NoError(t, err)
	require.True(t, installed)

	tx, err = database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")
	require.NoError(t, database.ClearPendingOTPEnrollment(tx, user.Id), "ClearPendingOTPEnrollment")
	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

	assert.Equal(t, ciphertext, reloadUser(t, user.Id).OtpEnrollmentSecretEncrypted,
		"a rolled back transaction must leave the pending enrolment where it was; if this is nil, "+
			"the clear ran outside the caller's transaction and a rolled back enable would have "+
			"thrown away a seed the user still needs")
}

// TestEnableUserOTPTx_ClearsThePendingEnrollment is the property #247 §4.5 states, at the only tier
// that can observe it: an authenticator never commits with a live pending seed still installed, and
// a failed enable never discards one.
func TestEnableUserOTPTx_ClearsThePendingEnrollment(t *testing.T) {
	user := createEnrollableUser(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ciphertext := encryptedKeyURL(t, "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")

	installed, err := database.TryInstallPendingOTPEnrollment(nil, user.Id, ciphertext, now,
		now.Add(-15*time.Minute))
	require.NoError(t, err)
	require.True(t, installed)

	// The failing arm first, so the success below is not passing on a row that was already clear.
	// Id 0 is what makes UpdateUser fail without touching the database, and the whole transaction
	// including the clear must roll back with it.
	broken := reloadUser(t, user.Id)
	broken.Id = 0
	_, err = handlers.EnableUserOTPTx(database, broken)
	require.Error(t, err, "EnableUserOTPTx must fail on a user with id 0")

	assert.Equal(t, ciphertext, reloadUser(t, user.Id).OtpEnrollmentSecretEncrypted,
		"a failed enable must leave the pending enrolment alone: the user has scanned that QR "+
			"code and is about to retry with the next passcode")

	enrolling := reloadUser(t, user.Id)
	enrolling.OTPEnabled = true
	require.NoError(t, enrolling.SetOTPSecret("ZP2Z5KXRBAPPHWXEHH65PY5H7EKLVHRZ"), "SetOTPSecret")
	generation, err := handlers.EnableUserOTPTx(database, enrolling)
	require.NoError(t, err, "EnableUserOTPTx")
	assert.EqualValues(t, 1, generation, "the counter advance still happens")

	after := reloadUser(t, user.Id)
	assert.True(t, after.OTPEnabled, "the authenticator must be established")
	assert.Nil(t, after.OtpEnrollmentSecretEncrypted,
		"an enabled authenticator must have no pending seed behind it")
	assert.False(t, after.OtpEnrollmentIssuedAt.Valid,
		"an enabled authenticator must have no pending issued_at behind it")
}
