package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The re-encryption sweep, ReencryptStoredSecrets, on the tier's own engine (#492 decisions 4 to
// 6 and 9). Each test runs in a database of its own, because the sweep reads every stored secret
// there is.
//
// A configuration of a rotation is stated as an operator sets it: the data key, and the previous
// key when one is set. What a value is under is asserted with a cipher built here from one key
// alone, never from what the sweep reports: a value is under the new key when a cipher holding the
// new key alone opens it.

// The two data keys of the rotation, and a third that is neither, under which nothing opens.
var (
	sweepOldKey   = []byte("old-data-key-old-data-key-old-da")
	sweepNewKey   = []byte("new-data-key-new-data-key-new-da")
	sweepOtherKey = []byte("neither-key-neither-key-neither-")
)

// The configurations a rotation runs through, as the cipher main builds from the two variables.
var (
	// Before the rotation: the old key alone.
	configOldAlone = mustSweepCipher(sweepOldKey, nil)
	// The first rollout: the new key goes in as the previous key, and the old still seals.
	configNewAsPrevious = mustSweepCipher(sweepOldKey, sweepNewKey)
	// The swap: the new key seals, and the old opens what is still under it.
	configSwapped = mustSweepCipher(sweepNewKey, sweepOldKey)
)

// The verifiers, each holding one key alone.
var (
	newKeyAlone   = mustSweepCipher(sweepNewKey, nil)
	oldKeyAlone   = mustSweepCipher(sweepOldKey, nil)
	otherKeyAlone = mustSweepCipher(sweepOtherKey, nil)
)

func mustSweepCipher(current, previous []byte) *encryption.DataCipher {
	cipher, err := encryption.NewDataCipherWithPrevious(current, previous)
	if err != nil {
		panic(err)
	}
	return cipher
}

// sweep is the sweep an operator runs once every auth server has the swapped configuration.
func sweep(t *testing.T, db data.Database) record.Reencryption {
	t.Helper()
	report, unreadable := sweepNaming(t, db, sweepNewKey, sweepOldKey)
	require.Len(t, unreadable, report.Unreadable, "the sweep names each value it counts as unreadable")
	return report
}

// sweepNaming runs the sweep with the given keys and answers its report and every value it named
// as unreadable, in the order it named them.
func sweepNaming(t *testing.T, db data.Database, currentKey, previousKey []byte) (record.Reencryption, []record.StoredSecret) {
	t.Helper()
	var unreadable []record.StoredSecret
	report, err := db.ReencryptStoredSecrets(context.Background(), currentKey, previousKey, func(value record.StoredSecret) {
		unreadable = append(unreadable, value)
	})
	require.NoError(t, err, "the sweep")
	return report, unreadable
}

// The nine kinds of stored secret, by where each is held.
const (
	kindSMTPPassword        = "settings.smtp_password_encrypted"
	kindTurnstileSecretKey  = "settings.turnstile_secret_key_encrypted"
	kindClientSecret        = "clients.client_secret_encrypted"
	kindEmailCode           = "users.email_verification_code_encrypted"
	kindOTPSecret           = "users.otp_secret_encrypted"
	kindForgotPasswordCode  = "users.forgot_password_code_encrypted"
	kindOTPEnrollmentSecret = "users.otp_enrollment_secret_encrypted"
	kindPreRegistrationCode = "pre_registrations.verification_code_encrypted"
	kindSigningKey          = "key_pairs.private_key_pem"
)

var nineKinds = []string{
	kindSMTPPassword, kindTurnstileSecretKey, kindClientSecret, kindEmailCode, kindOTPSecret,
	kindForgotPasswordCode, kindOTPEnrollmentSecret, kindPreRegistrationCode, kindSigningKey,
}

// nineSecrets is one row of each kind, written through the data layer by one configuration.
type nineSecrets struct {
	tag                                               string
	settingsID, clientID, userID, preRegID, keyPairID int64
}

// plaintext is what the kind's value of this set opens to.
func (n nineSecrets) plaintext(kind string) string {
	return kind + "/" + n.tag
}

// storeNine seals one value of each kind with cipher and writes them through the data layer, as a
// server holding that cipher writes them. The signing key takes state, as key_pairs holds one key
// in each state.
func storeNine(t *testing.T, db data.Database, cipher *encryption.DataCipher, state record.KeyState, tag string) nineSecrets {
	t.Helper()
	ctx := context.Background()
	n := nineSecrets{tag: tag}
	seal := func(kind string) []byte {
		sealed, err := cipher.Encrypt(n.plaintext(kind))
		require.NoError(t, err)
		return sealed
	}

	settings := initialSettings("Sweep " + tag)
	settings.SMTPPasswordEncrypted = seal(kindSMTPPassword)
	settings.TurnstileSecretKeyEncrypted = seal(kindTurnstileSecretKey)
	require.NoError(t, db.CreateSettings(ctx, nil, settings))
	n.settingsID = settings.ID

	client := &record.Client{ClientIdentifier: "c-" + fake.UUID(), ClientSecretEncrypted: seal(kindClientSecret)}
	require.NoError(t, db.CreateClient(ctx, nil, client))
	n.clientID = client.ID

	user := &record.User{
		Subject: fake.UUID(), Username: fake.Username(), Email: fake.Email(), PasswordHash: "x",
		EmailVerificationCodeEncrypted: seal(kindEmailCode),
		OTPSecretEncrypted:             seal(kindOTPSecret),
		ForgotPasswordCodeEncrypted:    seal(kindForgotPasswordCode),
		OTPEnrollmentSecretEncrypted:   seal(kindOTPEnrollmentSecret),
	}
	require.NoError(t, db.CreateUser(ctx, nil, user))
	n.userID = user.ID

	preReg := &record.PreRegistration{
		Email: fake.Email(), VerificationCodeEncrypted: seal(kindPreRegistrationCode),
		VerificationCodeHash: codeHashOf(t, fake.UUID()),
	}
	require.NoError(t, db.CreatePreRegistration(ctx, nil, preReg))
	n.preRegID = preReg.ID

	keyPair := sweepKeyPair(state, seal(kindSigningKey))
	require.NoError(t, db.CreateKeyPair(ctx, nil, keyPair))
	n.keyPairID = keyPair.ID
	return n
}

func sweepKeyPair(state record.KeyState, privateKey []byte) *record.KeyPair {
	return &record.KeyPair{
		State: state.String(), KeyIdentifier: fake.UUID(), Type: "RSA", Algorithm: "RS256",
		PrivateKeyPEM: privateKey,
	}
}

// read answers the nine values of the set as the data layer reads them now.
func (n nineSecrets) read(t *testing.T, db data.Database) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	settings, err := db.GetSettingsByID(ctx, nil, n.settingsID)
	require.NoError(t, err)
	client, err := db.GetClientByID(ctx, nil, n.clientID)
	require.NoError(t, err)
	user, err := db.GetUserByID(ctx, nil, n.userID)
	require.NoError(t, err)
	preReg, err := db.GetPreRegistrationByID(ctx, nil, n.preRegID)
	require.NoError(t, err)
	keyPair, err := db.GetKeyPairByID(ctx, nil, n.keyPairID)
	require.NoError(t, err)
	return map[string][]byte{
		kindSMTPPassword:        settings.SMTPPasswordEncrypted,
		kindTurnstileSecretKey:  settings.TurnstileSecretKeyEncrypted,
		kindClientSecret:        client.ClientSecretEncrypted,
		kindEmailCode:           user.EmailVerificationCodeEncrypted,
		kindOTPSecret:           user.OTPSecretEncrypted,
		kindForgotPasswordCode:  user.ForgotPasswordCodeEncrypted,
		kindOTPEnrollmentSecret: user.OTPEnrollmentSecretEncrypted,
		kindPreRegistrationCode: preReg.VerificationCodeEncrypted,
		kindSigningKey:          keyPair.PrivateKeyPEM,
	}
}

// where names each value of the set by its table, column and row id, as the sweep reports one.
func (n nineSecrets) where(kind string) record.StoredSecret {
	table, column, _ := strings.Cut(kind, ".")
	id := map[string]int64{
		"settings": n.settingsID, "clients": n.clientID, "users": n.userID,
		"pre_registrations": n.preRegID, "key_pairs": n.keyPairID,
	}[table]
	return record.StoredSecret{Table: table, Column: column, ID: id}
}

// assertNineOpen asserts that cipher opens each of the set's nine values to its own plaintext.
func assertNineOpen(t *testing.T, db data.Database, n nineSecrets, cipher *encryption.DataCipher, under string) {
	t.Helper()
	values := n.read(t, db)
	for _, kind := range nineKinds {
		got, err := cipher.Decrypt(values[kind])
		if assert.NoErrorf(t, err, "%s of the %s set does not open under %s", kind, n.tag, under) {
			assert.Equalf(t, n.plaintext(kind), got, "%s of the %s set", kind, n.tag)
		}
	}
}

// assertNoneOpen asserts that cipher opens none of the set's nine values.
func assertNoneOpen(t *testing.T, db data.Database, n nineSecrets, cipher *encryption.DataCipher, under string) {
	t.Helper()
	values := n.read(t, db)
	for _, kind := range nineKinds {
		_, err := cipher.Decrypt(values[kind])
		assert.Errorf(t, err, "%s of the %s set still opens under %s", kind, n.tag, under)
	}
}

// The phase matrix (#492 decision 9). At each rollout the two configurations that run side by side
// each open every kind of stored secret the other seals, and after the sweep the new key alone opens
// every value and the old key alone opens none.
func TestReencryptStoredSecrets_PhaseMatrix(t *testing.T) {
	t.Parallel()
	h := migratedIsolatedDB(t)

	sealedOldAlone := storeNine(t, h.DB, configOldAlone, record.KeyStateCurrent, "old-alone")
	sealedNewAsPrevious := storeNine(t, h.DB, configNewAsPrevious, record.KeyStateNext, "new-as-previous")
	sealedSwapped := storeNine(t, h.DB, configSwapped, record.KeyStatePrevious, "swapped")

	// The first rollout: old pods beside pods holding the new key as the previous key.
	assertNineOpen(t, h.DB, sealedOldAlone, configNewAsPrevious, "the new key as the previous key")
	assertNineOpen(t, h.DB, sealedNewAsPrevious, configOldAlone, "the old key alone")
	// The second rollout, the swap: pods holding the new key as the previous key beside swapped ones.
	assertNineOpen(t, h.DB, sealedNewAsPrevious, configSwapped, "the swapped keys")
	assertNineOpen(t, h.DB, sealedSwapped, configNewAsPrevious, "the new key as the previous key")

	report := sweep(t, h.DB)

	assert.Equal(t, record.Reencryption{Reencrypted: 18, AlreadyCurrent: 9}, report,
		"the two sets sealed under the old key are re-encrypted, and the swapped set is already under the new key")
	for _, set := range []nineSecrets{sealedOldAlone, sealedNewAsPrevious, sealedSwapped} {
		assertNineOpen(t, h.DB, set, newKeyAlone, "the new key alone")
		assertNoneOpen(t, h.DB, set, oldKeyAlone, "the old key alone")
	}
}

// A value neither key opens is left byte for byte and reported by table, column and row id, and the
// sweep goes on past it. The report lists the values in the order the sweep reached them, which
// shows the signing keys go last, and the current one last of all (#492 decisions 5 and 6): the
// current signing key here is the first key pair written, so a sweep in row order would reach it
// first.
func TestReencryptStoredSecrets_ReportsAndLeavesWhatNeitherKeyOpens_TheSigningKeysLast(t *testing.T) {
	t.Parallel()
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	unreadable := storeNine(t, h.DB, otherKeyAlone, record.KeyStateCurrent, "neither")
	sealedNext, err := otherKeyAlone.Encrypt("the next signing key")
	require.NoError(t, err)
	nextKeyPair := sweepKeyPair(record.KeyStateNext, sealedNext)
	require.NoError(t, h.DB.CreateKeyPair(ctx, nil, nextKeyPair))
	sealedPrevious, err := otherKeyAlone.Encrypt("the previous signing key")
	require.NoError(t, err)
	previousKeyPair := sweepKeyPair(record.KeyStatePrevious, sealedPrevious)
	require.NoError(t, h.DB.CreateKeyPair(ctx, nil, previousKeyPair))
	// A readable client secret beside them, after the unreadable one in the sweep's order.
	readable, err := configNewAsPrevious.Encrypt("a readable client secret")
	require.NoError(t, err)
	readableClient := &record.Client{ClientIdentifier: "c-" + fake.UUID(), ClientSecretEncrypted: readable}
	require.NoError(t, h.DB.CreateClient(ctx, nil, readableClient))
	before := unreadable.read(t, h.DB)

	report, named := sweepNaming(t, h.DB, sweepNewKey, sweepOldKey)

	assert.Equal(t, 1, report.Reencrypted, "the readable client secret is re-encrypted past the unreadable values")
	assert.Zero(t, report.AlreadyCurrent)
	assert.Equal(t, 11, report.Unreadable, "each value neither key opens is counted")
	require.Len(t, named, 11, "each value neither key opens is named: %+v", named)
	var stringKinds []record.StoredSecret
	for _, kind := range nineKinds[:8] {
		stringKinds = append(stringKinds, unreadable.where(kind))
	}
	assert.ElementsMatch(t, stringKinds, named[:8], "the stored secrets other than the signing keys come first")
	assert.ElementsMatch(t, []record.StoredSecret{
		{Table: "key_pairs", Column: "private_key_pem", ID: nextKeyPair.ID},
		{Table: "key_pairs", Column: "private_key_pem", ID: previousKeyPair.ID},
	}, named[8:10], "the next and previous signing keys come after every other stored secret")
	assert.Equal(t, unreadable.where(kindSigningKey), named[10], "the current signing key comes last of all")

	after := unreadable.read(t, h.DB)
	for _, kind := range nineKinds {
		assert.Truef(t, bytes.Equal(before[kind], after[kind]), "%s neither key opens was rewritten", kind)
	}
	for _, keyPair := range []*record.KeyPair{nextKeyPair, previousKeyPair} {
		stored, getErr := h.DB.GetKeyPairByID(ctx, nil, keyPair.ID)
		require.NoError(t, getErr)
		assert.Truef(t, bytes.Equal(keyPair.PrivateKeyPEM, stored.PrivateKeyPEM), "the %s signing key was rewritten", keyPair.State)
	}
	got, err := h.DB.GetClientByID(ctx, nil, readableClient.ID)
	require.NoError(t, err)
	opened, err := newKeyAlone.Decrypt(got.ClientSecretEncrypted)
	require.NoError(t, err, "the readable client secret is under the new key")
	assert.Equal(t, "a readable client secret", opened)
}

// Run with no previous key, or with the previous key equal to the current one, the sweep is a check:
// it writes nothing, counts what the current key opens and reports the rest (#492 decision 5).
func TestReencryptStoredSecrets_WithNoPreviousKeyWritesNothing(t *testing.T) {
	t.Parallel()
	h := migratedIsolatedDB(t)

	underNew := storeNine(t, h.DB, newKeyAlone, record.KeyStateCurrent, "under-new")
	underOld := storeNine(t, h.DB, oldKeyAlone, record.KeyStateNext, "under-old")
	beforeNew, beforeOld := underNew.read(t, h.DB), underOld.read(t, h.DB)

	for _, tc := range []struct {
		name        string
		previousKey []byte
	}{
		{"no previous key", nil},
		{"the previous key equal to the current one", append([]byte(nil), sweepNewKey...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, named := sweepNaming(t, h.DB, sweepNewKey, tc.previousKey)

			assert.Zero(t, report.Reencrypted)
			assert.Equal(t, 9, report.AlreadyCurrent)
			assert.Equal(t, 9, report.Unreadable)
			var wantUnreadable []record.StoredSecret
			for _, kind := range nineKinds {
				wantUnreadable = append(wantUnreadable, underOld.where(kind))
			}
			assert.ElementsMatch(t, wantUnreadable, named, "the values under the old key open under no key given")

			afterNew, afterOld := underNew.read(t, h.DB), underOld.read(t, h.DB)
			for _, kind := range nineKinds {
				assert.Truef(t, bytes.Equal(beforeNew[kind], afterNew[kind]), "%s under the current key was rewritten", kind)
				assert.Truef(t, bytes.Equal(beforeOld[kind], afterOld[kind]), "%s under the old key was rewritten", kind)
			}
		})
	}
}

// The sweep reads a table in bounded batches, and reaches every row however many batches that
// takes. 250 clients are more than two of its batches of 100 (commondb's reencryptionBatchSize).
func TestReencryptStoredSecrets_ReachesEveryRowAcrossBatches(t *testing.T) {
	t.Parallel()
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	const clients = 250
	ids := make([]int64, 0, clients)
	for i := range clients {
		sealed, err := oldKeyAlone.Encrypt("client secret " + strconv.Itoa(i))
		require.NoError(t, err)
		client := &record.Client{ClientIdentifier: "c-" + fake.UUID(), ClientSecretEncrypted: sealed}
		require.NoError(t, h.DB.CreateClient(ctx, nil, client))
		ids = append(ids, client.ID)
	}

	report := sweep(t, h.DB)

	assert.Equal(t, record.Reencryption{Reencrypted: clients}, report)
	for i, id := range ids {
		client, err := h.DB.GetClientByID(ctx, nil, id)
		require.NoError(t, err)
		opened, err := newKeyAlone.Decrypt(client.ClientSecretEncrypted)
		if assert.NoErrorf(t, err, "client %d is not under the new key", i) {
			assert.Equal(t, "client secret "+strconv.Itoa(i), opened)
		}
	}
}

// A sweep stopped part of the way, its context cancelled while it waits for a row a server holds,
// answers the cancellation, and the next run carries on and finishes: every value ends under the new
// key (#492 decision 4).
func TestReencryptStoredSecrets_InterruptedAndRunAgainFinishes(t *testing.T) {
	t.Parallel()
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	set := storeNine(t, h.DB, oldKeyAlone, record.KeyStateCurrent, "interrupted")

	// A server holds the user's row, which the sweep reaches after the settings and the client.
	held := beginTxOn(t, h.DB)
	require.NoError(t, h.DB.AcquireUserRow(ctx, held, set.userID))

	sweepCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	var first record.Reencryption
	go func() {
		var err error
		first, err = h.DB.ReencryptStoredSecrets(sweepCtx, sweepNewKey, sweepOldKey, nil)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the sweep finished while a server held a row it re-encrypts (err %v)", err)
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled, "a cancelled sweep answers its cancellation")
	case <-time.After(30 * time.Second):
		t.Fatal("the cancelled sweep never returned")
	}
	require.NoError(t, h.DB.CommitTransaction(ctx, held))
	assert.Less(t, first.Reencrypted, 9, "the cancelled sweep did not reach the end")

	second := sweep(t, h.DB)

	assert.Zero(t, second.Unreadable)
	assert.Equal(t, 9, second.Reencrypted+second.AlreadyCurrent, "the second run reaches every value")
	assertNineOpen(t, h.DB, set, newKeyAlone, "the new key alone")
}

// A server's write that lands while the sweep waits for the row, leaving the bytes the sweep read
// with a zero byte after them, is a change: the sweep's conditional write misses and leaves the
// server's bytes as they are. SQL Server compares two VARBINARY values equal when they differ only
// in trailing zero bytes, so this is the case its statement must tell apart by length (#492
// decision 4).
func TestReencryptStoredSecrets_ATrailingZeroByteIsAChange(t *testing.T) {
	t.Parallel()
	runTrailingZeroByteIsAChange(t, migratedIsolatedDB(t).DB)
}

// TestReencryptStoredSecrets_ATrailingZeroByteIsAChange_RCSI is the same case on a SQL Server
// database with READ_COMMITTED_SNAPSHOT on, the one where the sweep's batch read does not wait for
// the row the server holds: it reads the bytes as last committed, and its write, waiting for the
// row, then finds the server's. On the tier's own database the read waits instead, and reads the
// server's bytes. It skips on the other three engines. The database is shared, so the case looks
// only at its own client.
func TestReencryptStoredSecrets_ATrailingZeroByteIsAChange_RCSI(t *testing.T) {
	runTrailingZeroByteIsAChange(t, rcsiDatabase(t).primary)
}

func runTrailingZeroByteIsAChange(t *testing.T, db data.Database) {
	ctx := context.Background()

	sealed, err := oldKeyAlone.Encrypt("the client's secret")
	require.NoError(t, err)
	client := &record.Client{ClientIdentifier: "c-" + fake.UUID(), ClientSecretEncrypted: sealed}
	require.NoError(t, db.CreateClient(ctx, nil, client))

	// A server holds the client's row, so the sweep waits to write it.
	held := beginTxOn(t, db)
	require.NoError(t, db.AcquireClientRow(ctx, held, client.ID))
	type outcome struct {
		named []record.StoredSecret
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		_, o.err = db.ReencryptStoredSecrets(ctx, sweepNewKey, sweepOldKey, func(value record.StoredSecret) {
			o.named = append(o.named, value)
		})
		done <- o
	}()
	select {
	case o := <-done:
		t.Fatalf("the sweep finished while a server held the row it re-encrypts (err %v)", o.err)
	case <-time.After(500 * time.Millisecond):
	}

	// The server writes the bytes the sweep read with a zero byte after them, and commits.
	changed := append(append([]byte(nil), sealed...), 0)
	stored, err := db.GetClientByID(ctx, held, client.ID)
	require.NoError(t, err)
	stored.ClientSecretEncrypted = changed
	require.NoError(t, db.UpdateClient(ctx, held, stored))
	require.NoError(t, db.CommitTransaction(ctx, held))

	var o outcome
	select {
	case o = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the sweep never returned after the server committed")
	}
	require.NoError(t, o.err)
	assert.Contains(t, o.named, record.StoredSecret{Table: "clients", Column: "client_secret_encrypted", ID: client.ID},
		"the server's bytes open under neither key, and are reported")

	after, err := db.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	assert.Equal(t, changed, after.ClientSecretEncrypted, "the server's bytes are left as the server wrote them")
}

// A current key or a previous key of the wrong length is refused before anything is read.
func TestReencryptStoredSecrets_RefusesKeysOfTheWrongLength(t *testing.T) {
	t.Parallel()
	h := migratedIsolatedDB(t)
	set := storeNine(t, h.DB, oldKeyAlone, record.KeyStateCurrent, "refused")

	for _, tc := range []struct {
		name                    string
		currentKey, previousKey []byte
		want                    string
	}{
		{"a short current key", sweepNewKey[:16], sweepOldKey, "data encryption key must be 32 bytes, but it has 16 bytes"},
		{"a long previous key", sweepNewKey, append(append([]byte(nil), sweepOldKey...), 'x'),
			"previous data encryption key must be 32 bytes, but it has 33 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := h.DB.ReencryptStoredSecrets(context.Background(), tc.currentKey, tc.previousKey, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Equal(t, record.Reencryption{}, report)
			assertNineOpen(t, h.DB, set, oldKeyAlone, "the old key alone")
		})
	}
}

// --- The sweep beside a server's writes -------------------------------------------------------

// sweepPoint is where, in a server write, the sweep is made to run.
type sweepPoint int

const (
	// sweepBeforeTransaction: the sweep runs to its end after the server read the row and before
	// it opens the transaction that writes it, a request's read and its save.
	sweepBeforeTransaction sweepPoint = iota + 1
	// sweepBeforeVerification: the sweep runs to its end between the verification's comparison
	// and its conditional write.
	sweepBeforeVerification
	// The sweep starts while the server holds the row in an open transaction, after the named
	// call, and must wait for the server's commit.
	sweepWhileAcquireClientRowHolds
	sweepWhileUpdateClientHolds
	sweepWhileSetClientPublicHolds
	sweepWhileAcquireSettingsRowHolds
)

// sweepDuring is the database a server's handler writes through, which runs the sweep once at
// point. Everything else is the real data layer.
type sweepDuring struct {
	data.Database
	t     *testing.T
	point sweepPoint
	// gap runs right after a sweep at sweepBeforeVerification, for a change committed in the same
	// gap.
	gap func()
	// previousKey, when set, is the previous key the sweep runs with in place of the old key: a
	// sweep run with an older key, which opens what the servers' keys do not.
	previousKey []byte

	mu      sync.Mutex
	fired   bool
	report  record.Reencryption
	pending chan error
}

func (d *sweepDuring) firesAt(point sweepPoint) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.point != point || d.fired {
		return false
	}
	d.fired = true
	return true
}

// sweepToTheEnd runs the sweep and waits for it.
func (d *sweepDuring) sweepToTheEnd() {
	previous := sweepOldKey
	if d.previousKey != nil {
		previous = d.previousKey
	}
	report, err := d.ReencryptStoredSecrets(context.Background(), sweepNewKey, previous, nil)
	require.NoError(d.t, err, "the sweep")
	d.report = report
}

// sweepAgainstTheHeldRow starts the sweep and returns once it is seen waiting for the row the
// server holds: the sweep cannot finish until the server commits.
func (d *sweepDuring) sweepAgainstTheHeldRow() {
	d.pending = make(chan error, 1)
	go func() {
		report, err := d.ReencryptStoredSecrets(context.Background(), sweepNewKey, sweepOldKey, nil)
		d.mu.Lock()
		d.report = report
		d.mu.Unlock()
		d.pending <- err
	}()
	select {
	case err := <-d.pending:
		d.t.Fatalf("the sweep finished while the server held the row uncommitted (err %v): it must wait for the server", err)
	case <-time.After(500 * time.Millisecond):
	}
}

// finished asserts the sweep ran, waiting for one started against a held row, and answers it.
func (d *sweepDuring) finished() record.Reencryption {
	d.t.Helper()
	require.True(d.t, d.fired, "the sweep never ran: the server did not reach its point")
	if d.pending != nil {
		select {
		case err := <-d.pending:
			require.NoError(d.t, err, "the sweep")
		case <-time.After(30 * time.Second):
			d.t.Fatal("the sweep never returned after the server committed")
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.report
}

func (d *sweepDuring) RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if d.firesAt(sweepBeforeTransaction) {
		d.sweepToTheEnd()
	}
	return d.Database.RunInTransaction(ctx, fn)
}

func (d *sweepDuring) TryVerifyUserEmail(ctx context.Context, tx *sql.Tx, userID int64, email string,
	codeEncrypted []byte) (bool, error) {
	if d.firesAt(sweepBeforeVerification) {
		d.sweepToTheEnd()
		if d.gap != nil {
			d.gap()
		}
	}
	return d.Database.TryVerifyUserEmail(ctx, tx, userID, email, codeEncrypted)
}

func (d *sweepDuring) AcquireClientRow(ctx context.Context, tx *sql.Tx, clientID int64) error {
	err := d.Database.AcquireClientRow(ctx, tx, clientID)
	if err == nil && d.firesAt(sweepWhileAcquireClientRowHolds) {
		d.sweepAgainstTheHeldRow()
	}
	return err
}

func (d *sweepDuring) UpdateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error {
	err := d.Database.UpdateClient(ctx, tx, client)
	if err == nil && d.firesAt(sweepWhileUpdateClientHolds) {
		d.sweepAgainstTheHeldRow()
	}
	return err
}

func (d *sweepDuring) SetClientPublic(ctx context.Context, tx *sql.Tx, clientID int64) (bool, error) {
	changed, err := d.Database.SetClientPublic(ctx, tx, clientID)
	if err == nil && d.firesAt(sweepWhileSetClientPublicHolds) {
		d.sweepAgainstTheHeldRow()
	}
	return changed, err
}

func (d *sweepDuring) AcquireSettingsRow(ctx context.Context, tx *sql.Tx, settingsID int64) error {
	err := d.Database.AcquireSettingsRow(ctx, tx, settingsID)
	if err == nil && d.firesAt(sweepWhileAcquireSettingsRowHolds) {
		d.sweepAgainstTheHeldRow()
	}
	return err
}

// adminRequest is an admin API request by a caller holding authserver:manage, under settings.
func adminRequest(t *testing.T, method, target string, body any, settings *record.Settings) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	ctx := reqctx.WithSettings(req.Context(), settings)
	ctx = reqctx.WithValidatedToken(ctx, oauth.JWTToken{Claims: map[string]interface{}{
		"sub": "an-administrator", "scope": "authserver:manage",
	}})
	return req.WithContext(ctx)
}

type acceptingEmailValidator struct{}

func (acceptingEmailValidator) ValidateEmailAddress(string) error { return nil }

type acceptingSecretKeyChecker struct{}

func (acceptingSecretKeyChecker) CheckSecretKey(context.Context, string) turnstile.SecretKeyCheck {
	return turnstile.SecretKeyAccepted
}

// smtpListener is a TCP listener standing in for the SMTP server the email save dials.
func smtpListener(t *testing.T) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// A server's write overlapping the sweep keeps the server's change, and the value ends under the
// current key, in each order (#492 decisions 4 and 10). The servers hold the swapped configuration,
// as they do once the operator runs the sweep, and each write is made by its real handler:
//
//   - the sweep commits after the request read the row and before its save, which then writes onto
//     what the sweep left;
//   - the save holds the row when the sweep reaches it, so the sweep waits, and its write, which
//     names the bytes it read, then finds the server's.
//
// A value replaced or cleared meanwhile is not put back.
func TestReencryptStoredSecrets_BesideAServerWrite(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()
	smtpHost, smtpPort := smtpListener(t)
	const replacementSecret = "a-replacement-client-secret-of-sixty-characters-or-more-0123456789"

	// The client saves.
	newClient := func(t *testing.T) *record.Client {
		sealed, err := oldKeyAlone.Encrypt("the client's secret")
		require.NoError(t, err)
		client := &record.Client{
			ClientIdentifier: "c-" + fake.UUID(), ClientSecretEncrypted: sealed,
			ClientCredentialsEnabled: true, TokenExpirationInSeconds: 300,
		}
		require.NoError(t, h.DB.CreateClient(ctx, nil, client))
		return client
	}
	clientPut := func(t *testing.T, db data.Database, client *record.Client, route string, body any,
		handler func(data.Database) http.HandlerFunc) {
		t.Helper()
		req := adminRequest(t, http.MethodPut, "/api/v1/admin/clients/"+strconv.FormatInt(client.ID, 10)+"/"+route,
			body, &record.Settings{ID: 1})
		req.SetPathValue("id", strconv.FormatInt(client.ID, 10))
		rr := httptest.NewRecorder()
		handler(db).ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	}
	storedClient := func(t *testing.T, client *record.Client) *record.Client {
		stored, err := h.DB.GetClientByID(ctx, nil, client.ID)
		require.NoError(t, err)
		return stored
	}
	underNewKey := func(t *testing.T, sealed []byte, want, what string) {
		t.Helper()
		opened, err := newKeyAlone.Decrypt(sealed)
		if assert.NoErrorf(t, err, "%s is not under the new key", what) {
			assert.Equalf(t, want, opened, "%s", what)
		}
	}

	clientSave := func(t *testing.T, point sweepPoint) {
		client := newClient(t)
		db := &sweepDuring{Database: h.DB, t: t, point: point}
		clientPut(t, db, client, "tokens", api.UpdateClientTokensRequest{
			TokenExpirationInSeconds:                900,
			IncludeOpenIDConnectClaimsInAccessToken: record.ThreeStateSettingDefault.String(),
			IncludeOpenIDConnectClaimsInIDToken:     record.ThreeStateSettingDefault.String(),
		}, func(db data.Database) http.HandlerFunc {
			return apihandlers.HandleClientTokensPut(db, &countingAuditLogger{})
		})
		db.finished()

		stored := storedClient(t, client)
		assert.Equal(t, 900, stored.TokenExpirationInSeconds, "the client save was lost")
		underNewKey(t, stored.ClientSecretEncrypted, "the client's secret", "the kept client secret")
	}
	secretReplacement := func(t *testing.T, point sweepPoint) {
		client := newClient(t)
		db := &sweepDuring{Database: h.DB, t: t, point: point}
		clientPut(t, db, client, "authentication", api.UpdateClientAuthenticationRequest{ClientSecret: replacementSecret},
			func(db data.Database) http.HandlerFunc {
				return apihandlers.HandleClientAuthenticationPut(db, &countingAuditLogger{}, configSwapped)
			})
		db.finished()

		underNewKey(t, storedClient(t, client).ClientSecretEncrypted, replacementSecret, "the replacement client secret")
	}
	switchToPublic := func(t *testing.T, point sweepPoint) {
		client := newClient(t)
		db := &sweepDuring{Database: h.DB, t: t, point: point}
		clientPut(t, db, client, "authentication", api.UpdateClientAuthenticationRequest{IsPublic: true},
			func(db data.Database) http.HandlerFunc {
				return apihandlers.HandleClientAuthenticationPut(db, &countingAuditLogger{}, configSwapped)
			})
		db.finished()

		stored := storedClient(t, client)
		assert.True(t, stored.IsPublic, "the switch to public was lost")
		assert.Empty(t, stored.ClientSecretEncrypted, "the client secret the switch cleared was put back")
	}

	// The settings saves, each keeping its stored credential.
	newSettings := func(t *testing.T) *record.Settings {
		settings := initialSettings("Beside the sweep")
		settings.SMTPEnabled = true
		settings.SMTPHost = smtpHost
		settings.SMTPPort = smtpPort
		settings.SMTPEncryption = emaildelivery.SMTPEncryptionNone.String()
		settings.SMTPFromEmail = "noreply@example.com"
		password, err := oldKeyAlone.Encrypt("the smtp password")
		require.NoError(t, err)
		settings.SMTPPasswordEncrypted = password
		settings.TurnstileEnabled = true
		settings.TurnstileSiteKey = "1x00000000000000000000AA"
		secretKey, err := oldKeyAlone.Encrypt("the turnstile secret key")
		require.NoError(t, err)
		settings.TurnstileSecretKeyEncrypted = secretKey
		require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))
		// What the request reads at its start.
		read, err := h.DB.GetSettingsByID(ctx, nil, settings.ID)
		require.NoError(t, err)
		return read
	}
	settingsPut := func(t *testing.T, handler http.HandlerFunc, route string, body any, settings *record.Settings) *record.Settings {
		t.Helper()
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, adminRequest(t, http.MethodPut, "/api/v1/admin/settings/"+route, body, settings))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		stored, err := h.DB.GetSettingsByID(ctx, nil, settings.ID)
		require.NoError(t, err)
		return stored
	}
	emailSave := func(t *testing.T, point sweepPoint) {
		settings := newSettings(t)
		db := &sweepDuring{Database: h.DB, t: t, point: point}
		stored := settingsPut(t, apihandlers.HandleSettingsEmailPut(db, acceptingEmailValidator{}, &countingAuditLogger{}, configSwapped),
			"email", api.UpdateSettingsEmailRequest{
				SMTPEnabled: true, SMTPHost: smtpHost, SMTPPort: smtpPort,
				SMTPEncryption: emaildelivery.SMTPEncryptionNone.String(),
				SMTPFromName:   "Saved beside the sweep", SMTPFromEmail: "noreply@example.com",
			}, settings)
		db.finished()

		assert.Equal(t, "Saved beside the sweep", stored.SMTPFromName, "the email save was lost")
		underNewKey(t, stored.SMTPPasswordEncrypted, "the smtp password", "the kept SMTP password")
	}
	turnstileSave := func(t *testing.T, point sweepPoint) {
		settings := newSettings(t)
		db := &sweepDuring{Database: h.DB, t: t, point: point}
		stored := settingsPut(t, apihandlers.HandleSettingsTurnstilePut(db, &countingAuditLogger{}, configSwapped, acceptingSecretKeyChecker{}),
			"turnstile", api.UpdateSettingsTurnstileRequest{TurnstileEnabled: false, TurnstileSiteKey: settings.TurnstileSiteKey},
			settings)
		db.finished()

		assert.False(t, stored.TurnstileEnabled, "the Turnstile save was lost")
		underNewKey(t, stored.TurnstileSecretKeyEncrypted, "the turnstile secret key", "the kept Turnstile secret key")
	}

	for _, tc := range []struct {
		name  string
		write func(*testing.T, sweepPoint)
		holds sweepPoint
	}{
		{"a client save", clientSave, sweepWhileAcquireClientRowHolds},
		{"a client secret replacement", secretReplacement, sweepWhileUpdateClientHolds},
		{"a switch to public", switchToPublic, sweepWhileSetClientPublicHolds},
		{"an email save keeping its password", emailSave, sweepWhileAcquireSettingsRowHolds},
		{"a Turnstile save keeping its secret key", turnstileSave, sweepWhileAcquireSettingsRowHolds},
	} {
		t.Run(tc.name+", the sweep committing between its read and its save", func(t *testing.T) {
			tc.write(t, sweepBeforeTransaction)
		})
		t.Run(tc.name+", holding the row when the sweep reaches it", func(t *testing.T) {
			tc.write(t, tc.holds)
		})
	}
}

// A settings save keeping a credential neither of the servers' keys opens, with a sweep committing
// between the request's read and its save that repairs it: the sweep runs with the older key the
// credential was sealed under as its previous key, and moves it under the new key. The save then
// keeps the repaired credential rather than writing back the stale bytes its request read, which
// would leave a value no key opens after the sweep saw it under the new key (#492 decisions 4 and
// 10). Turning the Turnstile challenge off still goes through.
func TestReencryptStoredSecrets_ASettingsSaveKeepsACredentialTheSweepRepaired(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()
	smtpHost, smtpPort := smtpListener(t)

	newSettings := func(t *testing.T) *record.Settings {
		settings := initialSettings("A repaired credential")
		settings.SMTPEnabled = true
		settings.SMTPHost = smtpHost
		settings.SMTPPort = smtpPort
		settings.SMTPEncryption = emaildelivery.SMTPEncryptionNone.String()
		settings.SMTPFromEmail = "noreply@example.com"
		password, err := otherKeyAlone.Encrypt("the smtp password")
		require.NoError(t, err)
		settings.SMTPPasswordEncrypted = password
		settings.TurnstileEnabled = true
		settings.TurnstileSiteKey = "1x00000000000000000000AA"
		secretKey, err := otherKeyAlone.Encrypt("the turnstile secret key")
		require.NoError(t, err)
		settings.TurnstileSecretKeyEncrypted = secretKey
		require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))
		read, err := h.DB.GetSettingsByID(ctx, nil, settings.ID)
		require.NoError(t, err)
		return read
	}
	save := func(t *testing.T, handler http.HandlerFunc, route string, body any, settings *record.Settings) *record.Settings {
		t.Helper()
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, adminRequest(t, http.MethodPut, "/api/v1/admin/settings/"+route, body, settings))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		stored, err := h.DB.GetSettingsByID(ctx, nil, settings.ID)
		require.NoError(t, err)
		return stored
	}
	underNewKey := func(t *testing.T, sealed []byte, want, what string) {
		t.Helper()
		opened, err := newKeyAlone.Decrypt(sealed)
		if assert.NoErrorf(t, err, "%s is not under the new key", what) {
			assert.Equalf(t, want, opened, "%s", what)
		}
	}

	t.Run("an email save keeping its password", func(t *testing.T) {
		settings := newSettings(t)
		db := &sweepDuring{Database: h.DB, t: t, point: sweepBeforeTransaction, previousKey: sweepOtherKey}
		stored := save(t, apihandlers.HandleSettingsEmailPut(db, acceptingEmailValidator{}, &countingAuditLogger{}, configSwapped),
			"email", api.UpdateSettingsEmailRequest{
				SMTPEnabled: true, SMTPHost: smtpHost, SMTPPort: smtpPort,
				SMTPEncryption: emaildelivery.SMTPEncryptionNone.String(),
				SMTPFromName:   "Saved after the repair", SMTPFromEmail: "noreply@example.com",
			}, settings)
		db.finished()

		assert.Equal(t, "Saved after the repair", stored.SMTPFromName, "the email save was lost")
		underNewKey(t, stored.SMTPPasswordEncrypted, "the smtp password", "the repaired SMTP password")
	})
	t.Run("a Turnstile save turning the challenge off", func(t *testing.T) {
		settings := newSettings(t)
		db := &sweepDuring{Database: h.DB, t: t, point: sweepBeforeTransaction, previousKey: sweepOtherKey}
		stored := save(t, apihandlers.HandleSettingsTurnstilePut(db, &countingAuditLogger{}, configSwapped, acceptingSecretKeyChecker{}),
			"turnstile", api.UpdateSettingsTurnstileRequest{TurnstileEnabled: false, TurnstileSiteKey: settings.TurnstileSiteKey},
			settings)
		db.finished()

		assert.False(t, stored.TurnstileEnabled, "the Turnstile save was lost")
		underNewKey(t, stored.TurnstileSecretKeyEncrypted, "the turnstile secret key", "the repaired Turnstile secret key")
	})
}

// An email verification across a re-seal (#492 decision 11): the sweep commits between the
// handler's comparison of the code and its conditional write, which then misses. The right code
// still verifies; a code replaced or an address changed in the same gap is still refused.
func TestReencryptStoredSecrets_AcrossAnEmailVerification(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()
	const code = "ABCD2345"

	pendingUser := func(t *testing.T) *record.User {
		sealed, err := oldKeyAlone.Encrypt(code)
		require.NoError(t, err)
		user := &record.User{
			Subject: fake.UUID(), Username: fake.Username(), Email: fake.Email(), PasswordHash: "x", Enabled: true,
			EmailVerificationCodeEncrypted: sealed,
			EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}
		require.NoError(t, h.DB.CreateUser(ctx, nil, user))
		return user
	}
	verify := func(t *testing.T, db data.Database, user *record.User) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(api.VerifyAccountEmailRequest{VerificationCode: code})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification", bytes.NewReader(body))
		reqCtx := reqctx.WithSettings(req.Context(), &record.Settings{ID: 1, SMTPEnabled: true})
		reqCtx = reqctx.WithValidatedToken(reqCtx, oauth.JWTToken{Claims: map[string]interface{}{
			"sub": user.Subject, "scope": "authserver:manage-account",
		}})
		rr := httptest.NewRecorder()
		apihandlers.HandleAccountEmailVerificationPost(db, &countingAuditLogger{}, uncountedFailures{}, configSwapped).
			ServeHTTP(rr, req.WithContext(reqCtx))
		return rr
	}
	storedUser := func(t *testing.T, user *record.User) *record.User {
		stored, err := h.DB.GetUserByID(ctx, nil, user.ID)
		require.NoError(t, err)
		return stored
	}
	refused := func(t *testing.T, rr *httptest.ResponseRecorder) {
		t.Helper()
		require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
		var refusal api.ErrorResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refusal))
		assert.Equal(t, "INVALID_OR_EXPIRED_VERIFICATION_CODE", refusal.ErrorCode)
	}

	t.Run("the right code verifies", func(t *testing.T) {
		user := pendingUser(t)
		db := &sweepDuring{Database: h.DB, t: t, point: sweepBeforeVerification}

		rr := verify(t, db, user)

		assert.Equal(t, 1, db.finished().Reencrypted, "the sweep sealed the pending code again in the gap")
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		stored := storedUser(t, user)
		assert.True(t, stored.EmailVerified, "the address is verified")
		assert.Empty(t, stored.EmailVerificationCodeEncrypted, "the code is spent")
	})

	t.Run("a code replaced in the gap is refused", func(t *testing.T) {
		user := pendingUser(t)
		replacement, err := configSwapped.Encrypt("WXYZ6789")
		require.NoError(t, err)
		db := &sweepDuring{Database: h.DB, t: t, point: sweepBeforeVerification, gap: func() {
			stored, storeErr := h.DB.TryStoreEmailVerificationCode(ctx, nil, user.ID, user.Email, replacement,
				time.Now().UTC(), time.Now().UTC())
			require.NoError(t, storeErr)
			require.True(t, stored, "the new send stored its code")
		}}

		rr := verify(t, db, user)

		assert.Equal(t, 1, db.finished().Reencrypted, "the sweep sealed the pending code again in the gap")
		refused(t, rr)
		stored := storedUser(t, user)
		assert.False(t, stored.EmailVerified)
		opened, err := newKeyAlone.Decrypt(stored.EmailVerificationCodeEncrypted)
		require.NoError(t, err)
		assert.Equal(t, "WXYZ6789", opened, "the replacement code stays pending")
	})

	t.Run("an address changed in the gap is refused", func(t *testing.T) {
		user := pendingUser(t)
		moved := fake.Email()
		db := &sweepDuring{Database: h.DB, t: t, point: sweepBeforeVerification, gap: func() {
			changed, changeErr := h.DB.TrySetUserEmail(ctx, nil, user.ID, user.Email, false, moved)
			require.NoError(t, changeErr)
			require.True(t, changed, "the email change committed")
		}}

		rr := verify(t, db, user)

		assert.Equal(t, 1, db.finished().Reencrypted, "the sweep sealed the pending code again in the gap")
		refused(t, rr)
		stored := storedUser(t, user)
		assert.Equal(t, moved, stored.Email)
		assert.False(t, stored.EmailVerified, "the moved address is not verified by the old one's code")
	})
}
