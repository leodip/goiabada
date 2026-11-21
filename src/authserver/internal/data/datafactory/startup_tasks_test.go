package datafactory

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The three keys of the check's table. Distinct, 32 bytes each, so a signing key sealed under any
// one of them opens under that one alone.
var (
	currentKey  = bytes.Repeat([]byte{0x11}, 32)
	previousKey = bytes.Repeat([]byte{0x22}, 32)
	unknownKey  = bytes.Repeat([]byte{0x33}, 32)
)

const (
	signingKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\nnot a real key, only what the check opens\n-----END RSA PRIVATE KEY-----"
	// stillUnderPreviousRecord is the Warn record a start writes when the current signing key is
	// under the previous data key (#492 decision 6).
	stillUnderPreviousRecord = "the stored data is still under the previous data encryption key: " +
		"run goiabada-authserver reencrypt before removing GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS"
	neitherKeyRefusal = "the data encryption key check failed: " +
		"data-at-rest decrypts under neither GOIABADA_AES_ENCRYPTION_KEY nor GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS: " +
		"the stored data does not decrypt under GOIABADA_AES_ENCRYPTION_KEY"
	currentKeyRefusal = "the data encryption key check failed: the stored data does not decrypt under GOIABADA_AES_ENCRYPTION_KEY"
)

// signingKeyUnder is a key pair in state whose PEM is real ciphertext under key, which is what the
// check opens: a stubbed decrypt would test the stub.
func signingKeyUnder(t *testing.T, state record.KeyState, key []byte) record.KeyPair {
	t.Helper()
	ciphertext, err := encryption.EncryptText(signingKeyPEM, key)
	require.NoError(t, err)
	return record.KeyPair{State: state.String(), PrivateKeyPEM: ciphertext}
}

// currentUnder is the current signing key sealed under key.
func currentUnder(t *testing.T, key []byte) record.KeyPair {
	t.Helper()
	return signingKeyUnder(t, record.KeyStateCurrent, key)
}

// expectNoSharedIdentifiers answers the startup warning's read with nothing, which every start
// that gets past the data key check makes.
func expectNoSharedIdentifiers(db *datamocks.Database) {
	db.EXPECT().GetIdentifiersSharedByClientsAndResources(mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()
}

// assertOnlyRead pins that a start called the two reads and nothing else: a start never
// re-encrypts, and never writes anything to the database (#492 decision 3).
func assertOnlyRead(t *testing.T, db *datamocks.Database) {
	t.Helper()
	assertCalled(t, db, "GetAllSigningKeys", "GetIdentifiersSharedByClientsAndResources")
}

// assertCalled pins the calls a start made, in order.
func assertCalled(t *testing.T, db *datamocks.Database, methods ...string) {
	t.Helper()
	var called []string
	for _, c := range db.Calls {
		called = append(called, c.Method)
	}
	assert.Equal(t, methods, called, "a start reads, and writes nothing")
}

// TestRunStartupDataTasks_ChecksTheKeyWithoutAUsablePreviousKey pins what a start does with no
// previous key, or one it ignores: it still reads the current signing key, so a key that opens
// nothing stops the start with ErrDataKeyMismatch, where before nothing was read and the first token
// request answered 500 (#542). A current signing key under the current data key, and a database
// not yet seeded, pass.
func TestRunStartupDataTasks_ChecksTheKeyWithoutAUsablePreviousKey(t *testing.T) {
	previousKeys := []struct {
		name     string
		previous []byte
	}{
		{"no previous key", nil},
		{"a previous key of the wrong length", []byte("too short")},
		{"a previous key equal to the current one", bytes.Clone(currentKey)},
	}
	stored := []struct {
		name     string
		keys     func(t *testing.T) []record.KeyPair
		mismatch bool
	}{
		{"the current signing key under the current key", func(t *testing.T) []record.KeyPair {
			return []record.KeyPair{currentUnder(t, currentKey)}
		}, false},
		{"a database not yet seeded", func(*testing.T) []record.KeyPair { return nil }, false},
		{"the current signing key under another key", func(t *testing.T) []record.KeyPair {
			return []record.KeyPair{currentUnder(t, unknownKey)}
		}, true},
	}
	for _, p := range previousKeys {
		for _, st := range stored {
			t.Run(p.name+", "+st.name, func(t *testing.T) {
				capture := logtest.CaptureSlog(t)
				db := datamocks.NewDatabase(t)
				keys := st.keys(t)
				db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(keys, nil).Once()
				if len(keys) == 0 {
					db.EXPECT().IsEmpty(mock.Anything).Return(true, nil).Once()
				}
				if !st.mismatch {
					expectNoSharedIdentifiers(db)
				}

				err := runStartupDataTasks(context.Background(), db, currentKey, p.previous)
				switch {
				case st.mismatch:
					require.ErrorIs(t, err, ErrDataKeyMismatch, "a key that opens nothing must stop the start")
					assert.Equal(t, currentKeyRefusal, err.Error(), "the troubleshooting page quotes this text whole")
				case len(keys) == 0:
					require.NoError(t, err)
					assertCalled(t, db, "GetAllSigningKeys", "IsEmpty", "GetIdentifiersSharedByClientsAndResources")
				default:
					require.NoError(t, err)
					assertOnlyRead(t, db)
				}
				assert.Empty(t, recordsNamed(capture, stillUnderPreviousRecord), "no previous key took part, so none is warned of")
			})
		}
	}
}

// TestRunStartupDataTasks_AcceptsTheCurrentSigningKeyUnderThePreviousKey pins the start in the
// middle of a rotation (#492 decision 6): the current signing key is still under the previous data
// key, so the stored data has not all been moved yet. The start goes on, and says so once, at
// Warn, naming the command that moves it. It re-encrypts nothing: that is the reencrypt command's
// job, run when the operator knows every auth server holds the swapped keys (#492 decision 3).
func TestRunStartupDataTasks_AcceptsTheCurrentSigningKeyUnderThePreviousKey(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	db := datamocks.NewDatabase(t)
	db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
		Return([]record.KeyPair{currentUnder(t, previousKey)}, nil).Once()
	expectNoSharedIdentifiers(db)

	require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, previousKey),
		"a start between the swap and the end of reencrypt serves")

	warned := recordsNamed(capture, stillUnderPreviousRecord)
	require.Len(t, warned, 1, "one record says the data is still under the previous key")
	assert.Equal(t, slog.LevelWarn, warned[0].Level, "removing the previous key now would stop the next start, so Warn")
	assertOnlyRead(t, db)
}

// TestRunStartupDataTasks_TheCurrentSigningKeyIsTheOneRead pins which stored value the check
// opens: the current signing key, wherever the database returns it among the others (#492
// decision 6). reencrypt moves the signing keys last and the current one last of all, so a sweep
// stopped with only the current signing key left to move has every other signing key under the
// new data key: a check of whichever key came first would pass it by row order, and a start with
// the previous key removed would then serve secrets it cannot open. The other states are never
// opened, so one neither key opens does not stop a start whose current signing key opens.
func TestRunStartupDataTasks_TheCurrentSigningKeyIsTheOneRead(t *testing.T) {
	interrupted := func(t *testing.T) []record.KeyPair {
		return []record.KeyPair{
			signingKeyUnder(t, record.KeyStatePrevious, currentKey),
			signingKeyUnder(t, record.KeyStateNext, currentKey),
			currentUnder(t, previousKey),
		}
	}
	orders := map[string][]int{
		"the current signing key last":    {0, 1, 2},
		"the current signing key first":   {2, 0, 1},
		"the current signing key between": {1, 2, 0},
	}

	for name, order := range orders {
		reordered := func(t *testing.T, keys []record.KeyPair) []record.KeyPair {
			out := make([]record.KeyPair, 0, len(keys))
			for _, i := range order {
				out = append(out, keys[i])
			}
			return out
		}

		t.Run(name+": a sweep that stopped before it, with the previous key removed, is refused", func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(reordered(t, interrupted(t)), nil).Once()

			err := runStartupDataTasks(context.Background(), db, currentKey, nil)

			require.ErrorIs(t, err, ErrDataKeyMismatch)
			assert.Equal(t, currentKeyRefusal, err.Error())
		})

		t.Run(name+": the same database with the previous key set serves and warns", func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			db := datamocks.NewDatabase(t)
			db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(reordered(t, interrupted(t)), nil).Once()
			expectNoSharedIdentifiers(db)

			require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, previousKey))
			assert.Len(t, recordsNamed(capture, stillUnderPreviousRecord), 1)
		})

		t.Run(name+": another signing key neither key opens does not stop the start", func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			db := datamocks.NewDatabase(t)
			db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(reordered(t, []record.KeyPair{
				signingKeyUnder(t, record.KeyStatePrevious, unknownKey),
				signingKeyUnder(t, record.KeyStateNext, previousKey),
				currentUnder(t, currentKey),
			}), nil).Once()
			expectNoSharedIdentifiers(db)

			require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, nil),
				"a damaged key that signs nothing is not the one the server serves with")
			assert.Empty(t, recordsNamed(capture, stillUnderPreviousRecord),
				"the current signing key is under the current data key, whatever the next one is under")
		})
	}
}

// TestRunStartupDataTasks_NoSigningKeyToReadPassesUnchecked pins the database not yet seeded: with
// no signing key and no settings row there is nothing encrypted to check, and the start goes on to
// seed it.
func TestRunStartupDataTasks_NoSigningKeyToReadPassesUnchecked(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()
	db.EXPECT().IsEmpty(mock.Anything).Return(true, nil).Once()
	expectNoSharedIdentifiers(db)

	require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, previousKey))
	assertCalled(t, db, "GetAllSigningKeys", "IsEmpty", "GetIdentifiersSharedByClientsAndResources")
}

// TestRunStartupDataTasks_RefusesASetUpDatabaseWithNoUsableCurrentSigningKey: a database that has
// been set up and holds no current signing key with a private key is refused, rather than passed
// as one not yet seeded: the seed, seeing the settings row, would put no key back, and the server
// would become ready unable to sign a token. Whether the database is seeded is asked only when it
// holds no signing key at all, which is the one shape the signing keys cannot tell apart.
func TestRunStartupDataTasks_RefusesASetUpDatabaseWithNoUsableCurrentSigningKey(t *testing.T) {
	cases := []struct {
		name      string
		keys      func(t *testing.T) []record.KeyPair
		asksEmpty bool
		want      string
	}{
		{"the current signing key holding no PEM", func(t *testing.T) []record.KeyPair {
			return []record.KeyPair{{State: record.KeyStateCurrent.String()}, signingKeyUnder(t, record.KeyStateNext, currentKey)}
		}, false, "the current signing key's private key is empty"},
		{"other signing keys and no current one", func(t *testing.T) []record.KeyPair {
			return []record.KeyPair{signingKeyUnder(t, record.KeyStateNext, currentKey), signingKeyUnder(t, record.KeyStatePrevious, currentKey)}
		}, false, "no signing key is in the current state"},
		{"no signing key, the settings row seeded", func(*testing.T) []record.KeyPair { return nil },
			true, "the database holds no signing key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(tc.keys(t), nil).Once()
			if tc.asksEmpty {
				db.EXPECT().IsEmpty(mock.Anything).Return(false, nil).Once()
			}

			err := runStartupDataTasks(context.Background(), db, currentKey, previousKey)

			require.ErrorIs(t, err, ErrNoCurrentSigningKey)
			require.NotErrorIs(t, err, ErrDataKeyMismatch, "no key failed to open anything")
			assert.Equal(t, "the data encryption key check failed: "+tc.want+": "+ErrNoCurrentSigningKey.Error(), err.Error())
		})
	}

	t.Run("a failed read of whether the database is seeded stops startup", func(t *testing.T) {
		boom := errors.New("storage is unavailable")
		db := datamocks.NewDatabase(t)
		db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()
		db.EXPECT().IsEmpty(mock.Anything).Return(false, boom).Once()

		err := runStartupDataTasks(context.Background(), db, currentKey, previousKey)

		require.ErrorIs(t, err, boom)
		assert.Contains(t, err.Error(), "the data encryption key check failed")
	})
}

// TestRunStartupDataTasks_IsFailClosed pins the boundary every start crosses exactly once, before
// it serves anything: a start that cannot show its keys open the stored data stops rather than run
// on data it cannot read. Each refusal keeps the outer "the data encryption key check failed", the
// one message an operator gets.
func TestRunStartupDataTasks_IsFailClosed(t *testing.T) {
	t.Run("the current signing key under neither key is refused", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
			Return([]record.KeyPair{currentUnder(t, unknownKey)}, nil).Once()

		err := runStartupDataTasks(context.Background(), db, currentKey, previousKey)

		require.ErrorIs(t, err, ErrDataKeyMismatch)
		assert.Equal(t, neitherKeyRefusal, err.Error(),
			"the refusal names both variables, because one of them is what the operator has to fix, "+
				"and the troubleshooting page quotes this text whole")
	})

	t.Run("a failed read of the signing keys stops startup", func(t *testing.T) {
		boom := errors.New("storage is unavailable")
		db := datamocks.NewDatabase(t)
		db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(nil, boom).Once()

		err := runStartupDataTasks(context.Background(), db, currentKey, previousKey)

		require.ErrorIs(t, err, boom, "a signing key nobody could read is not one that opened")
		assert.Contains(t, err.Error(), "the data encryption key check failed")
	})
}

// TestRunStartupDataTasks_AStopBeforeTheCheckReadsNothing is #390 decision 9 for the data key
// check: a shutdown signal during startup does not start it.
func TestRunStartupDataTasks_AStopBeforeTheCheckReadsNothing(t *testing.T) {
	db := datamocks.NewDatabase(t)
	ctx, stop := context.WithCancel(context.Background())
	stop()

	err := runStartupDataTasks(ctx, db, currentKey, previousKey)

	require.ErrorIs(t, err, context.Canceled, "the start was asked to stop, and says so in a way it can match")
	assert.Empty(t, db.Calls, "nothing was read")
}

// sharedIdentifierRecord is the message of the startup warning about a client and a resource
// sharing an identifier (#151).
const sharedIdentifierRecord = "a client and a resource share an identifier"

// TestRunStartupDataTasks_WarnsOfEachIdentifierAClientAndAResourceShare pins the startup warning of
// #151: one Warn record per identifier that both a client and a resource hold, naming it as both,
// and none when there is no such identifier. The admin API refuses a new pair, so these are pairs
// stored before that check or landed by two overlapping writes, which the start names rather than
// refuses.
func TestRunStartupDataTasks_WarnsOfEachIdentifierAClientAndAResourceShare(t *testing.T) {
	cases := []struct {
		name   string
		shared []string
	}{
		{"no shared identifier", nil},
		{"one shared identifier", []string{"myapp"}},
		{"two shared identifiers", []string{"billing", "myapp"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			db := datamocks.NewDatabase(t)
			db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
				Return([]record.KeyPair{currentUnder(t, currentKey)}, nil).Once()
			db.EXPECT().GetIdentifiersSharedByClientsAndResources(mock.Anything, (*sql.Tx)(nil)).Return(tc.shared, nil).Once()

			require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, nil),
				"a shared identifier is warned of, never refused")

			var warned []string
			for _, logRecord := range recordsNamed(capture, sharedIdentifierRecord) {
				assert.Equal(t, slog.LevelWarn, logRecord.Level)
				assert.Equal(t, logRecord.Attrs["client_identifier"], logRecord.Attrs["resource_identifier"],
					"the record names the identifier as the client's and as the resource's")
				identifier, _ := logRecord.Attrs["client_identifier"].(string)
				warned = append(warned, identifier)
			}
			assert.Equal(t, tc.shared, warned, "one record per shared identifier, in the order read")
		})
	}
}

// TestRunStartupDataTasks_AFailedSharedIdentifierReadDoesNotStopTheStart pins that the warning is
// not fail-closed: it changes nothing, so a read of it that fails is logged at Warn and the start
// goes on.
func TestRunStartupDataTasks_AFailedSharedIdentifierReadDoesNotStopTheStart(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	db := datamocks.NewDatabase(t)
	db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
		Return([]record.KeyPair{currentUnder(t, currentKey)}, nil).Once()
	boom := errors.New("storage is unavailable")
	db.EXPECT().GetIdentifiersSharedByClientsAndResources(mock.Anything, (*sql.Tx)(nil)).Return(nil, boom).Once()

	require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, nil))

	failed := recordsNamed(capture, "unable to check for identifiers shared by a client and a resource")
	require.Len(t, failed, 1, "the failed read is said once")
	assert.Equal(t, slog.LevelWarn, failed[0].Level)
	assert.NotNil(t, failed[0].Attrs["error"], "and carries the error")
}
