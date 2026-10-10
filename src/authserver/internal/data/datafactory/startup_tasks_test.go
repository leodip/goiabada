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

// The three keys of the rotation table. Distinct, 32 bytes each, so the canary under any one of
// them opens under that one alone.
var (
	currentKey  = bytes.Repeat([]byte{0x11}, 32)
	previousKey = bytes.Repeat([]byte{0x22}, 32)
	unknownKey  = bytes.Repeat([]byte{0x33}, 32)
)

const (
	canaryPEM     = "-----BEGIN RSA PRIVATE KEY-----\nnot a real key, only a canary\n-----END RSA PRIVATE KEY-----"
	rotatedRecord = "rotated data-at-rest encryption to the new GOIABADA_AES_ENCRYPTION_KEY"
)

// canaryUnder is a key pair whose PEM is real ciphertext under key, which is what the decision
// reads: a stubbed decrypt would test the stub.
func canaryUnder(t *testing.T, key []byte) record.KeyPair {
	t.Helper()
	ciphertext, err := encryption.EncryptText(canaryPEM, key)
	require.NoError(t, err)
	return record.KeyPair{PrivateKeyPEM: ciphertext}
}

// rotatedRecords counts the record a re-key writes, so the rows that must not re-key can say they
// wrote nothing either.
func rotatedRecords(capture *logtest.SlogCapture) []logtest.CapturedRecord {
	var found []logtest.CapturedRecord
	for _, logRecord := range capture.Records() {
		if logRecord.Message == rotatedRecord {
			found = append(found, logRecord)
		}
	}
	return found
}

// TestRunStartupDataTasks_ChecksTheKeyWithoutAUsablePreviousKey pins what a start does with no
// previous key to rotate from, or one it ignores: it still reads the canary, so a key that opens
// nothing stops the start with ErrDataKeyMismatch, where before nothing was read and the first token
// request answered 500 (#542). A canary under the current key, and a database not yet seeded, pass;
// nothing is ever re-keyed.
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
		{"a canary under the current key", func(t *testing.T) []record.KeyPair { return []record.KeyPair{canaryUnder(t, currentKey)} }, false},
		{"a database not yet seeded", func(*testing.T) []record.KeyPair { return nil }, false},
		{"a canary under another key", func(t *testing.T) []record.KeyPair { return []record.KeyPair{canaryUnder(t, unknownKey)} }, true},
	}
	for _, p := range previousKeys {
		for _, st := range stored {
			t.Run(p.name+", "+st.name, func(t *testing.T) {
				db := datamocks.NewDatabase(t)
				db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(st.keys(t), nil).Once()

				err := runStartupDataTasks(context.Background(), db, currentKey, p.previous)
				if st.mismatch {
					require.ErrorIs(t, err, ErrDataKeyMismatch, "a key that opens nothing must stop the start")
					assert.Contains(t, err.Error(), "GOIABADA_AES_ENCRYPTION_KEY")
				} else {
					require.NoError(t, err)
				}
				db.AssertNotCalled(t, "ReencryptToKey", mock.Anything, mock.Anything, mock.Anything)
			})
		}
	}
}

// TestRunStartupDataTasks_NothingToRotate pins the states in which the canary is read and the data
// is left alone: no key pair, key pairs holding no PEM, which is a database not yet seeded, and a
// canary already under the current key, which is every startup after the one that rotated. That
// last one is what makes leaving the previous key set across restarts safe.
func TestRunStartupDataTasks_NothingToRotate(t *testing.T) {
	cases := []struct {
		name string
		keys func(t *testing.T) []record.KeyPair
	}{
		{"no key pairs", func(*testing.T) []record.KeyPair { return nil }},
		{"key pairs holding no PEM", func(*testing.T) []record.KeyPair {
			return []record.KeyPair{{}, {PrivateKeyPEM: []byte{}}}
		}},
		{"a canary already under the current key", func(t *testing.T) []record.KeyPair {
			return []record.KeyPair{canaryUnder(t, currentKey)}
		}},
		// The canary is the FIRST non-empty PEM. The pair under an unknown key after it would be a
		// refusal if it were read; the empty one before it would be a refusal too, since it opens
		// under nothing, if emptiness were not skipped.
		{"the first non-empty PEM is the canary", func(t *testing.T) []record.KeyPair {
			return []record.KeyPair{{}, canaryUnder(t, currentKey), canaryUnder(t, unknownKey)}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			db := datamocks.NewDatabase(t)
			db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(tc.keys(t), nil).Once()

			require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, previousKey))
			db.AssertNotCalled(t, "ReencryptToKey", mock.Anything, mock.Anything, mock.Anything)
			assert.Empty(t, rotatedRecords(capture), "nothing was re-keyed, so nothing may say it was")
		})
	}
}

// TestRunStartupDataTasks_RotatesACanaryUnderThePreviousKey pins the one branch that writes: the
// re-key runs once, FROM the previous key TO the current one, and the startup says so at Info. The
// argument order is the whole risk here, because ReencryptToKey called the other way round would
// decrypt nothing and fail, or, on a database already rotated, rotate it back.
//
// It also reads no settings: the legacy key column is the 1.5.x conversion's, which #359 deleted
// (#262), and rotation never wanted it. This is what fails if someone re-adds the read.
func TestRunStartupDataTasks_RotatesACanaryUnderThePreviousKey(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	db := datamocks.NewDatabase(t)
	db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
		Return([]record.KeyPair{{}, canaryUnder(t, previousKey)}, nil).Once()
	db.EXPECT().ReencryptToKey(mock.Anything, previousKey, currentKey).Return(nil).Once()

	require.NoError(t, runStartupDataTasks(context.Background(), db, currentKey, previousKey))

	records := rotatedRecords(capture)
	require.Len(t, records, 1, "one rotation, one record")
	assert.Equal(t, slog.LevelInfo, records[0].Level, "a rotation is lifecycle, so Info")
	db.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything, mock.Anything)
}

// TestRunStartupDataTasks_IsFailClosed pins the boundary every application crosses exactly once,
// at startup, before it serves anything: a rotation that cannot proceed must stop the process
// rather than let it run on data it cannot read.
//
// Serving on data that is half re-keyed is worse than not serving: half the rows readable under
// the current key and half under the previous one is a database no single key opens. Each refusal
// keeps the outer "the data encryption key check failed", the one message an operator gets.
func TestRunStartupDataTasks_IsFailClosed(t *testing.T) {
	boom := errors.New("storage is unavailable")

	t.Run("a canary under neither key is refused and nothing is re-keyed", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
			Return([]record.KeyPair{canaryUnder(t, unknownKey)}, nil).Once()

		err := runStartupDataTasks(context.Background(), db, currentKey, previousKey)

		require.ErrorIs(t, err, ErrDataKeyMismatch, "re-keying data the process cannot prove it reads would corrupt it")
		assert.Contains(t, err.Error(), "the data encryption key check failed")
		assert.Contains(t, err.Error(),
			"data-at-rest decrypts under neither GOIABADA_AES_ENCRYPTION_KEY nor GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS",
			"the refusal names both variables, because one of them is what the operator has to fix")
		db.AssertNotCalled(t, "ReencryptToKey", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a failed read of the signing keys stops startup", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).Return(nil, boom).Once()

		err := runStartupDataTasks(context.Background(), db, currentKey, previousKey)

		require.ErrorIs(t, err, boom, "a canary nobody could read is not a canary that said nothing to do")
		assert.Contains(t, err.Error(), "the data encryption key check failed")
		db.AssertNotCalled(t, "ReencryptToKey", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a failed re-key stops startup", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		db := datamocks.NewDatabase(t)
		db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
			Return([]record.KeyPair{canaryUnder(t, previousKey)}, nil).Once()
		db.EXPECT().ReencryptToKey(mock.Anything, previousKey, currentKey).Return(boom).Once()

		err := runStartupDataTasks(context.Background(), db, currentKey, previousKey)

		require.ErrorIs(t, err, boom,
			"a rotation failure must stop startup: half the rows would read under the current key and half under the previous one")
		assert.Contains(t, err.Error(), "the data encryption key check failed")
		assert.Empty(t, rotatedRecords(capture), "a rotation that failed must not be reported as one that happened")
	})
}

// TestRunStartupDataTasks_AStopBeforeTheRotationStartsNothing and the case after it are #390
// decision 9 for the data-key rotation: a shutdown signal during startup does not start the
// rotation, and a rotation under way when it arrives runs to its end, since the re-key is one
// transaction and the next start would only have to begin it again.
func TestRunStartupDataTasks_AStopBeforeTheRotationStartsNothing(t *testing.T) {
	db := datamocks.NewDatabase(t)
	ctx, stop := context.WithCancel(context.Background())
	stop()

	err := runStartupDataTasks(ctx, db, currentKey, previousKey)

	require.ErrorIs(t, err, context.Canceled, "the start was asked to stop, and says so in a way it can match")
	db.AssertNotCalled(t, "GetAllSigningKeys", mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "ReencryptToKey", mock.Anything, mock.Anything, mock.Anything)
}

func TestRunStartupDataTasks_AStopDuringTheRotationLetsItFinish(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	db := datamocks.NewDatabase(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	// The stop arrives once the rotation has begun, with its read of the canary.
	db.EXPECT().GetAllSigningKeys(mock.Anything, (*sql.Tx)(nil)).
		Run(func(context.Context, *sql.Tx) { stop() }).
		Return([]record.KeyPair{canaryUnder(t, previousKey)}, nil).Once()
	var reencryptCtxErr error
	db.EXPECT().ReencryptToKey(mock.Anything, previousKey, currentKey).
		Run(func(ctx context.Context, _, _ []byte) { reencryptCtxErr = ctx.Err() }).
		Return(nil).Once()

	require.NoError(t, runStartupDataTasks(ctx, db, currentKey, previousKey))

	assert.NoError(t, reencryptCtxErr, "the re-key ran under a context the stop could not end")
	assert.Len(t, rotatedRecords(capture), 1, "and it finished, and said so")
}
