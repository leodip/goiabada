package datafactory

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// keyRotationStore is what the startup task reads and writes: the signing keys, one of which is
// the canary, and the re-key the decision ends in.
type keyRotationStore interface {
	GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]record.KeyPair, error)
	ReencryptToKey(ctx context.Context, oldKey, newKey []byte) error
}

// runStartupDataTasks is everything that has to happen to the stored data after the migration
// chain and before either application serves a request. One thing is left: the optional
// env-to-env key rotation. The email lowercase pass went in #351, which made it migration 000047
// and a pre-flight that runs BEFORE the chain rather than after it; the one-shot move of the data
// key out of the database and the TOTP secret encryption pass (#82) went in #359, which deleted
// both 1.5.x conversions and set the policy that an upgrade must pass through 1.6.x (#262).
//
// So this function reads no settings at all. Nothing here is allowed to re-add a settings read:
// the legacy key column is the conversion's, not rotation's, and startup_tasks_test.go asserts
// GetSettingsById is never called.
//
// THE REMAINING TASK IS FAIL-CLOSED, and that is the property this function exists to make
// testable rather than merely true. It returns an error that must stop startup, because it leaves
// the data half-converted when it fails: secrets re-keyed under a key the running process does not
// hold are a set of clients and accounts that silently cannot be used. NewDatabase builds a real
// database out of global configuration, so no test can drive it into that branch; extracted, the
// branch is one mock call away.
//
// The keys are parameters rather than config reads for the same reason. The caller has already
// validated envKey as 32 bytes; previousKey is optional and is acted on only at that length.
func runStartupDataTasks(ctx context.Context, database keyRotationStore, envKey []byte, previousKey []byte) error {
	// A start asked to stop does not begin the rotation, and one that has begun runs to its end
	// whatever the stop: the re-key is one transaction, and a rotation cut short would only have to
	// begin again at the next start (#390 decision 9).
	if stopErr := ctx.Err(); stopErr != nil {
		return errs.Wrap(stopErr, "the start was stopped before the data key rotation")
	}
	rotated, err := rotateDataKeyIfNeeded(context.WithoutCancel(ctx), database, envKey, previousKey)
	if err != nil {
		return errs.Wrap(err, "AES data key rotation failed")
	}
	if rotated {
		slog.InfoContext(ctx, "rotated data-at-rest encryption to the new GOIABADA_AES_ENCRYPTION_KEY")
	}
	return nil
}

// rotateDataKeyIfNeeded is the env-to-env rotation of the data key (#83): given the current key and
// an optional previous one, it decides whether the stored data is already under the current key
// (nothing to do) or still under the previous one (re-key it), and reports whether it re-keyed.
//
// Detection uses a canary, the first non-empty RSA private key PEM, which is encrypted and always
// present once the database is seeded. Reading it first is what makes the task idempotent, so
// GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS can be left set across restarts: after the first startup the
// canary opens under the current key and nothing is re-keyed again.
//
// It answers false and touches nothing when the previous key is absent, not 32 bytes, or equal to
// the current one, and when no key pair holds a PEM yet (a database not yet seeded). A canary that
// opens under neither key is a misconfiguration and is refused, rather than guessed at by re-keying
// data the process cannot prove it can read.
//
// The canary is read outside ReencryptToKey's transaction, exactly as it was when the decision and
// the re-key were one method in commondb. The decision moved here so that each branch is one mock
// call away rather than four engines away; what it decides, and when, did not change (#438
// decision 8).
func rotateDataKeyIfNeeded(ctx context.Context, database keyRotationStore, currentKey, previousKey []byte) (bool, error) {
	if len(previousKey) != 32 || bytes.Equal(previousKey, currentKey) {
		return false, nil
	}

	keys, err := database.GetAllSigningKeys(ctx, nil)
	if err != nil {
		return false, errs.Wrap(err, "unable to load signing keys for rotation check")
	}
	var canary []byte
	for _, k := range keys {
		if len(k.PrivateKeyPEM) > 0 {
			canary = k.PrivateKeyPEM
			break
		}
	}
	if canary == nil {
		return false, nil // no encrypted data yet
	}

	if _, err := encryption.DecryptText(canary, currentKey); err == nil {
		return false, nil // already encrypted under the current key
	}
	if _, err := encryption.DecryptText(canary, previousKey); err != nil {
		return false, errs.New(
			"data-at-rest decrypts under neither GOIABADA_AES_ENCRYPTION_KEY nor GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS")
	}

	if err := database.ReencryptToKey(ctx, previousKey, currentKey); err != nil {
		return false, err
	}
	return true, nil
}
