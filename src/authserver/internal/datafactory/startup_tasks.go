package datafactory

import (
	"log/slog"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
)

// runStartupDataTasks is everything that has to happen to the stored data after the migration
// chain and before either application serves a request: the one-shot move of the data key out
// of the database, an optional env-to-env key rotation, and the TOTP secret encryption pass
// (#82). The email lowercase pass was the fourth until #351 made it migration 000047 and a
// pre-flight that runs BEFORE the chain rather than after it.
//
// EVERY ONE OF THEM IS FAIL-CLOSED, and that is the property this function exists to make
// testable rather than merely true. Each returns an error that must stop startup, because each
// leaves the data half-converted when it fails: a users table where some addresses are
// lowercase and some are not, served by an application whose credential paths look up only the
// lowercase form, is a set of accounts that silently cannot sign in. NewDatabase builds a real
// database out of global configuration, so no test can drive it into any of these branches;
// extracted, every branch is one mock call away.
//
// The keys are parameters rather than config reads for the same reason. The caller has already
// validated envKey as 32 bytes; previousKey is optional and is acted on only at that length.
func runStartupDataTasks(database data.Database, envKey []byte, previousKey []byte) error {

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		return errs.Wrap(err, "unable to load settings for encryption migration")
	}

	// Existing installs historically stored the data key in the DB. If it is
	// still there, re-encrypt everything to the env key (and encrypt the RSA
	// private keys), then blank the legacy column. Fail-closed and one-shot: the
	// re-encryption is a single transaction, so a failure retries cleanly. A
	// fresh DB has no settings row yet (seeding happens afterwards), so this is
	// skipped and the seeder encrypts directly with the env key.
	if settings != nil && len(settings.AESEncryptionKeyLegacy) == 32 {
		if err := database.ReencryptDataToNewKey(settings.AESEncryptionKeyLegacy, envKey); err != nil {
			return errs.Wrap(err, "failed to migrate data-at-rest encryption to GOIABADA_AES_ENCRYPTION_KEY")
		}
		slog.Info("migrated data-at-rest encryption (secrets and RSA signing keys) to GOIABADA_AES_ENCRYPTION_KEY")
	}

	// Env-to-env key rotation (issue #83): if a previous key is supplied and the
	// data is still encrypted under it, re-encrypt everything to the current key.
	// Idempotent (safe to leave the previous key set across restarts) and
	// fail-closed.
	if len(previousKey) == 32 {
		rotated, err := database.RotateEncryptionKeyIfNeeded(envKey, previousKey)
		if err != nil {
			return errs.Wrap(err, "AES data key rotation failed")
		}
		if rotated {
			slog.Info("rotated data-at-rest encryption to the new GOIABADA_AES_ENCRYPTION_KEY")
		}
	}

	// Encrypt any legacy plaintext TOTP secrets at rest (issue #82), now keyed by
	// the env key. Fail-closed, idempotent, resumable; a no-op on a fresh DB.
	migrated, err := database.BackfillEncryptedOTPSecrets(envKey)
	if err != nil {
		return errs.Wrap(err, "failed to encrypt legacy plaintext OTP secrets")
	}
	if migrated > 0 {
		slog.Info("encrypted legacy plaintext otp secrets at rest", "count", migrated)
	}

	return nil
}
