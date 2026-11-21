package datafactory

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// ErrDataKeyMismatch is stored data that GOIABADA_AES_ENCRYPTION_KEY does not decrypt, nor
// GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS when one is set: the key is not the one this database was set
// up with, or during a rotation the previous key was removed before reencrypt reached its end
// (#492 decision 6). Every start refuses it. A start that went on served 500s from the first token request,
// "cipher: message authentication failed", while /health answered 200, so on Kubernetes a pod given
// newly generated Secrets by mistake replaced the working ones; refused, it never becomes ready and
// the rollout waits with them still serving (#542).
var ErrDataKeyMismatch = errors.New("the stored data does not decrypt under GOIABADA_AES_ENCRYPTION_KEY")

// ErrNoCurrentSigningKey is a database that has been set up, its settings row seeded, but holds no
// current signing key with a private key: the row is gone, or its private key is empty. Every start
// refuses it, since a server that went on would listen and become ready while it could sign no
// token, and the seed, which sees the settings row, would not put a key back.
var ErrNoCurrentSigningKey = errors.New("the database is set up but holds no current signing key with a private key")

// signingKeyReader is what the data key check reads: the signing keys, among which the current
// one is the stored value it opens, and, only when there is no signing key at all, whether the
// database has been seeded yet.
type signingKeyReader interface {
	GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]record.KeyPair, error)
	IsEmpty(ctx context.Context) (bool, error)
}

// sharedIdentifierReader is what the startup warning reads: the identifiers a client and a
// resource both hold (#151).
type sharedIdentifierReader interface {
	GetIdentifiersSharedByClientsAndResources(ctx context.Context, tx *sql.Tx) ([]string, error)
}

// startupDataStore is what runStartupDataTasks takes: both tasks' ports. Each is a read: a start
// writes nothing to the stored data.
type startupDataStore interface {
	signingKeyReader
	sharedIdentifierReader
}

// runStartupDataTasks is everything that has to happen to the stored data after the migration
// chain and before either application serves a request. Two things are left: the check that the
// data keys open the stored data, and the warning about a client and a resource sharing an
// identifier. The email lowercase pass went in #351, which made it migration 000047
// and a pre-flight that runs BEFORE the chain rather than after it; the one-shot move of the data
// key out of the database and the TOTP secret encryption pass (#82) went in #359, which deleted
// both 1.5.x conversions and set the policy that an upgrade must pass through 1.6.x (#262). The
// re-encryption a start ran when the stored data was under the previous key went in #492: it is
// the reencrypt command's now, run when the operator knows every auth server holds the swapped
// keys, which a start cannot know (#492 decision 3).
//
// So this function writes nothing, and acts on no setting. It asks whether the settings row exists
// only when the database holds no signing key at all, to tell a database not yet seeded from one
// whose signing keys are gone; nothing here is allowed to act on what the row holds, since the
// legacy key column is the conversion's. startup_tasks_test.go asserts the two reads below are the
// only calls a start on a seeded database makes.
//
// THE CHECK IS FAIL-CLOSED, and that is the property this function exists to make testable rather
// than merely true. It returns an error that must stop startup: a server whose keys open none of
// the stored data answers 500 from its first token request while /health answers 200 (#542).
// NewDatabase builds a real database out of global configuration, so no test can drive it into that
// branch; extracted, the branch is one mock call away.
//
// The keys are parameters rather than config reads for the same reason. The caller has already
// validated envKey as 32 bytes; previousKey is optional and is acted on only at that length.
//
// The warning is not fail-closed: it changes nothing, and a failed read of it is logged and the
// start goes on. A start asked to stop by the time the check ends does not read it.
func runStartupDataTasks(ctx context.Context, database startupDataStore, envKey []byte, previousKey []byte) error {
	// A start asked to stop does not begin the check (#390 decision 9). One under way is a read,
	// which the stop ends, and the error it answers then matches context.Canceled.
	if stopErr := ctx.Err(); stopErr != nil {
		return errs.Wrap(stopErr, "the start was stopped before the data key check")
	}
	underPrevious, err := checkDataKey(ctx, database, envKey, previousKey)
	if err != nil {
		return errs.Wrap(err, "the data encryption key check failed")
	}
	if underPrevious {
		slog.WarnContext(ctx, "the stored data is still under the previous data encryption key: run goiabada-authserver reencrypt before removing GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS")
	}
	if ctx.Err() == nil {
		warnOfSharedIdentifiers(ctx, database)
	}
	return nil
}

// warnOfSharedIdentifiers logs one Warn record for every identifier a client and a resource both
// hold. The admin API refuses a new such pair (#151), but not one stored before that check, nor
// one two overlapping writes, one per table, landed past it, and renaming either side is a
// breaking change for the integrations using it, so the start names each pair for the operator
// rather than refusing it or renaming anything.
func warnOfSharedIdentifiers(ctx context.Context, database sharedIdentifierReader) {
	identifiers, err := database.GetIdentifiersSharedByClientsAndResources(ctx, nil)
	if err != nil {
		slog.WarnContext(ctx, "unable to check for identifiers shared by a client and a resource", "error", err)
		return
	}
	for _, identifier := range identifiers {
		slog.WarnContext(ctx, "a client and a resource share an identifier",
			"client_identifier", identifier,
			"resource_identifier", identifier)
	}
}

// checkDataKey checks the data keys against the stored data (#542, #492 decision 6): given the
// current key and an optional previous one, it answers whether the stored data is under the
// current key, still under the previous one (true), or under neither (ErrDataKeyMismatch).
//
// It opens one stored value, the current signing key, the one key the server cannot serve
// without. reencrypt moves the signing keys last and the current one last of all, so when the
// current signing key is under the current data key a sweep has been through everything else, and
// a start with the previous key removed before reencrypt reached its end is refused rather than
// serving with secrets it cannot open. It is a guard for that mistake, not a proof: reencrypt run
// with no previous key is the proof. The other signing keys are never opened, so a damaged one
// that signs nothing does not stop a start.
//
// Only a database not yet seeded, holding no signing key and no settings row, passes unchecked: the
// seed then writes both in one transaction. A database holding other signing keys but no current
// one with a PEM, or holding none while its settings row exists, has been set up and lost its
// current signing key, and is refused with ErrNoCurrentSigningKey. The settings row is asked about
// only when there is no signing key at all, so a seeded database's start still makes one read. A
// previous key that is not 32 bytes, or equals the current one, takes no part.
func checkDataKey(ctx context.Context, database signingKeyReader, currentKey, previousKey []byte) (bool, error) {
	keys, err := database.GetAllSigningKeys(ctx, nil)
	if err != nil {
		return false, errs.Wrap(err, "unable to load signing keys to check the data key")
	}
	var stored []byte
	foundCurrent := false
	for _, k := range keys {
		if k.State == record.KeyStateCurrent.String() {
			stored = k.PrivateKeyPEM
			foundCurrent = true
			break
		}
	}
	switch {
	case foundCurrent && len(stored) == 0:
		return false, errs.Wrap(ErrNoCurrentSigningKey, "the current signing key's private key is empty")
	case !foundCurrent && len(keys) > 0:
		return false, errs.Wrap(ErrNoCurrentSigningKey, "no signing key is in the current state")
	case !foundCurrent:
		empty, err := database.IsEmpty(ctx)
		if err != nil {
			return false, errs.Wrap(err, "unable to tell whether the database holding no signing key is seeded")
		}
		if empty {
			return false, nil // not yet seeded: no encrypted data yet
		}
		return false, errs.Wrap(ErrNoCurrentSigningKey, "the database holds no signing key")
	}

	if _, err := encryption.DecryptText(stored, currentKey); err == nil {
		return false, nil // under the current key
	}
	if len(previousKey) != 32 || bytes.Equal(previousKey, currentKey) {
		return false, errs.WithStack(ErrDataKeyMismatch)
	}
	if _, err := encryption.DecryptText(stored, previousKey); err != nil {
		return false, errs.Wrap(ErrDataKeyMismatch,
			"data-at-rest decrypts under neither GOIABADA_AES_ENCRYPTION_KEY nor GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS")
	}
	return true, nil
}
