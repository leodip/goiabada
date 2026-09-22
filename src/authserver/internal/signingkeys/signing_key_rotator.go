package signingkeys

import (
	"context"
	"database/sql"
	"errors"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

// ErrRotationInProgress means a compare-and-set transitioned no row, so another rotation
// had already moved the key this one read. The caller lost the race and nothing was
// committed.
//
// Stdlib errors.New and not errs.New, which is the rule for every package-level sentinel in
// this tree: errs.New captures a stack where it is called, and a package-level var is called
// during init, so the frames would be runtime.doInit rather than the site that raised it. Worse,
// errs.WithStack is the identity on an error whose tree already carries a stack, so the
// WithStack below would silently record nothing. Matched with errors.Is, so it loses no
// diagnosis by having no frames of its own (#279 decision 5).
var ErrRotationInProgress = errors.New("another signing key rotation is in progress")

// ErrKeySetIncomplete means the current or the next key is missing. The rotation refused
// before writing anything, so the key set is exactly as it was found.
// Stdlib errors.New, for the reason ErrRotationInProgress above states (#279 decision 5).
var ErrKeySetIncomplete = errors.New("expected current and next signing keys to exist")

// RotationDatabase is what key rotation needs: the key rows it reads, advances and retires, in
// one transaction.
//
// Exported, unlike most ports here, because the settings endpoint that builds a rotator lives in
// apihandlers and its own port has to name this capability to hand it on (#386 decision 8).
type RotationDatabase interface {
	CreateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *models.KeyPair) error
	DeleteKeyPair(ctx context.Context, tx *sql.Tx, keyPairId int64) error
	GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]models.KeyPair, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdateKeyPairState(ctx context.Context, tx *sql.Tx, keyPairId int64, fromState string, toState string) (bool, error)
}

// SigningKeyRotator performs the current -> previous -> deleted transition of the signing
// keys, as one transaction whose every refusal happens before the commit.
//
// The reason it is a transaction, and the reason each state change is a compare-and-set
// rather than a plain update: the rotation is five writes, and two rotations running at
// once used to interleave so that the second deleted the previous key the first had just
// demoted. That key still signs live tokens, which /certs publishes and the token parser
// falls back to, so destroying it retires every token it signed. OIDC Core 10.1.1 says the
// JWK Set SHOULD retain recently decommissioned keys for a smooth transition, which is the
// entire reason the previous state exists (#251).
//
// Undoing either half reopens it. Without the transaction, the loser's delete is already
// committed by the time it discovers it lost; without the compare-and-set, it never
// discovers it lost at all and writes over the winner's transition.
//
// The transaction is opened through RunInTransaction, so a rotation the engine aborts as a
// deadlock victim is rerun; the rerun reads the key set afresh, and if it lost the race
// meanwhile its own compare-and-set refuses it (#301).
type SigningKeyRotator struct {
	database RotationDatabase
	// keySizeBits is unexported and has no setter, so no production caller can lower it.
	// It exists as a field only because the replacement key is now generated on every
	// path, including every refusal, and a 4096-bit generation costs about 300ms against
	// 7ms at 1024: in-package tests set it directly.
	keySizeBits int
}

func NewSigningKeyRotator(database RotationDatabase) *SigningKeyRotator {
	return &SigningKeyRotator{
		database:    database,
		keySizeBits: 4096,
	}
}

// Rotate demotes the current key to previous, promotes the next key to current, and
// creates a replacement next key, deleting the key that was previous. It returns
// ErrKeySetIncomplete when there is no current or no next key, and ErrRotationInProgress
// when another rotation won the race.
//
// The replacement key is generated before the transaction opens. That is deliberate: the
// generation is the slow step by three orders of magnitude, and holding a transaction open
// across it is what made the window wide enough to hit.
func (r *SigningKeyRotator) Rotate(ctx context.Context) error {

	newNextKey, err := NewKeyPair(models.KeyStateNext, r.keySizeBits)
	if err != nil {
		return err
	}

	// Opened through RunInTransaction, so a deadlock reruns the body (#301). A rerun reads the
	// key set again inside its own transaction, so one that lost the race in the meantime is
	// refused by its own compare-and-set exactly as a first run would be; the two sentinels are
	// not deadlocks, so they roll back once and surface unchanged. The replacement key is the
	// one value the body captures, and the id CreateKeyPair assigns onto it is reassigned by
	// the next attempt.
	return r.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		allSigningKeys, err := r.database.GetAllSigningKeys(ctx, tx)
		if err != nil {
			return err
		}

		var currentKey *models.KeyPair
		var nextKey *models.KeyPair
		var previousKey *models.KeyPair
		for i := range allSigningKeys {
			kp := &allSigningKeys[i]
			keyState, err := models.KeyStateFromString(kp.State)
			if err != nil {
				return err
			}
			switch keyState {
			case models.KeyStateCurrent:
				currentKey = kp
			case models.KeyStateNext:
				nextKey = kp
			case models.KeyStatePrevious:
				previousKey = kp
			}
		}

		// The guard runs before any write. It used to run after the delete below, so a
		// deployment with no next key lost its previous key and was then refused (#251).
		if currentKey == nil || nextKey == nil {
			return errs.WithStack(ErrKeySetIncomplete)
		}

		// The delete stays ahead of the demotion. Demoting while the old previous row is
		// still there would put two rows in the previous state within one statement, which
		// the unique index on key_pairs (state) refuses on every engine.
		if previousKey != nil {
			if err := r.database.DeleteKeyPair(ctx, tx, previousKey.Id); err != nil {
				return err
			}
		}

		moved, err := r.database.UpdateKeyPairState(ctx, tx, currentKey.Id,
			models.KeyStateCurrent.String(), models.KeyStatePrevious.String())
		if err != nil {
			return err
		}
		if !moved {
			return errs.WithStack(ErrRotationInProgress)
		}

		moved, err = r.database.UpdateKeyPairState(ctx, tx, nextKey.Id,
			models.KeyStateNext.String(), models.KeyStateCurrent.String())
		if err != nil {
			return err
		}
		if !moved {
			return errs.WithStack(ErrRotationInProgress)
		}

		return r.database.CreateKeyPair(ctx, tx, newNextKey)
	})
}
