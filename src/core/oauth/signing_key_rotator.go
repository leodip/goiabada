package oauth

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/rsautil"
	"github.com/pkg/errors"
)

// ErrRotationInProgress means a compare-and-set transitioned no row, so another rotation
// had already moved the key this one read. The caller lost the race and nothing was
// committed.
var ErrRotationInProgress = errors.New("another signing key rotation is in progress")

// ErrKeySetIncomplete means the current or the next key is missing. The rotation refused
// before writing anything, so the key set is exactly as it was found.
var ErrKeySetIncomplete = errors.New("expected current and next signing keys to exist")

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
type SigningKeyRotator struct {
	database data.Database
	// keySizeBits is unexported and has no setter, so no production caller can lower it.
	// It exists as a field only because the replacement key is now generated on every
	// path, including every refusal, and a 4096-bit generation costs about 300ms against
	// 7ms at 1024: in-package tests set it directly.
	keySizeBits int
}

func NewSigningKeyRotator(database data.Database) *SigningKeyRotator {
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
func (r *SigningKeyRotator) Rotate() error {

	newNextKey, err := r.generateNextKey()
	if err != nil {
		return err
	}

	tx, err := r.database.BeginTransaction()
	if err != nil {
		return err
	}
	defer r.database.RollbackTransaction(tx) //nolint:errcheck

	allSigningKeys, err := r.database.GetAllSigningKeys(tx)
	if err != nil {
		return err
	}

	var currentKey *models.KeyPair
	var nextKey *models.KeyPair
	var previousKey *models.KeyPair
	for i := range allSigningKeys {
		kp := &allSigningKeys[i]
		keyState, err := enums.KeyStateFromString(kp.State)
		if err != nil {
			return err
		}
		switch keyState {
		case enums.KeyStateCurrent:
			currentKey = kp
		case enums.KeyStateNext:
			nextKey = kp
		case enums.KeyStatePrevious:
			previousKey = kp
		}
	}

	// The guard runs before any write. It used to run after the delete below, so a
	// deployment with no next key lost its previous key and was then refused (#251).
	if currentKey == nil || nextKey == nil {
		return errors.WithStack(ErrKeySetIncomplete)
	}

	// The delete stays ahead of the demotion. Demoting while the old previous row is still
	// there would put two rows in the previous state within one statement, which the unique
	// index on key_pairs (state) refuses on every engine.
	if previousKey != nil {
		if err := r.database.DeleteKeyPair(tx, previousKey.Id); err != nil {
			return err
		}
	}

	moved, err := r.database.UpdateKeyPairState(tx, currentKey.Id,
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String())
	if err != nil {
		return err
	}
	if !moved {
		return errors.WithStack(ErrRotationInProgress)
	}

	moved, err = r.database.UpdateKeyPairState(tx, nextKey.Id,
		enums.KeyStateNext.String(), enums.KeyStateCurrent.String())
	if err != nil {
		return err
	}
	if !moved {
		return errors.WithStack(ErrRotationInProgress)
	}

	if err := r.database.CreateKeyPair(tx, newNextKey); err != nil {
		return err
	}

	return r.database.CommitTransaction(tx)
}

// generateNextKey builds the replacement key, already in the next state. It writes nothing.
func (r *SigningKeyRotator) generateNextKey() (*models.KeyPair, error) {

	privateKey, err := rsautil.GeneratePrivateKey(r.keySizeBits)
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate a private key")
	}
	privateKeyPEM := rsautil.EncodePrivateKeyToPEM(privateKey)

	// Encrypt the private key at rest (issue #83) before storing it.
	privateKeyPEMEncrypted, err := encryption.EncryptData(string(privateKeyPEM))
	if err != nil {
		return nil, errors.Wrap(err, "unable to encrypt the private key")
	}

	publicKeyASN1DER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal public key to PKIX")
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicKeyASN1DER})

	kid := uuid.New().String()
	publicKeyJWK, err := rsautil.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal JWK")
	}

	return &models.KeyPair{
		State:             enums.KeyStateNext.String(),
		KeyIdentifier:     kid,
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     privateKeyPEMEncrypted,
		PublicKeyPEM:      publicKeyPEM,
		PublicKeyASN1_DER: publicKeyASN1DER,
		PublicKeyJWK:      publicKeyJWK,
	}, nil
}
