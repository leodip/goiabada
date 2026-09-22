// Package signingkeys owns the auth server's token-signing keys across their whole life: minted
// here by NewKeyPair, rotated here by SigningKeyRotator, read here by TokenParser to verify a
// token, and decrypted here by ParsePrivateKey to sign one.
package signingkeys

import (
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/rsakey"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/errs"
)

// NewKeyPair builds an RS256 signing key of the given size in the given state, as the unsaved row
// the key set stores: a fresh key identifier, shared by the row and its JWK, and the private key
// encrypted at rest with the process data cipher (#83), so encryption.InitDataCipher must have run.
// It writes nothing.
//
// It is the one path to a key pair: the rotator's replacement key and the seeder's first two are
// all built here, where each used to assemble its own (#424).
func NewKeyPair(state models.KeyState, bits int) (*models.KeyPair, error) {
	kid := uuidutil.New()

	material, err := rsakey.Generate(bits, kid)
	if err != nil {
		return nil, err
	}

	privateKeyPEMEncrypted, err := encryption.EncryptData(string(material.PrivateKeyPEM))
	if err != nil {
		return nil, errs.Wrap(err, "unable to encrypt the private key")
	}

	return &models.KeyPair{
		State:             state.String(),
		KeyIdentifier:     kid,
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     privateKeyPEMEncrypted,
		PublicKeyPEM:      material.PublicKeyPEM,
		PublicKeyASN1_DER: material.PublicKeyDER,
		PublicKeyJWK:      material.PublicKeyJWK,
	}, nil
}
