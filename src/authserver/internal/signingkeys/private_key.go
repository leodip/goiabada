package signingkeys

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// ParsePrivateKey decrypts a key pair's stored private-key PEM with the data cipher it is given
// and parses it into an *rsa.PrivateKey for signing.
//
// It is here rather than on record.KeyPair, where it was a method until #387, because decrypting
// and parsing a key is a capability and record.KeyPair is a persistence record: the row as it is
// stored. A method doing this on the record put a cipher and a JWT library behind every package
// that names a stored row, and the record then answered a question — what does this key sign? —
// that nothing about being a row can answer. This package already owns the other two halves of the
// same capability, key-pair generation in Rotator and public-key lookup in TokenParser,
// so the private key's one read belongs beside them.
//
// A failure says which of the two steps failed, names the key by the kid /certs publishes, and
// keeps the cause after it. A key no configured data key opens is usually a missing or wrong
// GOIABADA_AES_ENCRYPTION_KEY or GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS, most often mid-rotation,
// while a parse failure is the stored key itself; each caller passes the error on as it is.
func ParsePrivateKey(dataCipher *encryption.DataCipher, keyPair *record.KeyPair) (*rsa.PrivateKey, error) {
	pem, err := dataCipher.Decrypt(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errs.Wrapf(err, "unable to decrypt signing key %s", keyPair.KeyIdentifier)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pem))
	if err != nil {
		return nil, errs.Wrapf(err, "signing key %s decrypts, but it is not an RSA private key PEM",
			keyPair.KeyIdentifier)
	}
	return privateKey, nil
}
