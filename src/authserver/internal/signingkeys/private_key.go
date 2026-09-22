package signingkeys

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// ParsePrivateKey decrypts a key pair's stored private-key PEM with the process data cipher
// (encryption.InitDataCipher must have run at startup) and parses it into an *rsa.PrivateKey for
// signing.
//
// It is here rather than on models.KeyPair, where it was a method until #387, because decrypting
// and parsing a key is a capability and models.KeyPair is a persistence record: the row as it is
// stored. A method doing this on the record put a cipher and a JWT library behind every package
// that names a stored row, and the record then answered a question — what does this key sign? —
// that nothing about being a row can answer. This package already owns the other two halves of the
// same capability, key-pair generation in SigningKeyRotator and public-key lookup in TokenParser,
// so the private key's one read belongs beside them.
//
// The error is returned as it arrives, from the cipher or from the parser, which is what the four
// call sites expect: each wraps or answers it in its own terms.
func ParsePrivateKey(keyPair *models.KeyPair) (*rsa.PrivateKey, error) {
	pem, err := encryption.DecryptData(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(pem))
}
