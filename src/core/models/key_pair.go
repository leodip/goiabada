package models

import (
	"crypto/rsa"
	"database/sql"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/encryption"
)

type KeyPair struct {
	Id            int64        `db:"id" fieldtag:"pk"`
	CreatedAt     sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt     sql.NullTime `db:"updated_at"`
	State         string       `db:"state"`
	KeyIdentifier string       `db:"key_identifier"`
	Type          string       `db:"type" fieldopt:"withquote"`
	Algorithm     string       `db:"algorithm" fieldopt:"withquote"`
	// PrivateKeyPEM is the RSA private key PEM, encrypted at rest with the data
	// cipher (issue #83). Use ParsePrivateKey to obtain the usable key.
	PrivateKeyPEM     []byte `db:"private_key_pem"`
	PublicKeyPEM      []byte `db:"public_key_pem"`
	PublicKeyASN1_DER []byte `db:"public_key_asn1_der"`
	PublicKeyJWK      []byte `db:"public_key_jwk"`
}

// ParsePrivateKey decrypts the stored private-key PEM with the process data
// cipher (encryption.InitDataCipher must have run at startup) and parses it into
// an *rsa.PrivateKey for signing.
func (kp *KeyPair) ParsePrivateKey() (*rsa.PrivateKey, error) {
	pem, err := encryption.DecryptData(kp.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(pem))
}
