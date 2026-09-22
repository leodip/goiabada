package models

import (
	"database/sql"
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
	// cipher (issue #83). Use signingkeys.ParsePrivateKey to obtain the usable
	// key: decrypting and parsing it is a capability of the package that owns
	// the signing keys, not of the row (#387).
	PrivateKeyPEM     []byte `db:"private_key_pem"`
	PublicKeyPEM      []byte `db:"public_key_pem"`
	PublicKeyASN1_DER []byte `db:"public_key_asn1_der"`
	PublicKeyJWK      []byte `db:"public_key_jwk"`
}
