package models

import "database/sql"

type KeyPair struct {
	Id                int64        `db:"id" fieldtag:"pk"`
	CreatedAt         sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt         sql.NullTime `db:"updated_at"`
	State             string       `db:"state"`
	KeyIdentifier     string       `db:"key_identifier"`
	Type              string       `db:"type" fieldopt:"withquote"`
	Algorithm         string       `db:"algorithm" fieldopt:"withquote"`
	PrivateKeyPEM     []byte       `db:"private_key_pem"`
	PublicKeyPEM      []byte       `db:"public_key_pem"`
	PublicKeyASN1_DER []byte       `db:"public_key_asn1_der"`
	PublicKeyJWK      []byte       `db:"public_key_jwk"`
}
