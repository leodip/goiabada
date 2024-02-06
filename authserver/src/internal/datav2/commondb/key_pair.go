package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func SetKeyPairInsertColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, keyPair *entitiesv2.KeyPair) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("key_pairs")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"state",
		"key_identifier",
		"type",
		"algorithm",
		"private_key_pem",
		"public_key_pem",
		"public_key_asn1_der",
		"public_key_jwk",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		keyPair.State,
		keyPair.KeyIdentifier,
		keyPair.Type,
		keyPair.Algorithm,
		keyPair.PrivateKeyPEM,
		keyPair.PublicKeyPEM,
		keyPair.PublicKeyASN1_DER,
		keyPair.PublicKeyJWK,
	)

	return insertBuilder
}

func ScanKeyPair(rows *sql.Rows) (*entitiesv2.KeyPair, error) {
	var (
		id              int64
		created_at      time.Time
		updated_at      time.Time
		state           string
		key_identifier  string
		key_type        string
		algorithm       string
		private_key_pem []byte
		public_key_pem  []byte
		public_key_asn1 []byte
		public_key_jwk  []byte
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&state,
		&key_identifier,
		&key_type,
		&algorithm,
		&private_key_pem,
		&public_key_pem,
		&public_key_asn1,
		&public_key_jwk,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan row")
	}

	keyPair := &entitiesv2.KeyPair{
		Id:                id,
		CreatedAt:         created_at,
		UpdatedAt:         updated_at,
		State:             state,
		KeyIdentifier:     key_identifier,
		Type:              key_type,
		Algorithm:         algorithm,
		PrivateKeyPEM:     private_key_pem,
		PublicKeyPEM:      public_key_pem,
		PublicKeyASN1_DER: public_key_asn1,
		PublicKeyJWK:      public_key_jwk,
	}

	return keyPair, nil
}
