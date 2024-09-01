package models

import "database/sql"

type PreRegistration struct {
	Id                        int64        `db:"id" fieldtag:"pk"`
	CreatedAt                 sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt                 sql.NullTime `db:"updated_at"`
	Email                     string       `db:"email"`
	PasswordHash              string       `db:"password_hash"`
	VerificationCodeEncrypted []byte       `db:"verification_code_encrypted"`
	VerificationCodeIssuedAt  sql.NullTime `db:"verification_code_issued_at"`
}
