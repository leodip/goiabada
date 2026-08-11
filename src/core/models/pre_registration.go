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
	// VerificationCodeHash is an unsalted SHA-256 of the activation code, and the only
	// way the activation link finds this row: the link carries the code and nothing
	// else, so no email address travels in it and no part of it needs percent-encoding
	// (#112). Its column is UNIQUE, and every row written after migration 000028 carries
	// a real hash.
	VerificationCodeHash string `db:"verification_code_hash"`
}
