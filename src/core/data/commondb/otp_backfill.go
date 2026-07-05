package commondb

import (
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/pkg/errors"
)

// BackfillEncryptedOTPSecrets migrates any TOTP secrets still held in the legacy
// plaintext users.otp_secret column into the encrypted users.otp_secret_encrypted
// column, clearing the plaintext value as it goes. See issue #82.
//
// It is idempotent and resumable: a migrated row has its plaintext blanked, so
// it is not reselected on a later run, and a run interrupted partway simply
// finishes the remaining rows next time. It returns the number of rows migrated.
//
// The caller (data.NewDatabase) runs this at startup, before the server begins
// serving, and treats any error as fatal so the process never serves requests
// with a partially-migrated 2FA store.
func (d *CommonDatabase) BackfillEncryptedOTPSecrets(aesKey []byte) (int, error) {
	if len(aesKey) != 32 {
		return 0, errors.WithStack(errors.New("cannot backfill OTP secrets: AES key must be 32 bytes"))
	}

	// Rows needing migration have a non-empty plaintext secret. Migrated rows
	// have otp_secret blanked, which is what makes repeated runs idempotent.
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "otp_secret").From("users")
	sb.Where(sb.NotEqual("otp_secret", ""))
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(nil, query, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to query users with plaintext OTP secrets")
	}

	// Collect the rows fully before issuing any UPDATE: some drivers (SQLite is
	// configured with a single connection) cannot run a write while a result set
	// is still open on the same connection.
	type pending struct {
		id     int64
		secret string
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.secret); err != nil {
			_ = rows.Close()
			return 0, errors.Wrap(err, "unable to scan user OTP secret")
		}
		todo = append(todo, p)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, errors.Wrap(err, "error iterating users with plaintext OTP secrets")
	}
	_ = rows.Close()

	migrated := 0
	for _, p := range todo {
		encrypted, err := encryption.EncryptText(p.secret, aesKey)
		if err != nil {
			return migrated, errors.Wrapf(err, "unable to encrypt OTP secret for user id %d", p.id)
		}

		ub := sqlbuilder.NewUpdateBuilder()
		ub.Update("users")
		ub.Set(
			ub.Assign("otp_secret_encrypted", encrypted),
			ub.Assign("otp_secret", ""),
		)
		ub.Where(ub.Equal("id", p.id))
		uq, uargs := ub.BuildWithFlavor(d.Flavor)

		if _, err := d.ExecSql(nil, uq, uargs...); err != nil {
			return migrated, errors.Wrapf(err, "unable to store encrypted OTP secret for user id %d", p.id)
		}
		migrated++
	}

	return migrated, nil
}
