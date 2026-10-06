package commondb

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/core/errs"
)

// aesProtectedColumns lists the (table, column) pairs holding AES-GCM ciphertext
// of string secrets that must be re-keyed when the data-encryption key changes
// (issue #83).
var aesProtectedColumns = []struct{ table, column string }{
	{"settings", "smtp_password_encrypted"},
	{"clients", "client_secret_encrypted"},
	{"users", "email_verification_code_encrypted"},
	{"users", "otp_secret_encrypted"},
	{"users", "forgot_password_code_encrypted"},
	{"users", "otp_enrollment_secret_encrypted"},
	{"pre_registrations", "verification_code_encrypted"},
}

// ReencryptToKey re-encrypts every secret stored at rest from oldKey to newKey and re-encrypts
// the RSA private keys. The whole operation runs in ONE transaction: it is all-or-nothing, so a
// failure leaves the data under oldKey and the caller can retry cleanly (fail-closed). See issue
// #83.
//
// It re-keys and decides nothing. Whether the data is under oldKey at all is answered by the
// datafactory startup task from a canary it reads first: that is policy over one read, so it sits
// above the data layer where a mock can drive every branch of it, and this method is the write it
// ends in (#438 decision 8). It does not blank settings.aes_encryption_key, which was the 1.5.x
// conversion's own bookkeeping, deleted by #359 (#262).
func (d *Database) ReencryptToKey(ctx context.Context, oldKey, newKey []byte) error {
	if len(oldKey) != 32 || len(newKey) != 32 {
		return errs.New("re-encryption requires 32-byte old and new keys")
	}

	// Opened through RunInTransaction, so a deadlock reruns the body (#301); every read and
	// write is inside it, so a rerun starts from the data as it was under oldKey.
	return d.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return d.reencryptAll(ctx, tx, oldKey, newKey)
	})
}

func (d *Database) reencryptAll(ctx context.Context, tx *sql.Tx, oldKey, newKey []byte) error {
	for _, c := range aesProtectedColumns {
		if err := d.reencryptStringColumn(ctx, tx, c.table, c.column, oldKey, newKey); err != nil {
			return errs.Wrapf(err, "re-encrypting %s.%s", c.table, c.column)
		}
	}
	if err := d.reencryptPrivateKeys(ctx, tx, oldKey, newKey); err != nil {
		return errs.Wrap(err, "re-encrypting RSA private keys")
	}
	// settings.aes_encryption_key is deliberately left alone. Blanking it was the 1.5.x startup
	// conversion's own bookkeeping ("so subsequent startups skip the migration"), and rotation
	// only ever reached it by sharing this helper; there is no migration to skip after #359
	// deleted the conversion (#262). rotate_test.go pins that it stays.
	return nil
}

// reencryptStringColumn re-encrypts one string-secret column across a table. It
// reads each row fully before writing (SQLite runs on a single connection), and
// skips rows whose ciphertext is empty/NULL.
func (d *Database) reencryptStringColumn(ctx context.Context, tx *sql.Tx, table, column string, oldKey, newKey []byte) error {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", column).From(table)
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return err
	}
	type item struct {
		id int64
		ct []byte
	}
	var items []item
	for rows.Next() {
		var id int64
		var ct []byte
		if err := rows.Scan(&id, &ct); err != nil {
			_ = rows.Close()
			return err
		}
		if len(ct) == 0 {
			continue
		}
		items = append(items, item{id: id, ct: ct})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, it := range items {
		plaintext, err := encryption.DecryptText(it.ct, oldKey)
		if err != nil {
			return errs.Wrapf(err, "decrypt %s id %d", column, it.id)
		}
		newCt, err := encryption.EncryptText(plaintext, newKey)
		if err != nil {
			return err
		}
		ub := sqlbuilder.NewUpdateBuilder()
		ub.Update(table)
		ub.Set(ub.Assign(column, newCt))
		ub.Where(ub.Equal("id", it.id))
		uq, uargs := ub.BuildWithFlavor(d.Flavor)
		if _, err := d.ExecSQL(ctx, tx, uq, uargs...); err != nil {
			return err
		}
	}
	return nil
}

// reencryptPrivateKeys encrypts/re-encrypts the RSA private-key PEMs. A PEM held as ciphertext
// under oldKey is decrypted and re-encrypted under newKey.
//
// The plaintext-PEM branch below is unreachable rather than wrong. It existed for the 1.5.x
// startup conversion, where the PEMs were still plaintext; #359 deleted that caller (#262), and
// the one caller left, datafactory's startup task, picks the first non-empty PrivateKeyPEM as its
// canary and refuses before calling ReencryptToKey when it decrypts under neither key (#438
// decision 8). So a plaintext PEM fails closed at the canary, never reaching this branch. It is kept because deleting it would
// change a crypto path for no observable gain.
func (d *Database) reencryptPrivateKeys(ctx context.Context, tx *sql.Tx, oldKey, newKey []byte) error {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "private_key_pem").From("key_pairs")
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return err
	}
	type item struct {
		id  int64
		pem []byte
	}
	var items []item
	for rows.Next() {
		var id int64
		var pem []byte
		if err := rows.Scan(&id, &pem); err != nil {
			_ = rows.Close()
			return err
		}
		if len(pem) == 0 {
			continue
		}
		items = append(items, item{id: id, pem: pem})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, it := range items {
		var plaintextPEM string
		if bytes.HasPrefix(it.pem, []byte("-----BEGIN")) {
			plaintextPEM = string(it.pem) // plaintext PEM (pre-#83): encrypt it now
		} else {
			pt, err := encryption.DecryptText(it.pem, oldKey) // ciphertext under oldKey: rotate
			if err != nil {
				return errs.Wrapf(err, "decrypt private key id %d", it.id)
			}
			plaintextPEM = pt
		}
		enc, err := encryption.EncryptText(plaintextPEM, newKey)
		if err != nil {
			return err
		}
		ub := sqlbuilder.NewUpdateBuilder()
		ub.Update("key_pairs")
		ub.Set(ub.Assign("private_key_pem", enc))
		ub.Where(ub.Equal("id", it.id))
		uq, uargs := ub.BuildWithFlavor(d.Flavor)
		if _, err := d.ExecSQL(ctx, tx, uq, uargs...); err != nil {
			return err
		}
	}
	return nil
}
