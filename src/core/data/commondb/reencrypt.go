package commondb

import (
	"bytes"
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/pkg/errors"
)

// aesProtectedColumns lists the (table, column) pairs holding AES-GCM ciphertext
// of string secrets that must be re-keyed when the data-encryption key changes
// (issue #83).
var aesProtectedColumns = []struct{ table, column string }{
	{"settings", "smtp_password_encrypted"},
	{"clients", "client_secret_encrypted"},
	{"users", "email_verification_code_encrypted"},
	{"users", "phone_number_verification_code_encrypted"},
	{"users", "otp_secret_encrypted"},
	{"users", "forgot_password_code_encrypted"},
	{"pre_registrations", "verification_code_encrypted"},
}

// ReencryptDataToNewKey re-encrypts every secret stored at rest from oldKey to
// newKey, encrypts the RSA private keys (historically stored as plaintext PEM),
// and blanks the legacy aes_encryption_key column so the migration is not
// repeated. The whole operation runs in ONE transaction: it is all-or-nothing,
// so a failure leaves the data under oldKey and the next startup retries
// cleanly (fail-closed). See issue #83.
func (d *CommonDatabase) ReencryptDataToNewKey(oldKey, newKey []byte) error {
	if len(oldKey) != 32 || len(newKey) != 32 {
		return errors.WithStack(errors.New("re-encryption requires 32-byte old and new keys"))
	}

	tx, err := d.BeginTransaction()
	if err != nil {
		return errors.Wrap(err, "unable to begin re-encryption transaction")
	}

	if err := d.reencryptAll(tx, oldKey, newKey); err != nil {
		_ = d.RollbackTransaction(tx)
		return err
	}

	if err := d.CommitTransaction(tx); err != nil {
		return errors.Wrap(err, "unable to commit re-encryption transaction")
	}
	return nil
}

// RotateEncryptionKeyIfNeeded supports env-to-env rotation of the data key
// (issue #83). Given the current key and an optional previous key, it decides
// whether the stored data is already under currentKey (nothing to do) or still
// under previousKey (re-encrypt to currentKey). Detection uses a canary — an
// encrypted RSA private key PEM, always present after seeding — so the method is
// idempotent: it is safe to leave GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS set
// across restarts. It returns whether a rotation was performed.
//
// It is a no-op when previousKey is empty, equals currentKey, or there is no
// encrypted data yet (fresh database). If the canary decrypts under neither key,
// it errors (misconfiguration) rather than risk corrupting data.
func (d *CommonDatabase) RotateEncryptionKeyIfNeeded(currentKey, previousKey []byte) (bool, error) {
	if len(currentKey) != 32 {
		return false, errors.WithStack(errors.New("rotation requires a 32-byte current key"))
	}
	if len(previousKey) != 32 || bytes.Equal(previousKey, currentKey) {
		return false, nil
	}

	keys, err := d.GetAllSigningKeys(nil)
	if err != nil {
		return false, errors.Wrap(err, "unable to load signing keys for rotation check")
	}
	var canary []byte
	for _, k := range keys {
		if len(k.PrivateKeyPEM) > 0 {
			canary = k.PrivateKeyPEM
			break
		}
	}
	if canary == nil {
		return false, nil // no encrypted data yet
	}

	if _, err := encryption.DecryptText(canary, currentKey); err == nil {
		return false, nil // already encrypted under the current key
	}
	if _, err := encryption.DecryptText(canary, previousKey); err != nil {
		return false, errors.WithStack(errors.New(
			"data-at-rest decrypts under neither GOIABADA_AES_ENCRYPTION_KEY nor GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS"))
	}

	if err := d.ReencryptDataToNewKey(previousKey, currentKey); err != nil {
		return false, err
	}
	return true, nil
}

func (d *CommonDatabase) reencryptAll(tx *sql.Tx, oldKey, newKey []byte) error {
	for _, c := range aesProtectedColumns {
		if err := d.reencryptStringColumn(tx, c.table, c.column, oldKey, newKey); err != nil {
			return errors.Wrapf(err, "re-encrypting %s.%s", c.table, c.column)
		}
	}
	if err := d.reencryptPrivateKeys(tx, oldKey, newKey); err != nil {
		return errors.Wrap(err, "re-encrypting RSA private keys")
	}

	// Blank the legacy key column so subsequent startups skip the migration. The
	// column is NOT NULL, so write an empty blob rather than NULL (len 0 still
	// reads as "no legacy key").
	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("settings")
	ub.Set(ub.Assign("aes_encryption_key", []byte{}))
	query, args := ub.BuildWithFlavor(d.Flavor)
	if _, err := d.ExecSql(tx, query, args...); err != nil {
		return errors.Wrap(err, "unable to blank legacy aes_encryption_key column")
	}
	return nil
}

// reencryptStringColumn re-encrypts one string-secret column across a table. It
// reads each row fully before writing (SQLite runs on a single connection), and
// skips rows whose ciphertext is empty/NULL.
func (d *CommonDatabase) reencryptStringColumn(tx *sql.Tx, table, column string, oldKey, newKey []byte) error {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", column).From(table)
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(tx, query, args...)
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
			return errors.Wrapf(err, "decrypt %s id %d", column, it.id)
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
		if _, err := d.ExecSql(tx, uq, uargs...); err != nil {
			return err
		}
	}
	return nil
}

// reencryptPrivateKeys encrypts/re-encrypts the RSA private-key PEMs. On the
// first migration they are plaintext PEM (detected by the "-----BEGIN" prefix)
// and simply get encrypted with newKey; on a later rotation they are ciphertext
// under oldKey and are decrypted then re-encrypted.
func (d *CommonDatabase) reencryptPrivateKeys(tx *sql.Tx, oldKey, newKey []byte) error {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "private_key_pem").From("key_pairs")
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(tx, query, args...)
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
				return errors.Wrapf(err, "decrypt private key id %d", it.id)
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
		if _, err := d.ExecSql(tx, uq, uargs...); err != nil {
			return err
		}
	}
	return nil
}
