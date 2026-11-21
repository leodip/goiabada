package commondb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// reencryptionBatchSize bounds the rows one read of the sweep takes from a table. The sweep holds
// a batch in memory, never a table, and each read starts after the last id the one before it
// reached.
const reencryptionBatchSize = 100

// reencryptionAttempts bounds the writes the sweep makes for one value. A write that finds other
// bytes than it read means a server wrote the row meanwhile, so the sweep reads it again and starts
// over from what it holds; a value that keeps changing under it fails the run, which can be run
// again.
const reencryptionAttempts = 5

// ReencryptStoredSecrets is the re-encryption sweep that runs beside serving auth servers (#492
// decisions 4 to 6). See data.Database for its contract.
//
// It rests on one rule, which the data guide states: an auth server writes a stored secret only as
// ciphertext it has just sealed, or as it read it under that row's lock. A server's write that
// lands between the sweep's read and its write is then either a value freshly sealed under the
// current key, or the bytes the sweep read, written back under the lock the sweep's write waits
// for; the sweep's conditional write leaves the first as it is and still moves the second.
func (d *Database) ReencryptStoredSecrets(ctx context.Context, currentKey, previousKey []byte,
	unreadable func(record.StoredSecret)) (record.Reencryption, error) {
	// The cipher's constructor holds the keys to the rules a start holds them to: the current
	// key 32 bytes, and a previous key absent, equal to the current one, or 32 bytes too.
	cipher, err := encryption.NewDataCipherWithPrevious(currentKey, previousKey)
	if err != nil {
		return record.Reencryption{}, err
	}
	s := &reencryptionSweep{d: d, cipher: cipher, current: append([]byte(nil), currentKey...), unreadable: unreadable}
	if len(previousKey) > 0 && !bytes.Equal(previousKey, currentKey) {
		s.previous = append([]byte(nil), previousKey...)
	}

	for _, c := range aesProtectedColumns {
		if err := s.sweepColumn(ctx, c.table, c.column); err != nil {
			return s.report, s.stopped(ctx, errs.Wrapf(err, "re-encrypting %s.%s", c.table, c.column))
		}
	}
	if err := s.sweepSigningKeys(ctx); err != nil {
		return s.report, s.stopped(ctx, errs.Wrap(err, "re-encrypting the signing keys"))
	}
	return s.report, nil
}

// reencryptionSweep is one run of the sweep and what it has done so far.
type reencryptionSweep struct {
	d      *Database
	cipher *encryption.DataCipher
	// current and previous are the keys, previous nil when the run is a check: what it tells
	// apart is which key opens a value, which the cipher does not answer.
	current  []byte
	previous []byte
	// unreadable is handed each value neither key opens as the sweep reaches it, so a run over a
	// database that opens under neither key holds a batch in memory, never a list of every row.
	unreadable func(record.StoredSecret)
	report     record.Reencryption
}

// stopped answers err so that a run stopped by its context says so, whatever the driver made of
// the cancellation of the statement it was in.
func (s *reencryptionSweep) stopped(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return errs.Join(ctxErr, err)
	}
	return err
}

// sweepColumn takes one column of a table through the sweep, a batch at a time, with no
// transaction across the table: a value's write is a transaction of its own, committed as it lands.
func (s *reencryptionSweep) sweepColumn(ctx context.Context, table, column string) error {
	var after int64
	for {
		batch, err := s.d.readStoredSecretBatch(ctx, table, column, after)
		if err != nil {
			return err
		}
		for _, item := range batch {
			if err := s.sweepValue(ctx, table, column, item); err != nil {
				return err
			}
		}
		if len(batch) < reencryptionBatchSize {
			return nil
		}
		after = batch[len(batch)-1].id
	}
}

// sweepSigningKeys takes the signing keys through the sweep after every other stored secret, and
// the current one last of all, so a current signing key under the current data key means the sweep
// has been through everything else (#492 decision 6). key_pairs holds at most one key in each
// state, so it is read in one go; the order is the one read, so a key changing state during the
// run is not missed.
func (s *reencryptionSweep) sweepSigningKeys(ctx context.Context) error {
	keys, err := s.d.readSigningKeysForSweep(ctx)
	if err != nil {
		return err
	}
	var current []storedValue
	for _, key := range keys {
		if key.state == record.KeyStateCurrent.String() {
			current = append(current, key.storedValue)
			continue
		}
		if err := s.sweepValue(ctx, "key_pairs", "private_key_pem", key.storedValue); err != nil {
			return err
		}
	}
	for _, key := range current {
		if err := s.sweepValue(ctx, "key_pairs", "private_key_pem", key); err != nil {
			return err
		}
	}
	return nil
}

// sweepValue takes one stored value through the sweep: counts it when the current key opens it,
// reports it when neither key does, and otherwise writes it under the current key while the row
// still holds the bytes read. A write that finds other bytes reads the row again and decides on what
// it holds now: a server's replacement is under the current key, and a value cleared or a row
// deleted is not put back.
func (s *reencryptionSweep) sweepValue(ctx context.Context, table, column string, item storedValue) error {
	value := item.value
	for attempt := 1; ; attempt++ {
		// A stop lands between values, never inside one's write.
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(value) == 0 {
			return nil
		}
		if _, err := encryption.DecryptText(value, s.current); err == nil {
			s.report.AlreadyCurrent++
			return nil
		}
		plaintext, opened := s.openUnderPrevious(value)
		if !opened {
			s.report.Unreadable++
			if s.unreadable != nil {
				s.unreadable(record.StoredSecret{Table: table, Column: column, ID: item.id})
			}
			return nil
		}
		sealed, err := s.cipher.Encrypt(plaintext)
		if err != nil {
			return err
		}
		written, err := s.d.writeStoredSecretIfUnchanged(ctx, table, column, item.id, sealed, value)
		if err != nil {
			return err
		}
		if written {
			s.report.Reencrypted++
			return nil
		}
		if attempt == reencryptionAttempts {
			return errs.Errorf("the value of row %d changed under each of %d writes re-encrypting it", item.id, reencryptionAttempts)
		}
		var found bool
		value, found, err = s.d.readStoredSecret(ctx, table, column, item.id)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
	}
}

// openUnderPrevious opens value with the previous key, when the run has one.
func (s *reencryptionSweep) openUnderPrevious(value []byte) (string, bool) {
	if s.previous == nil {
		return "", false
	}
	plaintext, err := encryption.DecryptText(value, s.previous)
	return plaintext, err == nil
}

// readStoredSecretBatch is the batch read: the rows of table after the id after, in id order, at
// most reencryptionBatchSize of them, each with column, skipping the rows where it is NULL. table
// and column are always a pair from aesProtectedColumns, literals in reencrypt.go, never input. The
// rows are closed before it returns, because the sweep writes next and SQLite runs on a single
// connection.
func (d *Database) readStoredSecretBatch(ctx context.Context, table, column string, after int64) ([]storedValue, error) {
	rows, err := d.QuerySQL(ctx, nil, storedSecretBatch(table, column).text(d.Dialect), after)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var batch []storedValue
	for rows.Next() {
		var item storedValue
		if err := rows.Scan(&item.id, &item.value); err != nil {
			return nil, err
		}
		batch = append(batch, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}

// storedSecretBatch is readStoredSecretBatch's statement for one column.
func storedSecretBatch(table, column string) statement {
	limit := strconv.Itoa(reencryptionBatchSize)
	selected := "id, " + column + " FROM " + table + " WHERE id > "
	rest := " AND " + column + " IS NOT NULL ORDER BY id"
	return statement{
		sqlite:   "SELECT " + selected + "?" + rest + " LIMIT " + limit,
		mysql:    "SELECT " + selected + "?" + rest + " LIMIT " + limit,
		postgres: "SELECT " + selected + "$1" + rest + " LIMIT " + limit,
		mssql:    "SELECT TOP (" + limit + ") " + selected + "@p1" + rest,
	}
}

// readStoredSecret reads one row's column again, after the sweep's write found other bytes than it
// read. found is false when the row is gone.
func (d *Database) readStoredSecret(ctx context.Context, table, column string, id int64) ([]byte, bool, error) {
	rows, err := d.QuerySQL(ctx, nil, storedSecretByID(table, column).text(d.Dialect), id)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		return nil, false, rows.Err()
	}
	var value []byte
	if err := rows.Scan(&value); err != nil {
		return nil, false, err
	}
	return value, true, rows.Err()
}

// storedSecretByID is readStoredSecret's statement for one column.
func storedSecretByID(table, column string) statement {
	query := "SELECT " + column + " FROM " + table + " WHERE id = "
	return statement{sqlite: query + "?", mysql: query + "?", postgres: query + "$1", mssql: query + "@p1"}
}

// writeStoredSecretIfUnchanged writes sealed to one row's column only while the column still holds
// read, the bytes the sweep read, and reports whether it did. The new ciphertext always differs
// from read, its nonce being fresh, so a matched row is a changed row on all four engines, MySQL
// included.
//
// The write is a transaction of its own, run by runInTransactionSettlingWhateverTheStop, so that
// its outcome is known whatever a stop does to it (#492 decision 8), and a deadlock or a commit
// failure is answered as every transaction's is: an engine's deadlock victim is run again, and a
// commit whose outcome cannot be known carries data.ErrCommitOutcomeUnknown. The UPDATE runs under
// ctx, so a stop still ends its wait for a row lock; a driver can answer that cancellation after
// the statement took effect, as SQLite's does while it hands the result back, so a failed UPDATE
// is rolled back and never counted. One that succeeded is committed whatever the stop, and counted
// when the commit returns. A write that finds other bytes is rolled back.
func (d *Database) writeStoredSecretIfUnchanged(ctx context.Context, table, column string, id int64,
	sealed, read []byte) (bool, error) {
	err := d.runInTransactionSettlingWhateverTheStop(ctx, func(tx *sql.Tx) error {
		result, err := d.ExecSQL(ctx, tx, storedSecretIfUnchanged(table, column).text(d.Dialect), sealed, id, read)
		if err != nil {
			return err
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rowsAffected != 1 {
			return errStoredSecretChanged
		}
		return nil
	})
	switch {
	case errors.Is(err, errStoredSecretChanged):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// errStoredSecretChanged is writeStoredSecretIfUnchanged's body finding other bytes than the sweep
// read, which rolls its transaction back. It never leaves this file.
var errStoredSecretChanged = errors.New("the stored secret no longer holds the bytes the sweep read")

// storedSecretIfUnchanged is writeStoredSecretIfUnchanged's statement: the new ciphertext, the
// row's id and the bytes read. SQL Server compares two VARBINARY values equal when one is the other
// with trailing zero bytes, so its statement also holds the lengths equal: a row a server changed
// to the bytes read and a trailing zero is a changed row there too.
func storedSecretIfUnchanged(table, column string) statement {
	return statement{
		sqlite:   "UPDATE " + table + " SET " + column + " = ? WHERE id = ? AND " + column + " = ?",
		mysql:    "UPDATE " + table + " SET " + column + " = ? WHERE id = ? AND " + column + " = ?",
		postgres: "UPDATE " + table + " SET " + column + " = $1 WHERE id = $2 AND " + column + " = $3",
		mssql: "UPDATE " + table + " SET " + column + " = @p1 WHERE id = @p2 AND " + column + " = @p3" +
			" AND DATALENGTH(" + column + ") = DATALENGTH(@p3)",
	}
}

// signingKeyForSweep is one signing key as the sweep reads it: its row's id and private key, and
// its state.
type signingKeyForSweep struct {
	storedValue
	state string
}

// readSigningKeysForSweep reads every signing key whose private key is not NULL, in id order.
func (d *Database) readSigningKeysForSweep(ctx context.Context) ([]signingKeyForSweep, error) {
	rows, err := d.QuerySQL(ctx, nil, signingKeysForSweep.text(d.Dialect))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var keys []signingKeyForSweep
	for rows.Next() {
		var key signingKeyForSweep
		if err := rows.Scan(&key.id, &key.state, &key.value); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// signingKeysForSweep is readSigningKeysForSweep's statement.
var signingKeysForSweep = statement{
	sqlite:   "SELECT id, state, private_key_pem FROM key_pairs WHERE private_key_pem IS NOT NULL ORDER BY id",
	mysql:    "SELECT id, state, private_key_pem FROM key_pairs WHERE private_key_pem IS NOT NULL ORDER BY id",
	postgres: "SELECT id, state, private_key_pem FROM key_pairs WHERE private_key_pem IS NOT NULL ORDER BY id",
	mssql:    "SELECT id, state, private_key_pem FROM key_pairs WHERE private_key_pem IS NOT NULL ORDER BY id",
}
