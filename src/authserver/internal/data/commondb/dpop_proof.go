package commondb

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/errs"
)

var insertDPoPProof = statement{
	sqlite:   "INSERT INTO dpop_proofs (proof_hash, expires_at) VALUES (?, ?)",
	mysql:    "INSERT INTO dpop_proofs (proof_hash, expires_at) VALUES (?, ?)",
	postgres: "INSERT INTO dpop_proofs (proof_hash, expires_at) VALUES ($1, $2)",
	mssql:    "INSERT INTO dpop_proofs (proof_hash, expires_at) VALUES (@p1, @p2)",
}

var deleteExpiredDPoPProofs = statement{
	sqlite:   "DELETE FROM dpop_proofs WHERE expires_at < ?",
	mysql:    "DELETE FROM dpop_proofs WHERE expires_at < ?",
	postgres: "DELETE FROM dpop_proofs WHERE expires_at < $1",
	mssql:    "DELETE FROM dpop_proofs WHERE expires_at < @p1",
}

// The replay store of DPoP proofs (#42 decision 9, RFC 9449 section 11.1). An accepted proof is
// stored under its replay key until the last moment it could still be accepted, and a second use of
// it, at this instance or another sharing the database, finds the key taken.

// RecordDPoPProof stores one proof's replay key with its expiry, and reports whether THIS call
// stored it: false is a replay.
//
// The write is the insert alone, with no read before it: the primary key is what makes it atomic,
// so of any number of simultaneous uses of one proof exactly one insert succeeds, on every engine,
// and every other fails on the key, which is reported false. On PostgreSQL that refused insert
// aborts the transaction it ran in, so a caller that passes one ends it there; the token endpoint
// passes none.
//
// The key must be a lower-case SHA-256 hex digest, as dpop.Proof.ReplayKey computes it; anything
// else is a caller bug, and an error. That also keeps the key clear of SQL Server's `=`, which pads,
// so a key with trailing spaces would otherwise meet the record of the key without them (#283).
func (d *Database) RecordDPoPProof(ctx context.Context, tx *sql.Tx, proofHash string, expiresAt time.Time) (bool, error) {

	if !isSHA256Hex(proofHash) {
		return false, errs.New("can't record a DPoP proof under a key that is not a lower-case SHA-256 hex digest")
	}

	_, err := d.ExecSQL(ctx, tx, insertDPoPProof.text(d.Dialect), proofHash, expiresAt.UTC())
	if errors.Is(err, data.ErrUniqueViolation) {
		return false, nil
	}
	if err != nil {
		return false, errs.Wrap(err, "unable to record the DPoP proof")
	}

	return true, nil
}

// DeleteExpiredDPoPProofs reaps on expires_at alone. Every row it removes names a proof that could
// no longer be accepted; a row expiring at now itself is kept for the next sweep, since at that
// moment its proof still could be.
func (d *Database) DeleteExpiredDPoPProofs(ctx context.Context, tx *sql.Tx, now time.Time) error {

	_, err := d.ExecSQL(ctx, tx, deleteExpiredDPoPProofs.text(d.Dialect), now)
	if err != nil {
		return errs.Wrap(err, "unable to delete expired DPoP proofs")
	}

	return nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
