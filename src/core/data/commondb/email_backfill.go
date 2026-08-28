package commondb

import (
	"database/sql"
	"log/slog"
	"sort"
	"strings"

	"github.com/huandu/go-sqlbuilder"
	"github.com/pkg/errors"
)

// emailRow is one users row as the lowercase backfill reads it: the address, the id that
// breaks a tie between two spellings of it, and whether the row is still enabled.
type emailRow struct {
	id      int64
	email   string
	enabled bool
}

// BackfillLowercaseEmails brings every stored users.email down to its lowercase form, so a
// sign-in that lowercases the address it was given (every credential path does) can reach the
// row (#221, #283).
//
// It matters because the engines disagree about what "=" means. MySQL and SQL Server fold case
// in the comparison, so a legacy row spelled Alice@x.com signs in there today; SQLite and
// PostgreSQL compare exactly, so the same row cannot sign in at all. Pinning every column to a
// case-sensitive collation makes all four behave like the second pair, which would silently
// take the ability to sign in away from rows that have it. Lowercasing the stored address is
// what keeps that promise: no account that can sign in today loses the ability to.
//
// Go's strings.ToLower rather than the engine's LOWER(), and that is not a stylistic choice.
// SQLite's LOWER() maps ASCII only through modernc.org/sqlite, so an address like Ädmin@x.com
// is not even SELECTED by a LOWER()-based predicate there, and would survive this pass
// untouched on the default engine. Written in Go the rule is one rule on four engines.
//
// Where two rows differ only by case, one survives with its address lowercased and the rest are
// DISABLED with their address left exactly as it stands. Nothing is deleted, renamed or merged,
// and the survivor is the row that can sign in today (see pickEmailSurvivor). Such a pair can
// only exist on SQLite and PostgreSQL: MySQL and SQL Server's folding UNIQUE index on email has
// never permitted one, so the conversion there is collision-free by construction.
//
// Disabling a row also revokes its authentication state, in the same transaction as the flag,
// which is the invariant #106 established for every other enabled-to-disabled transition. See
// disableAndRevoke for why writing the flag alone is not enough.
//
// It is idempotent and resumable, on BackfillEncryptedOTPSecrets' terms (#82): a converged row
// no longer differs from its own lowercase form and is not reselected, a disabled non-survivor
// is skipped because it is already disabled, and a group interrupted halfway is recomputed to
// the same answer on the next run. It is NOT reversible: the original casing is not recorded
// anywhere and neither is the set of rows this disabled, which is why it has no down migration
// to be the inverse of.
//
// The caller (data.NewDatabase) runs this at startup, after the migration chain and before
// either application serves, and treats any error as fatal. It returns the number of rows
// lowercased and the number disabled.
func (d *CommonDatabase) BackfillLowercaseEmails() (int, int, error) {

	// One scan, filtered in Go. A SQL predicate would be wrong on SQLite for the reason above,
	// and only the rows that differ from their own lowercase form are retained, so what is held
	// in memory is the legacy residue rather than the users table.
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "email", "enabled").From("users")
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(nil, query, args...)
	if err != nil {
		return 0, 0, errors.Wrap(err, "unable to query users for the lowercase email backfill")
	}

	// Rows sharing a lowercased address are one group, and the whole of the collision policy is
	// about a group with more than one member. Collected fully before any UPDATE is issued:
	// SQLite is configured with a single connection and cannot write while a result set is open
	// on it, which is BackfillEncryptedOTPSecrets' own constraint.
	groups := map[string][]emailRow{}
	for rows.Next() {
		var r emailRow
		if err := rows.Scan(&r.id, &r.email, &r.enabled); err != nil {
			_ = rows.Close()
			return 0, 0, errors.Wrap(err, "unable to scan user email")
		}
		lowered := strings.ToLower(r.email)
		if r.email == lowered {
			continue
		}
		groups[lowered] = append(groups[lowered], r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, 0, errors.Wrap(err, "error iterating users for the lowercase email backfill")
	}
	_ = rows.Close()

	// Sorted so a run's log lines come out in the same order twice. The rule itself does not
	// depend on the order: no group can affect another, since a row belongs to exactly one.
	lowercased := make([]string, 0, len(groups))
	for lowered := range groups {
		lowercased = append(lowercased, lowered)
	}
	sort.Strings(lowercased)

	rowsLowercased, rowsDisabled := 0, 0
	for _, lowered := range lowercased {
		members := groups[lowered]

		// The row already spelled in lowercase is not in the scan's output, because the scan
		// keeps only rows that differ from their own lowercase form. It is what decides the
		// group, so it is fetched here and put back among the members.
		existing, err := d.findUserByExactEmail(lowered)
		if err != nil {
			return rowsLowercased, rowsDisabled, err
		}
		if existing != nil {
			members = append(members, *existing)
		}

		survivor := pickEmailSurvivor(members)

		if survivor.email != lowered {
			ub := sqlbuilder.NewUpdateBuilder()
			ub.Update("users")
			ub.Set(ub.Assign("email", lowered))
			ub.Where(ub.Equal("id", survivor.id))
			uq, uargs := ub.BuildWithFlavor(d.Flavor)
			if _, err := d.ExecSql(nil, uq, uargs...); err != nil {
				return rowsLowercased, rowsDisabled,
					errors.Wrapf(err, "unable to lowercase the email of user id %d", survivor.id)
			}
			rowsLowercased++
		}

		for _, member := range members {
			if member.id == survivor.id {
				continue
			}
			// Already disabled rows are skipped, and that is what makes a second run report
			// nothing: a non-survivor keeps its mixed-case address deliberately, so it is
			// selected by every later scan and would otherwise be counted again each time.
			if !member.enabled {
				continue
			}

			transitioned, err := d.disableAndRevoke(member.id)
			if err != nil {
				return rowsLowercased, rowsDisabled,
					errors.Wrapf(err, "unable to disable duplicate email user id %d", member.id)
			}
			if !transitioned {
				continue
			}
			rowsDisabled++

			// Loud, and naming the address: this is the one thing here that takes something
			// away from an account nobody asked about, and the operator has to be able to find
			// the row afterwards. The account was already unreachable through both credential
			// paths, since neither ever looks up a mixed-case address.
			slog.Warn("disabled a user whose email differs from another only by case",
				"userId", member.id, "email", member.email, "conflictsWith", lowered)
		}
	}

	return rowsLowercased, rowsDisabled, nil
}

// disableAndRevoke turns a collision loser off and, in the SAME transaction, invalidates
// every credential that row had authenticated under: the user's authentication generation is
// advanced, every refresh token belonging to them is revoked, and every session of theirs is
// deleted. It reports whether THIS call performed the enabled-to-disabled transition.
//
// The revocation is not decoration on the disable, it is what the disable means. #106
// established that enabled going true-to-false is the moment a user's outstanding credentials
// die, and the administrative path upholds it by pairing TrySetUserEnabled with
// RevokeUserAuthState inside one transaction. Writing enabled = false on its own does NOT
// invalidate anything: sessions, authorization codes and refresh tokens keep the generation
// they were issued under, and that generation still matches the user's. Nothing is observable
// while the flag is off, because every credential path also refuses a disabled user, which is
// exactly what makes the gap easy to miss. It becomes observable the moment an administrator
// re-enables the account, most plausibly right after resolving the email collision by hand:
// the pre-backfill sessions and refresh tokens are live again, with whatever access they
// carried. An administrator who disables and later re-enables has every reason to believe the
// first action killed them (#283).
//
// The sequence is written out here rather than delegated to handlers.RevokeUserAuthState
// because that helper lives in the authserver module and core cannot import it. Every
// primitive it needs is already a method on this type, so what is repeated is the order of
// four calls, not the logic inside them. Authorization codes need no statement of their own:
// they carry auth_state_generation too, so advancing it is what invalidates them, which is why
// the administrative path does not delete them either.
//
// Compare-and-set rather than an unconditional UPDATE, so a row some other process disabled
// first is neither counted again nor given a second generation advance. That also makes the
// pass idempotent across a restart that interrupted it.
func (d *CommonDatabase) disableAndRevoke(userId int64) (bool, error) {
	transitioned := false

	err := d.inTransaction(nil, func(tx *sql.Tx) error {
		var err error
		transitioned, err = d.TrySetUserEnabled(tx, userId, true, false)
		if err != nil {
			return err
		}
		if !transitioned {
			// Already disabled. Nothing was taken away, so there is nothing to revoke, and
			// advancing the generation here would evict credentials a previous disable has
			// already dealt with.
			return nil
		}

		if _, err := d.IncrementUserAuthStateGeneration(tx, userId); err != nil {
			return err
		}

		// User-scoped, so it covers both linkage shapes: auth-code tokens through the code's
		// user and ROPC tokens through the token's own. Nothing is preserved here, unlike the
		// administrative path's exceptSid: this account is not the one asking.
		tokens, err := d.GetRefreshTokensByUserId(tx, userId)
		if err != nil {
			return err
		}
		for _, rt := range tokens {
			if rt.Revoked {
				continue
			}
			rt.Revoked = true
			if err := d.UpdateRefreshToken(tx, rt); err != nil {
				return err
			}
		}

		sessions, err := d.GetUserSessionsByUserId(tx, userId)
		if err != nil {
			return err
		}
		for i := range sessions {
			if err := d.DeleteUserSession(tx, sessions[i].Id); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	return transitioned, nil
}

// pickEmailSurvivor returns the member of a group that keeps the address: the row whose address
// already equals its own lowercased form, falling back to the lowest id when no member
// qualifies (#221).
//
// The rule is total. At most one row per group can be the lowercase spelling, because two rows
// spelled identically would violate the UNIQUE index on email, so the first clause never has to
// choose between two candidates.
//
// It is that rule and not "lowest id" because the account that signs in today has to be the one
// that signs in afterwards. The likeliest collision is a mixed-case GOIABADA_ADMIN_EMAIL seeded
// at id 1, which cannot sign in on SQLite or PostgreSQL, beside a working lowercase account the
// operator created later; lowest-id-always would disable the working account and hand the
// deployment back to whatever GOIABADA_ADMIN_PASSWORD was. Most-recently-created gets that case
// right by recency rather than by any property of the accounts, and created_at is nullable on
// all four engines, which is why the fallback orders by id.
func pickEmailSurvivor(group []emailRow) emailRow {
	best := group[0]
	bestIsLower := best.email == strings.ToLower(best.email)

	for _, candidate := range group[1:] {
		candidateIsLower := candidate.email == strings.ToLower(candidate.email)
		switch {
		case candidateIsLower && !bestIsLower:
			best, bestIsLower = candidate, candidateIsLower
		case candidateIsLower == bestIsLower && candidate.id < best.id:
			best, bestIsLower = candidate, candidateIsLower
		}
	}

	return best
}

// findUserByExactEmail returns the row whose address is exactly email, byte for byte, or nil.
//
// The Go comparison on the way out is not redundant. MySQL and SQL Server fold case in "=", so
// the query answers with every case variant of the address; SQL Server also pads for "=" under
// every collation, BIN2 included, so 'a@x.com ' would come back as well. Trusting the engine
// here would make the backfill pick a survivor the group does not contain (#283).
func (d *CommonDatabase) findUserByExactEmail(email string) (*emailRow, error) {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "email", "enabled").From("users")
	sb.Where(sb.Equal("email", email))
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(nil, query, args...)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to look up the user holding email %q", email)
	}
	defer func() { _ = rows.Close() }()

	var found *emailRow
	for rows.Next() {
		var r emailRow
		if err := rows.Scan(&r.id, &r.email, &r.enabled); err != nil {
			return nil, errors.Wrapf(err, "unable to scan the user holding email %q", email)
		}
		if r.email == email {
			match := r
			found = &match
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrapf(err, "error iterating users holding email %q", email)
	}

	return found, nil
}
