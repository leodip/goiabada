package commondb

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

// emailRow is one users row as the lowercase backfill reads it: the address, the id that
// breaks a tie between two spellings of it, and whether the row is still enabled. Every
// field of it comes from readEmailGroup, never from the opening scan, for the reason
// convergeEmailGroup gives.
type emailRow struct {
	id      int64
	email   string
	enabled bool
}

// emailGroupAttempts is how many times one group is recomputed when a concurrent write moves
// a row out from under the decision. Three, because each attempt starts from a fresh read and
// a group only ever loses members: a second attempt already sees the state that defeated the
// first, so the only way to reach the third is a writer changing the same address twice while
// the pass runs.
const emailGroupAttempts = 3

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
// It is also safe beside a concurrent write, which is not the same claim as idempotent. The
// caller (data.NewDatabase) runs it at startup, after the migration chain and before THIS
// process serves, but the deployment is not this process: the Kubernetes page tells operators
// to run several replicas, so the replicas already up are serving while this one starts, and
// both the account and the admin email endpoints write users.email. So the opening scan is a
// candidate list rather than a decision, every group is re-read immediately before it is
// written, and every write is guarded on the address that re-read saw. See
// convergeEmailGroup, which is where the whole of that lives.
//
// Any error is fatal to startup. It returns the number of rows lowercased and the number
// disabled.
func (d *CommonDatabase) BackfillLowercaseEmails() (int, int, error) {

	// One scan, filtered in Go. A SQL predicate would be wrong on SQLite for the reason above,
	// and only the rows that differ from their own lowercase form are retained, so what is held
	// in memory is the legacy residue rather than the users table.
	//
	// Ids and addresses only, deliberately: nothing this scan reads decides anything. The
	// address is here because it is what keys the group, and the id is what re-reads the row.
	// `enabled` is NOT read, because reading it here is what would let a row concurrently
	// re-enabled after the scan be skipped as though it were still off.
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "email").From("users")
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(nil, query, args...)
	if err != nil {
		return 0, 0, errors.Wrap(err, "unable to query users for the lowercase email backfill")
	}

	// Rows sharing a lowercased address are one group, and the whole of the collision policy is
	// about a group with more than one member. Collected fully before any UPDATE is issued:
	// SQLite is configured with a single connection and cannot write while a result set is open
	// on it, which is BackfillEncryptedOTPSecrets' own constraint.
	candidates := map[string][]int64{}
	for rows.Next() {
		var id int64
		var email string
		if err := rows.Scan(&id, &email); err != nil {
			_ = rows.Close()
			return 0, 0, errors.Wrap(err, "unable to scan user email")
		}
		lowered := strings.ToLower(email)
		if email == lowered {
			continue
		}
		candidates[lowered] = append(candidates[lowered], id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, 0, errors.Wrap(err, "error iterating users for the lowercase email backfill")
	}
	_ = rows.Close()

	// Sorted so a run's log lines come out in the same order twice. The rule itself does not
	// depend on the order: no group can affect another, since a row belongs to exactly one.
	lowercased := make([]string, 0, len(candidates))
	for lowered := range candidates {
		lowercased = append(lowercased, lowered)
	}
	sort.Strings(lowercased)

	rowsLowercased, rowsDisabled := 0, 0
	for _, lowered := range lowercased {
		groupLowercased, groupDisabled, err := d.convergeEmailGroup(lowered, candidates[lowered])
		rowsLowercased += groupLowercased
		rowsDisabled += groupDisabled
		if err != nil {
			return rowsLowercased, rowsDisabled, err
		}
	}

	return rowsLowercased, rowsDisabled, nil
}

// convergeEmailGroup brings one group of addresses differing only by case to its settled
// state: the survivor holds the lowercased address, and every other member is disabled with
// its own address left exactly as it stands. It reports how many rows it lowercased and how
// many it disabled.
//
// THE GROUP IS RE-READ HERE, and that is the point of the function existing. The opening scan
// found these ids, but a scan is not a decision: another replica of the same deployment is
// serving while this one starts, and both the account and the admin email endpoints write
// users.email. Two things go wrong if the cached rows are written instead of re-read ones. The
// survivor UPDATE, constrained only by id, puts the collision's address back over an address a
// user had just changed to. And a loser is disabled and has every credential it holds revoked
// after somebody has already resolved the collision by hand, which is the more expensive of the
// two because it takes something away from an account nobody asked about (#283).
//
// The re-read and the guards are one mechanism and neither half works alone. A re-read followed
// by an unguarded write only narrows the window; a guarded write with no re-read would refuse
// to act on a row whose address had merely been lowercased by someone else and never notice
// that the survivor had changed.
//
// A guard reporting no row is not a failure and is not an error. It means somebody wrote that
// row between this attempt's read and its write, so the decision was computed against a state
// that no longer exists. The loop recomputes it against the state that does, which is also why
// a mismatch cannot be answered by skipping the row: a member leaving the group changes who
// the survivor is, so the whole group has to be decided again.
//
// GIVING UP AFTER emailGroupAttempts IS NOT THE FAIL-CLOSED PATH, and it is deliberately not
// an error. Failing here aborts startup, and the residue left behind is not a regression: the
// rows still spelled in mixed case are rows no credential path could reach before this change
// either, because every path lowercases the address it looks up. On MySQL and SQL Server the
// question does not arise, since the folding UNIQUE index has never permitted a case-variant
// pair, so a group there has one member, the only write is the survivor's, and exhausting the
// attempts would need a writer to store a MIXED-CASE address, which none does. The pass is
// idempotent and resumable, so the next restart picks the group up.
func (d *CommonDatabase) convergeEmailGroup(lowered string, candidates []int64) (int, int, error) {
	rowsLowercased, rowsDisabled := 0, 0

	for attempt := 1; attempt <= emailGroupAttempts; attempt++ {
		members, err := d.readEmailGroup(lowered, candidates)
		if err != nil {
			return rowsLowercased, rowsDisabled, err
		}
		if len(members) == 0 {
			// Nothing spells this address in any case any more, so there is no group and
			// nothing to converge. Reached when every candidate was concurrently renamed, and
			// on the retry after the last member of a group left it.
			return rowsLowercased, rowsDisabled, nil
		}

		survivor := pickEmailSurvivor(members)
		stale := false

		if survivor.email != lowered {
			moved, err := d.trySetUserEmail(survivor.id, survivor.email, lowered)
			if err != nil {
				return rowsLowercased, rowsDisabled,
					errors.Wrapf(err, "unable to lowercase the email of user id %d", survivor.id)
			}
			if moved {
				rowsLowercased++
			} else {
				stale = true
			}
		}

		if !stale {
			for _, member := range members {
				if member.id == survivor.id {
					continue
				}
				// Already disabled rows are skipped, and that is what makes a second run
				// report nothing: a non-survivor keeps its mixed-case address deliberately, so
				// it is selected by every later scan and would otherwise be counted again each
				// time. Read at this attempt's re-read, never at the opening scan.
				if !member.enabled {
					continue
				}

				transitioned, err := d.disableAndRevoke(member.id, member.email)
				if err != nil {
					return rowsLowercased, rowsDisabled,
						errors.Wrapf(err, "unable to disable duplicate email user id %d", member.id)
				}
				if !transitioned {
					stale = true
					break
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

		if !stale {
			return rowsLowercased, rowsDisabled, nil
		}
	}

	slog.Warn("gave up lowercasing a group of email addresses differing only by case, because the rows kept changing while the pass ran",
		"email", lowered, "attempts", emailGroupAttempts)

	return rowsLowercased, rowsDisabled, nil
}

// readEmailGroup returns the rows that spell lowered in some case RIGHT NOW: the candidates the
// opening scan found, filtered down to the ones still in the group, plus the row already
// spelled in lowercase.
//
// The candidate set is a superset of the group and stays one, which is what makes reading by id
// sufficient rather than merely helpful. A row can only LEAVE: every write path stores a
// trimmed, lowercased address, so nothing can write a new MIXED-CASE member in. The one member
// the scan cannot have seen is the row already spelled in lowercase, because the scan keeps only
// rows that differ from their own lowercase form, and `email = lowered` is what fetches that
// one. There is no portable way to ask for the group directly: a LOWER(email) predicate maps
// ASCII only on SQLite through modernc.org/sqlite, which is the same reason the whole pass
// decides in Go.
//
// The Go comparison on the way out is not redundant. MySQL and SQL Server fold case in `=`, so
// the exact-match term answers with every case variant of the address; SQL Server also pads for
// `=` under every collation, BIN2 included, so 'a@x.com ' would come back as well, and both
// engines compare NFC and NFD spellings of an accented character equal. A row the ENGINE
// believes is a member is one only if Go's ToLower agrees. Trusting the engine here would make
// the pass pick a survivor the group does not contain (#283, and see engineFoldedTheMatch).
func (d *CommonDatabase) readEmailGroup(lowered string, candidates []int64) ([]emailRow, error) {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "email", "enabled").From("users")

	// The exact-match term is unconditional and the id term is not: an empty IN () is a syntax
	// error on all four engines, and this runs at startup where that would be a crash.
	terms := []string{sb.Equal("email", lowered)}
	if len(candidates) > 0 {
		terms = append(terms, sb.In("id", sqlbuilder.Flatten(candidates)...))
	}
	sb.Where(sb.Or(terms...))

	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(nil, query, args...)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to look up the users holding email %q", lowered)
	}
	defer func() { _ = rows.Close() }()

	members := make([]emailRow, 0, len(candidates)+1)
	for rows.Next() {
		var r emailRow
		if err := rows.Scan(&r.id, &r.email, &r.enabled); err != nil {
			return nil, errors.Wrapf(err, "unable to scan a user holding email %q", lowered)
		}
		if strings.ToLower(r.email) != lowered {
			continue
		}
		members = append(members, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrapf(err, "error iterating users holding email %q", lowered)
	}

	return members, nil
}

// trySetUserEmail writes desired over one row's address, but only while that row still holds
// expected, and reports whether it did.
//
// Compare-and-set on the ADDRESS and not only on the id, because the id identifies the row
// while saying nothing about whether the decision computed against it still applies. Without
// the second term this statement puts a collision's address back over an address a user changed
// concurrently, and reports it as a row lowercased.
//
// SQL Server pads for `=` under every collation, so a row whose address had gained trailing
// spaces since the re-read would still satisfy the guard. Nothing can produce that today,
// because every write path trims, and it is named here because no collation closes padding: a
// future write path that stopped trimming would reopen it (see engineFoldedTheMatch).
func (d *CommonDatabase) trySetUserEmail(userId int64, expected string, desired string) (bool, error) {
	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(ub.Assign("email", desired))
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("email", expected),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(nil, query, args...)
	if err != nil {
		return false, err
	}

	// Rows CHANGED rather than rows matched on MySQL, which is the same number here: the caller
	// only issues this when desired differs from expected, so a matching row always changes.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when lowercasing a user email")
	}

	return rowsAffected == 1, nil
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
// ONE TRANSACTION IS THE WHOLE OF THE SAFETY HERE. Every write below has to fail with the
// disable or land with it: a disable that committed while the revocation did not would leave
// exactly the state this function exists to prevent, a row that looks dealt with holding live
// credentials at a generation the user still matches. Whether each write is enlisted is not
// visible in the successful path's result, which is why the scripted-driver tests assert it
// directly rather than by observing the rows afterwards.
//
// Compare-and-set on the address as well as on enabled, so a row somebody else disabled first,
// or renamed out of the collision first, is neither counted again nor given a second generation
// advance. A false return therefore means one of three things and the caller treats them
// identically, by recomputing the group: already disabled, address moved, row gone.
//
// It also emits AuditRevokedUserAuthState, once per transition, after the commit. That is the
// second half of the same invariant #106 established: the four credential sites do not merely
// revoke, they attest to having revoked, so a forced logout is never invisible to whoever has
// to explain it afterwards. See auditRevokedUserAuthState.
func (d *CommonDatabase) disableAndRevoke(userId int64, expectedEmail string) (bool, error) {
	transitioned := false
	swept := revocationSweep{
		TerminatedSessionIdentifiers: []string{},
		RevokedRefreshTokenJtis:      []string{},
	}

	err := d.inTransaction(nil, func(tx *sql.Tx) error {
		var err error
		transitioned, err = d.tryDisableUserWithEmail(tx, userId, expectedEmail)
		if err != nil {
			return err
		}
		if !transitioned {
			// Nothing was taken away, so there is nothing to revoke, and advancing the
			// generation here would evict credentials a previous disable has already dealt
			// with, or credentials of an account this pass no longer has any business touching.
			return nil
		}

		newGeneration, err := d.IncrementUserAuthStateGeneration(tx, userId)
		if err != nil {
			return err
		}
		swept.NewGeneration = newGeneration
		// Derived rather than read beforehand, which is RevokeUserAuthState's own reasoning
		// (#106): an ordinary SELECT is not a locking read, so a value read before the
		// increment can be one another writer has already moved away from, while new-1 is by
		// construction the generation THIS increment invalidated.
		swept.OldGeneration = newGeneration - 1

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
			// Recorded after the write, so the list names what this call TRANSITIONED rather
			// than what the user held. A token already revoked is skipped above and stays
			// absent, which is revokeRefreshTokens' rule at the four other sites.
			swept.RevokedRefreshTokenJtis = append(swept.RevokedRefreshTokenJtis, rt.RefreshTokenJti)
		}

		sessions, err := d.GetUserSessionsByUserId(tx, userId)
		if err != nil {
			return err
		}
		for i := range sessions {
			if err := d.DeleteUserSession(tx, sessions[i].Id); err != nil {
				return err
			}
			swept.TerminatedSessionIdentifiers = append(
				swept.TerminatedSessionIdentifiers, sessions[i].SessionIdentifier)
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	// AFTER the commit and only on a real transition, which is the contract
	// constants.AuditRevokedUserAuthState states and the four credential sites keep. Emitting
	// inside the transaction would record a revocation that a later rollback undid, and
	// emitting on a false return would record one that never happened.
	if transitioned {
		d.auditRevokedUserAuthState(userId, swept)
	}

	return transitioned, nil
}

// revocationSweep is what one disableAndRevoke transaction took away, collected so the audit
// event can name it. It mirrors handlers.RevocationResult field for field, minus
// PreservedSessionIdentifier, which is always "" here: that exception exists so an
// administrator does not sign themselves out, and nobody is signed in during a startup pass.
//
// Both slices are initialised rather than left nil, so an account that held nothing logs []
// instead of null and a consumer never has to tell "swept nothing" from "field absent". That is
// LogRevokedUserAuthState's rule and the reason it is worth repeating is that the two payloads
// are read by the same consumer.
type revocationSweep struct {
	TerminatedSessionIdentifiers []string
	RevokedRefreshTokenJtis      []string
	OldGeneration                int64
	NewGeneration                int64
}

// auditRevokedUserAuthState emits AuditRevokedUserAuthState for one collision loser.
//
// #106 decision 7 made the event mandatory for the action rather than for the endpoint: it is
// emitted by every site that invalidates a user's live authentication state, so that a forced
// logout never happens without a trace. The four credential sites reach it through
// handlers.LogRevokedUserAuthState. This one cannot, because that helper and AuditLogger both
// live in the authserver module and core cannot import it, so the payload is written out here
// and the shape is kept identical field for field. A consumer matching on
// revoked_user_auth_state finds the same keys whichever site produced the row, and tells them
// apart by `reason` as the event's contract says.
//
// WHY THE RECORD MATTERS MORE HERE THAN AT THE OTHER FOUR. Those four are things a person did
// and can account for. This one is the server disabling an account and destroying every
// credential it held, at startup, because two addresses differed only by case, with nobody
// asking (decision 10 records that reservation about the action itself). The slog.Warn beside
// it is not a substitute: it is a startup log line in a process a rolling deployment may
// already have replaced, while this row is in audit_logs where the admin console queries it.
//
// NON-FATAL, deliberately, and that is AuditLogger.Log's behaviour rather than a weaker
// standard adopted here: it logs a failure to persist and returns, so a full disk in the audit
// path cannot take an authentication server down. The same reasoning is stronger at startup,
// where returning an error aborts the boot. What is NOT sacrificed is ordering: the revocation
// is already committed and durable before this runs, so a lost audit row costs the trace and
// never the action.
func (d *CommonDatabase) auditRevokedUserAuthState(userId int64, swept revocationSweep) {
	details := map[string]interface{}{
		"userId": userId,
		"reason": constants.RevocationReasonEmailCollisionBackfill,
		// "" rather than absent, matching the other four: no administrator is acting here, and
		// a consumer reading this field gets the same type from every site.
		"loggedInUser":                 "",
		"terminatedSessionIdentifiers": swept.TerminatedSessionIdentifiers,
		"revokedRefreshTokenJtis":      swept.RevokedRefreshTokenJtis,
		"preservedSessionIdentifier":   "",
		"oldGeneration":                swept.OldGeneration,
		"newGeneration":                swept.NewGeneration,
	}

	// Both targets, in AuditLogger.Log's order, so the operator's audit configuration decides
	// where this event goes exactly as it decides for the other four. A site that ignored the
	// settings would be the one event an operator could not turn off, or could not turn on.
	settings, err := d.GetSettingsById(nil, 1)
	if err != nil {
		slog.Error("failed to read settings for audit logging",
			"error", err, "event", constants.AuditRevokedUserAuthState)
		return
	}
	if settings == nil {
		// No settings row at all, which is a real state and not a defensive branch: no
		// migration writes that row, the SEEDER does, and the seeder runs after this pass. So
		// a first-ever boot reaches here. It reaches here having disabled nobody, because a
		// database with no settings row has no users either, so what this branch loses is an
		// event that had nothing to attest. Warn rather than fail: an unauditable revocation
		// is still a revocation that already committed.
		slog.Warn("no settings row, so a revocation could not be audited",
			"event", constants.AuditRevokedUserAuthState, "userId", userId)
		return
	}

	if settings.AuditLogsInConsoleEnabled {
		evt := struct {
			AuditEvent string                 `json:"audit_event"`
			Details    map[string]interface{} `json:"details"`
		}{AuditEvent: constants.AuditRevokedUserAuthState, Details: details}

		eventJSON, err := json.Marshal(evt)
		if err != nil {
			slog.Error("failed to marshal audit event",
				"error", err, "event", constants.AuditRevokedUserAuthState)
		} else {
			slog.Info(string(eventJSON))
		}
	}

	if settings.AuditLogsInDatabaseEnabled {
		detailsJSON, err := json.Marshal(details)
		if err != nil {
			slog.Error("failed to marshal audit event details for DB",
				"error", err, "event", constants.AuditRevokedUserAuthState)
			return
		}
		// nil tx on purpose: the revocation's transaction is committed and gone, and enlisting
		// the audit row in a new one would buy nothing to be atomic with.
		//
		// insertAuditLogWithoutId rather than CreateAuditLog, and the difference is not
		// cosmetic: a self-call from inside commondb cannot reach the PostgreSQL and SQL Server
		// overrides of CreateAuditLog, so on those two engines it would take the id-reading
		// implementation their drivers cannot satisfy and report every successful write as a
		// failure. See insertAuditLogWithoutId.
		if err := d.insertAuditLogWithoutId(nil, &models.AuditLog{
			AuditEvent: constants.AuditRevokedUserAuthState,
			Details:    string(detailsJSON),
		}); err != nil {
			slog.Error("failed to persist audit log to database",
				"error", err, "event", constants.AuditRevokedUserAuthState)
		}
	}
}

// tryDisableUserWithEmail is TrySetUserEnabled's compare-and-set with the address in the
// predicate too: enabled goes true to false only while the row still holds expectedEmail. It
// sets updated_at because TrySetUserEnabled does, and this replaces that call rather than
// adding to it.
//
// Written out here instead of calling TrySetUserEnabled because the guard has to be IN the
// statement. A SELECT that checked the address first would not be equivalent even inside this
// transaction: PostgreSQL and SQL Server run READ COMMITTED by default, so another transaction
// can commit an address change between that SELECT and this UPDATE and this UPDATE would still
// fire. TrySetUserEnabled itself is not given an extra predicate because it is on the Database
// interface and every other caller wants the two-term compare-and-set it has.
//
// The padding caveat in trySetUserEmail applies to this statement's address term as well.
func (d *CommonDatabase) tryDisableUserWithEmail(tx *sql.Tx, userId int64, expectedEmail string) (bool, error) {
	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("enabled", false),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("enabled", true),
		ub.Equal("email", expectedEmail),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to disable the user holding a duplicate email")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when disabling a duplicate email user")
	}

	return rowsAffected == 1, nil
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
