package commondb

import "errors"

// ErrUniqueViolation is what a caller asks about when it wants to know whether a write lost a race
// for a unique key: an insert or an update the engine refused because some unique index already
// holds that value.
//
// It exists so that question has one answer on all four engines. Each driver reports the violation
// its own way -- SQLite code 2067, MySQL 1062, PostgreSQL SQLSTATE 23505, SQL Server 2627 or 2601,
// by value or by pointer -- and before this the one caller that cared read the driver's English
// sentence looking for the words "email" and "already", which matched none of the four engines'
// actual texts and so had never once fired. WrapSQLError tags a classified failure with this
// sentinel on the way out of the data layer, so every caller above it asks errors.Is and nothing
// else (#279).
//
// It is a plain stdlib errors.New, and it is the one shape testutil.AssertNoLegacyErrors exempts: a
// package-level sentinel must carry no stack, because a stack captured at init records the
// program's startup rather than the failure, and would then masquerade as the origin of every error
// wrapping it.
//
// It says nothing about WHICH key was violated. A caller that needs to distinguish two unique keys
// on one table has to look at the driver error itself, which is still reachable through errors.As
// below this.
var ErrUniqueViolation = errors.New("unique constraint violation")

// ErrIndeterminateCommit is what a caller asks about when it needs to know whether the rows its
// transaction wrote might be in the database after RunInTransaction returned an error. It tags a
// commit that failed for a reason the engine did not declare, where the server may have committed
// before the failure reached the client and the client cannot tell which happened.
//
// It exists because the distinction was decidable only from the error's TEXT before this. A body
// failure and an ambiguous commit both arrived as a plain error, so a caller that owed a
// reconciliation had no way to ask which one it was holding, and matching the sentence is the
// thing pattern 7 exists to stop.
//
// A deadlock is deliberately NOT tagged. The engine DECLARED that abort, so the transaction is
// known to have rolled back; RunInTransaction reruns it, and the error that surfaces when three
// attempts are exhausted names an outcome that is certain rather than unknown.
//
// The tag is not an instruction to retry, and nothing in the tree retries on it: replaying a body
// that may already have been applied is the hazard, not the remedy. What it licenses is a
// reconciliation keyed on a name the caller minted OUTSIDE the transaction -- read whether the row
// is there, act on the answer -- which is the only question that has a reliable answer afterwards.
// An id the insert returned is not such a name: it was assigned on a connection whose work may have
// vanished, and on an engine that reuses rowids it can later name someone else's row.
//
// Only a caller whose committed rows are reachable only through a step AFTER the commit owes
// anything here. StartNewUserSession is that caller: its row is named by a cookie the browser
// never receives when the ceremony fails, so an ambiguous commit leaves a session nobody can reach
// sitting in the admin console's list until its idle timeout (#198).
//
// It is a plain stdlib errors.New for the reason ErrUniqueViolation above it is.
var ErrIndeterminateCommit = errors.New("commit outcome unknown")
