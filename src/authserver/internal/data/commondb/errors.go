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
