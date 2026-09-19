package models

// EmailCaseRow is one users row as the startup pre-flight reads it, and the one projection in
// this package rather than a table: no column maps to EngineLowered, and nothing writes an
// EmailCaseRow back.
//
// It exists because the question the pre-flight asks cannot be answered from the stored address
// alone. Migration 000047 reduces addresses with `LOWER(email)`, which is the ENGINE's idea of
// lowercase, while every credential path looks a user up by Go's strings.ToLower of what it was
// given. Where the two disagree the migration reports success and leaves a row no sign-in can
// reach: SQLite's LOWER() maps ASCII only through modernc.org/sqlite, and SQL Server's leaves
// U+1E9E and U+212A unchanged at the collation 000040 installs. So the row has to arrive carrying
// both forms, and the comparison happens in Go where it is one rule on four engines (#351).
type EmailCaseRow struct {
	Id int64
	// Email is the address exactly as stored.
	Email string
	// EngineLowered is LOWER(email) as THIS engine computed it, which is what migration 000047's
	// predicate compares against and therefore what decides whether the row is repaired.
	EngineLowered string
}
