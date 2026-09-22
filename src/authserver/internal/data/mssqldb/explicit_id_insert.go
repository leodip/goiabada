package mssqldb

// explicitIdInsertSQL is SQL Server's answer to "what does an INSERT naming its own id need around
// it". SQL Server refuses an explicit value in an IDENTITY column unless IDENTITY_INSERT is on for
// that table, and allows it on for one table per session at a time, so the insert is bracketed by
// switching it on and back off. An explicit id above the identity's current value moves the
// identity up to it, so nothing is needed for the ids handed out afterwards.
//
// The setting belongs to the connection, which is why commondb.CreateInitialSettings, its one
// caller, runs the three statements on a transaction and refuses to run without one. A failure
// between the two leaves the setting on for a connection whose transaction is rolling back;
// go-mssqldb resets the session before the pool hands that connection out again (#424 decision
// 14). db_owner, which the application's login holds in its own database, carries the ALTER
// permission the statement needs.
//
// It is wired onto commondb.CommonDatabase in the constructor, beside insertReturningIdSQL. table
// is always a literal from the caller's code, never input.
func explicitIdInsertSQL(table string) (before []string, after []string) {
	return []string{"SET IDENTITY_INSERT " + table + " ON"},
		[]string{"SET IDENTITY_INSERT " + table + " OFF"}
}
