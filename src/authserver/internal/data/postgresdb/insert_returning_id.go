package postgresdb

// insertReturningIdSQL is PostgreSQL's answer to "how does an INSERT report the id it generated".
// pgx's database/sql wrapper does not implement LastInsertId at all -- it returns an error -- so
// the id has to come back as a row, and RETURNING is how PostgreSQL says that.
//
// It is wired onto commondb.CommonDatabase in the constructor, beside IsDeadlock and
// IsUniqueViolation, and commondb.insertReturningId owns everything around it: the query, the
// scan, and the rows.Err() check that catches a constraint violation the driver deferred to the
// result set. This function is only the grammar (#416).
//
// The clause is appended rather than spliced because RETURNING is the last clause of an INSERT in
// PostgreSQL's grammar, which is what makes this the one-line half of the pair; SQL Server's
// OUTPUT sits in the middle and has to be.
//
// It cannot fail, and returns an error anyway because the other dialect's can. Giving both the
// same signature is what lets the field be one field.
func insertReturningIdSQL(insertSQL string) (string, error) {
	return insertSQL + " RETURNING id", nil
}
