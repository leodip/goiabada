package postgresdb

// explicitIdInsertSQL is PostgreSQL's answer to "what does an INSERT naming its own id need around
// it". Nothing before it: a serial column takes an explicit value. One statement after it: the
// serial sequence moves only when nextval is called, so after an explicit id it would hand the
// same id out again and the next ordinary insert on the table would collide. setval puts it at the
// table's highest id, so the next nextval answers the one after.
//
// setval is not transactional, and does not need to be: a rollback leaves the sequence ahead of a
// table that has lost the row, and the next explicit insert sets it again (#424 decision 14). The
// migrating role owns the sequence, which is the privilege setval asks for.
//
// It is wired onto commondb.CommonDatabase in the constructor, beside insertReturningIdSQL, and
// commondb.CreateInitialSettings is its one caller. table is always a literal from that code,
// never input.
func explicitIdInsertSQL(table string) (before []string, after []string) {
	return nil, []string{
		"SELECT setval(pg_get_serial_sequence('" + table + "', 'id'), (SELECT MAX(id) FROM " + table + "))",
	}
}
