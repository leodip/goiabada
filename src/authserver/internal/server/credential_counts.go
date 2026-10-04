package server

import (
	"github.com/leodip/goiabada/authserver/internal/data"
)

// sharedCredentialCounts is where the five credential tiers count, chosen by engine with no setting
// (#394 decision 2). On PostgreSQL, MySQL and SQL Server it is the database every replica shares,
// so adding replicas or rolling out neither multiplies nor refills a budget; every deployment
// already has that database, so sharing adds no requirement. On SQLite it is nil, which counts in
// this process: SQLite cannot have a second replica, and the database would only add writes to its
// single connection.
//
// A type that names no engine never gets here, since the database could not have been opened; nil
// is answered for it all the same.
func sharedCredentialCounts(dbType string, database data.Database) data.Database {
	dialect, err := data.ParseDialect(dbType)
	if err != nil || dialect == data.SQLite {
		return nil
	}
	return database
}
