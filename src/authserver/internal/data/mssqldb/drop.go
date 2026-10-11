package mssqldb

import (
	"context"

	"github.com/leodip/goiabada/core/errs"
)

// DropDatabase drops the database cfg names, if there is one, over the maintenance connection.
// SQL Server refuses to drop a database with a session attached, so the batch first takes it to
// SINGLE_USER WITH ROLLBACK IMMEDIATE, which ends every other session.
//
// The server never calls it. It is the inverse of the CREATE DATABASE New issues,
// naming the database through the same quoteIdentifier and quoteLiteral, and it sits beside that
// so the tools that discard a database spell the drop once: schemadump's scratch databases, the
// data tier's fixtures, and droptestdb, which run-tests.sh runs before each tier so every local
// run starts from an empty database (#433).
func DropDatabase(ctx context.Context, cfg *DatabaseConfig) error {
	db, err := open(MaintenanceConnConfig(cfg))
	if err != nil {
		return errs.Wrap(err, "unable to open the maintenance connection")
	}
	defer func() { _ = db.Close() }()

	name := quoteIdentifier(cfg.Name)
	//nolint:gosec // G202: the name passes through quoteLiteral and quoteIdentifier; DROP DATABASE takes no parameter
	drop := "IF DB_ID(N" + quoteLiteral(cfg.Name) + ") IS NOT NULL BEGIN ALTER DATABASE " + name +
		" SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE " + name + "; END"
	if _, err := db.ExecContext(ctx, drop); err != nil {
		return errs.Wrap(err, "unable to drop database")
	}
	return nil
}
