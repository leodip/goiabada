package postgresdb

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/core/errs"
)

// DropDatabase drops the database cfg names, if there is one, over the maintenance connection.
// WITH (FORCE) ends any session still attached to it (PostgreSQL 13 and later), which a plain
// DROP DATABASE refuses to do.
//
// The server never calls it. It is the inverse of the CREATE DATABASE New issues,
// quoted the same way, because unquoted the name folds to lower case and a mixed-case database
// would silently survive its drop. It sits beside the create so the tools that discard a database
// spell the drop once: schemadump's scratch databases, the data tier's fixtures, and droptestdb,
// which run-tests.sh runs before each tier so every local run starts from an empty database (#433).
func DropDatabase(ctx context.Context, cfg *DatabaseConfig) error {
	db, err := sql.Open("pgx", MaintenanceDSN(cfg))
	if err != nil {
		return errs.Wrap(err, "unable to open the maintenance connection")
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdentifier(cfg.Name)+" WITH (FORCE)"); err != nil {
		return errs.Wrap(err, "unable to drop database")
	}
	return nil
}
