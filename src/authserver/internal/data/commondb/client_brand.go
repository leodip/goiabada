package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// A client's brand (#812 decision 1): clients.brand_id is the brand the client's pages are drawn
// in, or NULL to follow whichever brand is the default. Every pointer to a brand is guarded by the
// settings row's lock: the default pointer's writers take it (brand.go), and so do the writer here
// and a brand's deletion, which puts the brand's clients back on the default before it deletes it.

var selectClientBrandId = statement{
	sqlite:   "SELECT brand_id FROM clients WHERE id = ?",
	mysql:    "SELECT brand_id FROM clients WHERE id = ?",
	postgres: "SELECT brand_id FROM clients WHERE id = $1",
	mssql:    "SELECT brand_id FROM clients WHERE id = @p1",
}

// setClientBrand binds the brand, the time, then the client's id; see SetClientBrand.
var setClientBrand = statement{
	sqlite:   "UPDATE clients SET brand_id = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE clients SET brand_id = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE clients SET brand_id = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE clients SET brand_id = @p1, updated_at = @p2 WHERE id = @p3",
}

// clearBrandFromClients puts a brand's clients back on the default; it binds the time, then the
// brand's id. See DeleteBrand.
var clearBrandFromClients = statement{
	sqlite:   "UPDATE clients SET brand_id = NULL, updated_at = ? WHERE brand_id = ?",
	mysql:    "UPDATE clients SET brand_id = NULL, updated_at = ? WHERE brand_id = ?",
	postgres: "UPDATE clients SET brand_id = NULL, updated_at = $1 WHERE brand_id = $2",
	mssql:    "UPDATE clients SET brand_id = NULL, updated_at = @p1 WHERE brand_id = @p2",
}

// selectClientPageBrand is the brand a client's pages are drawn in: its own, or the one the
// settings row points at. It binds the settings row's id, then the client's identifier. A client
// that is not there, or that has no brand of its own while the pointer is empty, joins to none.
var selectClientPageBrand = statement{
	sqlite: "SELECT " + qualifiedBrandColumns.sqlite + " FROM clients " +
		"LEFT JOIN settings ON settings.id = ? " +
		"INNER JOIN brands ON brands.id = COALESCE(clients.brand_id, settings.default_brand_id) " +
		"WHERE clients.client_identifier = ?",
	mysql: "SELECT " + qualifiedBrandColumns.mysql + " FROM clients " +
		"LEFT JOIN settings ON settings.id = ? " +
		"INNER JOIN brands ON brands.id = COALESCE(clients.brand_id, settings.default_brand_id) " +
		"WHERE clients.client_identifier = ?",
	postgres: "SELECT " + qualifiedBrandColumns.postgres + " FROM clients " +
		"LEFT JOIN settings ON settings.id = $1 " +
		"INNER JOIN brands ON brands.id = COALESCE(clients.brand_id, settings.default_brand_id) " +
		"WHERE clients.client_identifier = $2",
	mssql: "SELECT " + qualifiedBrandColumns.mssql + " FROM clients " +
		"LEFT JOIN settings ON settings.id = @p1 " +
		"INNER JOIN brands ON brands.id = COALESCE(clients.brand_id, settings.default_brand_id) " +
		"WHERE clients.client_identifier = @p2",
}

// countClientsPerBrand groups every client by the brand it is drawn in, its own or the one the
// settings row points at, in one statement, so the pointer and the clients are read together. It
// binds the settings row's id. Clients drawn in no brand group under NULL, which the reader skips.
var countClientsPerBrand = statement{
	sqlite: "SELECT COALESCE(clients.brand_id, settings.default_brand_id), COUNT(*) FROM clients " +
		"LEFT JOIN settings ON settings.id = ? " +
		"GROUP BY COALESCE(clients.brand_id, settings.default_brand_id)",
	mysql: "SELECT COALESCE(clients.brand_id, settings.default_brand_id), COUNT(*) FROM clients " +
		"LEFT JOIN settings ON settings.id = ? " +
		"GROUP BY COALESCE(clients.brand_id, settings.default_brand_id)",
	postgres: "SELECT COALESCE(clients.brand_id, settings.default_brand_id), COUNT(*) FROM clients " +
		"LEFT JOIN settings ON settings.id = $1 " +
		"GROUP BY COALESCE(clients.brand_id, settings.default_brand_id)",
	mssql: "SELECT COALESCE(clients.brand_id, settings.default_brand_id), COUNT(*) FROM clients " +
		"LEFT JOIN settings ON settings.id = @p1 " +
		"GROUP BY COALESCE(clients.brand_id, settings.default_brand_id)",
}

// SetClientBrand gives a client a brand of its own, or with an empty brandId puts it back on the
// default, and writes nothing else but updated_at (#812 decision 1). It is the column's writer:
// UpdateClient leaves it out (dont-update), so a whole-row save made from a copy read earlier
// cannot write back a brand changed since, and CreateClient writes only the empty brand every
// create path starts a client on.
//
// WHAT THE LOCK BUYS. DeleteBrand takes the settings row before it moves a brand's clients and
// deletes it, so an assignment and a deletion of the brand it assigns are serialized: whichever
// takes the row second reads what the first committed. An assignment that lands first is moved by
// the deletion and counted; one that comes second finds the brand gone and answers
// ErrBrandNotFound, instead of the engine error the foreign key would raise. The brand and the
// client's brand are read after the lock is taken, as MakeBrandDefault reads its brand, so on
// MySQL's REPEATABLE READ this is the first read of the caller's transaction.
//
// It answers whether it wrote. A client that already has that brand is not written, and neither is
// a client that is not there, which is reported as no change: its caller reads the row back to
// answer, as AcquireClientRow's callers do.
func (d *Database) SetClientBrand(ctx context.Context, tx *sql.Tx, clientId int64, brandId sql.NullInt64) (bool, error) {

	if tx == nil {
		return false, errs.New("setting a client's brand requires a transaction: the settings row's lock lasts as long as it does")
	}
	if clientId == 0 {
		return false, errs.New("can't set the brand of a client with an id of 0")
	}

	if err := d.AcquireSettingsRow(ctx, tx, initialSettingsId); err != nil {
		return false, err
	}

	if brandId.Valid {
		brand, err := d.GetBrandById(ctx, tx, brandId.Int64)
		if err != nil {
			return false, err
		}
		if brand == nil {
			return false, errs.WithStack(data.ErrBrandNotFound)
		}
	}

	current, found, err := d.readClientBrandId(ctx, tx, clientId)
	if err != nil {
		return false, err
	}
	if !found || current == brandId {
		return false, nil
	}

	if _, err := d.ExecSQL(ctx, tx, setClientBrand.text(d.Dialect), brandId, time.Now().UTC(), clientId); err != nil {
		return false, errs.Wrap(err, "unable to set the client's brand")
	}
	return true, nil
}

// readClientBrandId reads one client's brand_id, and whether the client is there.
func (d *Database) readClientBrandId(ctx context.Context, tx *sql.Tx, clientId int64) (sql.NullInt64, bool, error) {
	var id sql.NullInt64
	rows, err := d.QuerySQL(ctx, tx, selectClientBrandId.text(d.Dialect), clientId)
	if err != nil {
		return id, false, errs.Wrap(err, "unable to read the client's brand")
	}
	defer func() { _ = rows.Close() }()

	found := rows.Next()
	if found {
		if err := rows.Scan(&id); err != nil {
			return id, false, errs.Wrap(err, "unable to scan the client's brand")
		}
	}
	if err := rows.Err(); err != nil {
		return id, false, errs.Wrap(err, "unable to read the client's brand")
	}
	return id, found, nil
}

// clearBrandFromClients puts every client given brandId back on the default, and answers how many
// it moved. DeleteBrand calls it under the settings row's lock.
func (d *Database) clearBrandFromClients(ctx context.Context, tx *sql.Tx, brandId int64) (int, error) {
	result, err := d.ExecSQL(ctx, tx, clearBrandFromClients.text(d.Dialect), time.Now().UTC(), brandId)
	if err != nil {
		return 0, errs.Wrap(err, "unable to move the brand's clients to the default")
	}
	moved, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when moving a brand's clients")
	}
	return int(moved), nil
}

// GetClientPageBrand answers the brand the pages of the client with this identifier are drawn in:
// its own brand, also when that brand is or stops being the default, or else the default brand. It
// answers nil for a client that is not there, and for one with no brand of its own while the
// settings row names no default.
func (d *Database) GetClientPageBrand(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Brand, error) {
	return queryOne(ctx, d, tx, selectClientPageBrand.text(d.Dialect),
		[]any{int64(initialSettingsId), clientIdentifier}, scanBrand, "brand")
}

// CountClientsPerBrand answers, by brand id, how many clients are drawn in each brand: those given
// it and, for the default brand, those with no brand of their own (#812 decision 3). A brand no
// client is drawn in is absent. With no default, a client with no brand of its own is counted in
// none.
func (d *Database) CountClientsPerBrand(ctx context.Context, tx *sql.Tx) (map[int64]int, error) {
	rows, err := d.QuerySQL(ctx, tx, countClientsPerBrand.text(d.Dialect), int64(initialSettingsId))
	if err != nil {
		return nil, errs.Wrap(err, "unable to count the clients of each brand")
	}
	defer func() { _ = rows.Close() }()

	counts := map[int64]int{}
	for rows.Next() {
		var brandId sql.NullInt64
		var count int
		if err := rows.Scan(&brandId, &count); err != nil {
			return nil, errs.Wrap(err, "unable to scan the clients of a brand")
		}
		if brandId.Valid {
			counts[brandId.Int64] = count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to count the clients of each brand")
	}
	return counts, nil
}
