package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreateClient(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.CreateClient(tx, client)
}

func (d *SQLiteDatabase) UpdateClient(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.UpdateClient(tx, client)
}

func (d *SQLiteDatabase) SetClientPublic(tx *sql.Tx, clientId int64) (bool, error) {
	return d.CommonDB.SetClientPublic(tx, clientId)
}

func (d *SQLiteDatabase) AcquireClientRow(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.AcquireClientRow(tx, clientId)
}

// AcquireClientRowShared is the EXCLUSIVE acquisition here, and the substitution costs nothing:
// SQLite has one writer, so there is no shared mode for it to be shared with. The exclusive
// acquisition is what the other three engines' shared statement conflicts with anyway, so this is
// the same order written in the only lock this engine has.
//
// IT IS ALSO A WRITE ON PURPOSE, and a plain locking SELECT here would be a regression rather than
// a cheaper equivalent. SQLite answers a transaction that read first and then tries to write with
// SQLITE_BUSY at once, without consulting the busy handler, so a `SELECT` here would turn every
// sign-in and every session bump into a reader upgrading to a writer: two of them overlapping
// would fail immediately instead of waiting. Unreachable in one process, where
// sqlitedb/db.go calls SetMaxOpenConns(1) and the two never overlap at all, and fail-closed
// across processes, but there is no reason to buy it. Measured: with the SELECT spelling, the
// data tier's discovery-barrier case fails here and passes everywhere else (#139).
func (d *SQLiteDatabase) AcquireClientRowShared(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.AcquireClientRow(tx, clientId)
}

func (d *SQLiteDatabase) GetClientById(tx *sql.Tx, clientId int64) (*models.Client, error) {
	return d.CommonDB.GetClientById(tx, clientId)
}

func (d *SQLiteDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*models.Client, error) {
	return d.CommonDB.GetClientByClientIdentifier(tx, clientIdentifier)
}

func (d *SQLiteDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadRedirectURIs(tx, client)
}

func (d *SQLiteDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadWebOrigins(tx, client)
}

func (d *SQLiteDatabase) GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]models.Client, error) {
	return d.CommonDB.GetClientsByIds(tx, clientIds)
}

func (d *SQLiteDatabase) ClientLoadPermissions(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadPermissions(tx, client)
}

func (d *SQLiteDatabase) GetAllClients(tx *sql.Tx) ([]models.Client, error) {
	return d.CommonDB.GetAllClients(tx)
}

func (d *SQLiteDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClient(tx, clientId)
}
