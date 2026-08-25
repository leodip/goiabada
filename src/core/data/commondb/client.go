package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateClient(tx *sql.Tx, client *models.Client) error {

	now := time.Now().UTC()

	originalCreatedAt := client.CreatedAt
	originalUpdatedAt := client.UpdatedAt
	client.CreatedAt = sql.NullTime{Time: now, Valid: true}
	client.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	insertBuilder := clientStruct.WithoutTag("pk").InsertInto("clients", client)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert client")
	}

	id, err := result.LastInsertId()
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	client.Id = id
	return nil
}

func (d *CommonDatabase) UpdateClient(tx *sql.Tx, client *models.Client) error {

	if client.Id == 0 {
		return errors.WithStack(errors.New("can't update client with id 0"))
	}

	originalUpdatedAt := client.UpdatedAt
	client.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	updateBuilder := clientStruct.WithoutTag("pk").WithoutTag("dont-update").Update("clients", client)
	updateBuilder.Where(updateBuilder.Equal("id", client.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update client")
	}

	return nil
}

// SetClientPublic makes one client public and reports whether THIS call performed the
// confidential-to-public transition. That transition is the write that removes the client's
// obligation to authenticate, so it is the one whose caller must revoke the grants issued while
// a secret was still required (#245). A save of a client that was already public takes nothing
// away and reports false, which is what stops an administrator re-saving a form from signing
// every user of the application out.
//
// WHY THE ANSWER IS NOT A READ. The obvious shape is to load the row, compare, then write. It
// does not hold: the load and the write are separate statements, and another request can commit
// confidential mode and issue a grant under the secret it created in between. The classification
// then comes from the stale side, reads "already public", and the transaction commits a public
// client still holding grants that only a secret could have redeemed.
//
// WHY IT IS TWO STATEMENTS AND NOT ONE. The conditional UPDATE below is the classification: the
// row it affects is the transition, and affecting none means there was nothing to change. On
// MySQL and SQL Server that statement alone is enough, because both wait for the in-flight
// writer and re-evaluate the predicate against the row it committed. PostgreSQL does not.
// Its READ COMMITTED mode finds target rows from the snapshot as of command start, so a row
// whose committed version still says public is never a target of `AND is_public = <false>`: the
// statement neither waits nor re-evaluates, and reports zero while the unconditional write that
// follows it blocks, unblocks and commits public anyway. Measured on all four engines in
// probe/client_flip_cas_race.out.
//
// So the first statement is an acquisition and the second is the classification. `WHERE id = ?`
// alone matches under every engine's snapshot, so it waits out any in-flight writer and takes
// the row; the conditional UPDATE after it then evaluates against this transaction's own
// version, which was derived from the committed one. It writes updated_at because the flip's
// own client write overwrites that column moments later regardless, so the acquisition adds
// nothing a reader can observe.
//
// The transaction is required rather than optional, for the reason RevokeClientGrants states
// about its own: without one, each statement autocommits and the acquisition drops its lock
// before the classification runs, which is the whole mechanism.
func (d *CommonDatabase) SetClientPublic(tx *sql.Tx, clientId int64) (bool, error) {

	if tx == nil {
		return false, errors.WithStack(errors.New("making a client public requires a transaction: the row must be held between acquiring it and classifying the write"))
	}

	if clientId == 0 {
		return false, errors.WithStack(errors.New("can't make a client public with an id of 0"))
	}

	now := time.Now().UTC()

	acquire := sqlbuilder.NewUpdateBuilder()
	acquire.Update("clients")
	acquire.Set(acquire.Assign("updated_at", now))
	acquire.Where(acquire.Equal("id", clientId))

	query, args := acquire.BuildWithFlavor(d.Flavor)
	if _, err := d.ExecSql(tx, query, args...); err != nil {
		return false, errors.Wrap(err, "unable to acquire client row before making it public")
	}

	classify := sqlbuilder.NewUpdateBuilder()
	classify.Update("clients")
	classify.Set(
		classify.Assign("is_public", true),
		classify.Assign("updated_at", now),
	)
	classify.Where(
		classify.Equal("id", clientId),
		classify.Equal("is_public", false),
	)

	query, args = classify.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to make client public")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when making client public")
	}
	if rowsAffected == 1 {
		return true, nil
	}

	// Zero rows has two causes and only one of them is an error, so they are told apart here
	// rather than reported as the same thing. This read DECIDES NOTHING about the transition:
	// that answer is already in hand above, and the row is held by the acquisition, so all this
	// can observe is whether there is a client to have saved at all.
	client, err := d.GetClientById(tx, clientId)
	if err != nil {
		return false, err
	}
	if client == nil {
		return false, errors.WithStack(errors.New("can't make a client public: no client with that id"))
	}
	return false, nil
}

func (d *CommonDatabase) getClientCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	clientStruct *sqlbuilder.Struct) (*models.Client, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var client models.Client
	if rows.Next() {
		addr := clientStruct.Addr(&client)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client")
		}
		return &client, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetClientById(tx *sql.Tx, clientId int64) (*models.Client, error) {

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.Equal("id", clientId))

	client, err := d.getClientCommon(tx, selectBuilder, clientStruct)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (d *CommonDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*models.Client, error) {

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.Equal("client_identifier", clientIdentifier))

	client, err := d.getClientCommon(tx, selectBuilder, clientStruct)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (d *CommonDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *models.Client) error {

	if client == nil {
		return nil
	}

	var err error
	client.RedirectURIs, err = d.GetRedirectURIsByClientId(tx, client.Id)
	if err != nil {
		return errors.Wrap(err, "unable to get redirect URIs")
	}

	return nil
}

func (d *CommonDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *models.Client) error {

	if client == nil {
		return nil
	}

	var err error
	client.WebOrigins, err = d.GetWebOriginsByClientId(tx, client.Id)
	if err != nil {
		return errors.Wrap(err, "unable to get web origins")
	}

	return nil
}

func (d *CommonDatabase) GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]models.Client, error) {

	if len(clientIds) == 0 {
		return []models.Client{}, nil
	}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(clientIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	clients := make([]models.Client, 0)
	for rows.Next() {
		var client models.Client
		addr := clientStruct.Addr(&client)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client")
		}
		clients = append(clients, client)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return clients, nil
}

func (d *CommonDatabase) ClientLoadPermissions(tx *sql.Tx, client *models.Client) error {

	if client == nil {
		return nil
	}

	clientPermissions, err := d.GetClientPermissionsByClientId(tx, client.Id)
	if err != nil {
		return err
	}

	permissionIds := make([]int64, 0)
	for _, clientPermission := range clientPermissions {
		permissionIds = append(permissionIds, clientPermission.PermissionId)
	}

	client.Permissions, err = d.GetPermissionsByIds(nil, permissionIds)
	if err != nil {
		return err
	}

	return nil
}

func (d *CommonDatabase) GetAllClients(tx *sql.Tx) ([]models.Client, error) {

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	clients := make([]models.Client, 0)
	for rows.Next() {
		var client models.Client
		addr := clientStruct.Addr(&client)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client")
		}
		clients = append(clients, client)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return clients, nil
}

// DeleteClient removes the client and, by ON DELETE CASCADE, every row that
// references it. Refresh tokens are cleared explicitly first because SQL Server
// cannot cascade them: see deleteRefreshTokensByColumn.
func (d *CommonDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {

	return d.inTransaction(tx, func(tx *sql.Tx) error {
		if err := d.deleteRefreshTokensByColumn(tx, "client_id", clientId); err != nil {
			return err
		}

		clientStruct := sqlbuilder.NewStruct(new(models.Client)).
			For(d.Flavor)

		deleteBuilder := clientStruct.DeleteFrom("clients")
		deleteBuilder.Where(deleteBuilder.Equal("id", clientId))

		sql, args := deleteBuilder.Build()
		_, err := d.ExecSql(tx, sql, args...)
		if err != nil {
			return errors.Wrap(err, "unable to delete client")
		}

		return nil
	})
}
