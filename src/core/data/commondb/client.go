package commondb

import (
	"database/sql"
	"sort"
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

// AcquireClientRow takes the client's row and holds it for the rest of the caller's
// transaction. It is one unconditional UPDATE that writes nothing a reader can observe: the row's
// updated_at, which every caller of this overwrites moments later with its own write.
//
// WHAT IT BUYS, AND WHY A READ ALONE DOES NOT. A caller that re-reads a column to decide what to
// preserve, and then writes the whole row back, has two statements with a gap between them.
// Another transaction can commit inside that gap, and the write then carries the value read
// before that commit. `WHERE id = ?` alone matches under every engine's snapshot, so this
// statement waits out any in-flight writer and takes the row; a read after it sees what that
// writer committed, and no later writer can get between the read and the caller's write.
//
// Measured rather than assumed, on all four engines, in the agreement's
// probe/shared_writer_restores_public.out and probe/client_flip_cas_race.out: under MVCC (mysql,
// postgres) a bare re-read returns the last committed version without waiting at all, so the
// window is the other writer's whole transaction rather than the gap between two statements.
// SQL Server's shared locks narrow it but do not close it. Removing this call therefore reopens
// a window on three engines, and does so silently, because everything still passes when nothing
// else is writing (#245).
//
// SQLite is the one engine where the interleaving cannot be constructed: sqlitedb/db.go calls
// SetMaxOpenConns(1), so a second writer queues behind the open transaction rather than landing
// inside it.
//
// The transaction is required rather than optional. Without one the statement autocommits and
// drops the row before the caller's read runs, which is the whole of what this buys.
func (d *CommonDatabase) AcquireClientRow(tx *sql.Tx, clientId int64) error {

	if tx == nil {
		return errors.WithStack(errors.New("acquiring a client row requires a transaction: an autocommitted statement releases the row before the caller can read it"))
	}

	if clientId == 0 {
		return errors.WithStack(errors.New("can't acquire a client row with an id of 0"))
	}

	acquire := sqlbuilder.NewUpdateBuilder()
	acquire.Update("clients")
	acquire.Set(acquire.Assign("updated_at", time.Now().UTC()))
	acquire.Where(acquire.Equal("id", clientId))

	query, args := acquire.BuildWithFlavor(d.Flavor)
	if _, err := d.ExecSql(tx, query, args...); err != nil {
		return errors.Wrap(err, "unable to acquire client row")
	}

	// A client that is not there affects no rows and is not reported here. There is nothing to
	// hold, and every caller reads the row immediately afterwards, which is the one place that
	// decides whether the client still exists. Answering it twice would put the same sentence in
	// two places and let them disagree.
	return nil
}

// AcquireClientRowSharedWith is the body three of the four dialects' AcquireClientRowShared share:
// the two refusals, and the execution of the locking read each of them passes in. The statement
// itself is the one part with no portable spelling, so it lives in the dialect packages and this
// holds everything else, including the reason the whole thing exists. SQLite is the exception and
// delegates to AcquireClientRow instead, for the reason stated there.
//
// WHAT IT IS FOR. DeleteClient takes the clients row exclusively and then reads the sessions
// associated with it, so that list is complete only if no association can be inserted while it is
// held. Nothing made that true: user_session_clients rows are created outside the deletion, by
// StartNewUserSession and by BumpUserSession, each in its own transaction, and a foreign key
// reference is not a barrier against the exclusive acquisition on PostgreSQL, where an UPDATE
// touching no key column takes FOR NO KEY UPDATE and a foreign key check takes FOR KEY SHARE and
// the two do not conflict. So every transaction that writes an association row, or a code, takes
// this lock first, and the deletion's list is then closed by the lock rather than by a re-read
// (#139).
//
// WHY SHARED RATHER THAN THE EXCLUSIVE ACQUISITION. AcquireClientRow serializes its callers, and a
// clients row is shared by everybody using that application: every authorization code issued and
// every session bump for a popular client would queue on one row. Two shared holders do not
// conflict, so concurrent sign-ins are unaffected; a shared holder and the deletion do, which is
// the whole of what is wanted.
//
// THE OBLIGATION THIS PUTS ON ITS CALLERS, and it is not optional. Lock queues are fair: once the
// deletion's exclusive request is queued behind a shared holder, a later shared request queues
// behind the DELETION rather than joining the holder. So a caller that takes this lock and only
// afterwards reaches for something ABOVE clients in the branch's order can be part of a cycle even
// though nothing is ever upgraded and no two shared holders ever conflict. A caller must already
// hold everything above clients, INCLUDING locks it takes only through a foreign key, before it
// calls this. That is why StartNewUserSession calls AcquireUserRow first: its session insert takes
// a shared users lock through user_sessions.user_id without naming it, and without the leading
// acquisition the three-party schedule (issuance holding users and waiting for the client, a fresh
// session holding the client and waiting for users, the deletion queued exclusively on the client)
// deadlocks on MySQL.
//
// No caller ever upgrades this to the exclusive acquisition, which is the classic way a shared
// scheme deadlocks. DeleteClient and the admin client-update handlers take the exclusive lock as
// their first statement rather than promoting a shared one.
//
// The transaction is required for AcquireClientRow's stated reason: without one the statement
// autocommits and the lock is gone before the caller reaches anything it was meant to cover.
func (d *CommonDatabase) AcquireClientRowSharedWith(tx *sql.Tx, clientId int64, lockingRead string) error {

	if tx == nil {
		return errors.WithStack(errors.New("acquiring a client row shared requires a transaction: an autocommitted statement releases the lock before the caller can use it"))
	}

	if clientId == 0 {
		return errors.WithStack(errors.New("can't acquire a client row with an id of 0"))
	}

	// Run as a query rather than an exec, and drained, because it IS a SELECT: go-mssqldb leaves
	// the connection busy until the result set is consumed, and a lock taken by a statement whose
	// rows were never read is a connection this transaction cannot use afterwards.
	rows, err := d.QuerySql(tx, lockingRead, clientId)
	if err != nil {
		return errors.Wrap(err, "unable to acquire client row shared")
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return errors.Wrap(err, "unable to scan the acquired client row")
		}
	}

	if err := rows.Err(); err != nil {
		return errors.Wrap(err, "unable to read the acquired client row")
	}

	// A client that is not there locks nothing and is not reported, which is AcquireClientRow's own
	// answer to the same question: every caller either reads the row immediately afterwards or is
	// about to fail its own foreign key, and answering existence twice would let the two disagree.
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
// So the first statement is an acquisition and the second is the classification. The
// acquisition is AcquireClientRow, shared with the three endpoints that re-read these columns
// rather than classifying them (#245 decision 18), so the mechanism has one spelling and one
// explanation: `WHERE id = ?` alone matches under every engine's snapshot, so it waits out any
// in-flight writer and takes the row, and the conditional UPDATE after it evaluates against this
// transaction's own version, which was derived from the committed one.
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

	if err := d.AcquireClientRow(tx, clientId); err != nil {
		return false, err
	}

	now := time.Now().UTC()

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

	query, args := classify.BuildWithFlavor(d.Flavor)
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
	// The engine may have folded a value this lookup did not ask for; see
	// engineFoldedTheMatch. RFC 6749 section 1.9 makes client_id case sensitive.
	if client != nil && engineFoldedTheMatch(client.ClientIdentifier, clientIdentifier) {
		return nil, nil
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
//
// IT JOINS THE LOCK ORDER, AND AN EARLIER MEASUREMENT SAID IT NEED NOT. That
// measurement was honest and is now stale: this transaction was clean against the
// session-side transactions AS THEY STOOD, and #139 then made every one of them take
// the user_sessions row first, which puts that session's user_session_clients rows in
// their hands from their first statement. This transaction's cascade wants exactly
// those rows, and by the time it asks for one it is already holding that session's
// codes, which the other side is about to sweep. Each holds half of what the other
// wants: a deadlock on PostgreSQL, MySQL and SQL Server, with the session-side
// transaction chosen as the victim on the last two.
//
// The explicit refresh-token delete is what makes it a cycle rather than a race, and
// it is not redundant with the cascade: refresh_tokens.client_id is NO ACTION on all
// four engines and only refresh_tokens.code_id is CASCADE, so that statement really
// does take a client's ROPC-issued tokens before the cascade runs.
//
// SO THE ORDER IS TAKEN EXPLICITLY, AND IN THIS ORDER, WHICH IS THE BRANCH'S:
// clients, then user_sessions, then the grants.
//
//  1. The clients row, EXCLUSIVELY, because this transaction is removing it and must
//     exclude everything. Taking it first is also what makes the list below complete:
//     no association naming this client can be inserted while it is held, because
//     every inserter now takes the same row shared before it writes one
//     (AcquireClientRowShared). A fixed-point loop over re-reads could not close that
//     gap, since InnoDB fixes the consistent-read snapshot at the transaction's first
//     plain SELECT and a later one never sees an association committed in between.
//  2. The session rows, so that the cascade is not the first statement to want a row a
//     session-first transaction is already holding.
//  3. The two deletes it has always run.
//
// The sort is not decoration. GetUserSessionClientsByClientId carries no ORDER BY, and
// two overlapping deletions of different clients sharing a session would otherwise take
// the session rows in an order the engine chose, which is a cycle among sessions that no
// rule about the order of TABLES can reach.
func (d *CommonDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {

	return d.inTransaction(tx, func(tx *sql.Tx) error {
		if err := d.AcquireClientRow(tx, clientId); err != nil {
			return err
		}

		associations, err := d.GetUserSessionClientsByClientId(tx, clientId)
		if err != nil {
			return err
		}

		for _, userSessionId := range sortedDistinctSessionIds(associations) {
			if err := d.AcquireUserSessionRowById(tx, userSessionId); err != nil {
				return err
			}
		}

		if err := d.deleteRefreshTokensByColumn(tx, "client_id", clientId); err != nil {
			return err
		}

		clientStruct := sqlbuilder.NewStruct(new(models.Client)).
			For(d.Flavor)

		deleteBuilder := clientStruct.DeleteFrom("clients")
		deleteBuilder.Where(deleteBuilder.Equal("id", clientId))

		sql, args := deleteBuilder.Build()
		_, err = d.ExecSql(tx, sql, args...)
		if err != nil {
			return errors.Wrap(err, "unable to delete client")
		}

		return nil
	})
}

// sortedDistinctSessionIds is the order DeleteClient takes its session rows in: ascending,
// each id once. One client can appear on a session only once in practice, but nothing in the
// schema says so today (#249 is the constraint that would), so the deduplication is here
// rather than assumed.
func sortedDistinctSessionIds(associations []models.UserSessionClient) []int64 {
	seen := make(map[int64]struct{}, len(associations))
	ids := make([]int64, 0, len(associations))
	for _, association := range associations {
		if _, already := seen[association.UserSessionId]; already {
			continue
		}
		seen[association.UserSessionId] = struct{}{}
		ids = append(ids, association.UserSessionId)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
