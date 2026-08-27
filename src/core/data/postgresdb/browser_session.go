package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

// CreateBrowserSession is written here rather than delegated because PostgreSQL has no
// LastInsertId: the id comes back through RETURNING, exactly as CreateCode does it.
func (d *PostgresDatabase) CreateBrowserSession(tx *sql.Tx, browserSession *models.BrowserSession) error {

	if browserSession.Owner == "" {
		return errors.WithStack(errors.New("can't create a browser session with an empty owner"))
	}

	if browserSession.SessionIdHash == "" {
		return errors.WithStack(errors.New("can't create a browser session with an empty session id hash"))
	}

	now := time.Now().UTC()

	originalCreatedAt := browserSession.CreatedAt
	originalUpdatedAt := browserSession.UpdatedAt
	browserSession.CreatedAt = sql.NullTime{Time: now, Valid: true}
	browserSession.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	browserSessionStruct := sqlbuilder.NewStruct(new(models.BrowserSession)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := browserSessionStruct.WithoutTag("pk").InsertInto("browser_sessions", browserSession)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		browserSession.CreatedAt = originalCreatedAt
		browserSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert browser session")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&browserSession.Id)
		if err != nil {
			browserSession.CreatedAt = originalCreatedAt
			browserSession.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan browser session id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		browserSession.CreatedAt = originalCreatedAt
		browserSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert browser session")
	}

	return nil
}

func (d *PostgresDatabase) GetBrowserSessionByOwnerAndSessionIdHash(tx *sql.Tx, owner, sessionIdHash string,
	now time.Time) (*models.BrowserSession, error) {
	return d.CommonDB.GetBrowserSessionByOwnerAndSessionIdHash(tx, owner, sessionIdHash, now)
}

func (d *PostgresDatabase) UpdateBrowserSessionData(tx *sql.Tx, owner, sessionIdHash, data string,
	now, expiresAt time.Time) (bool, error) {
	return d.CommonDB.UpdateBrowserSessionData(tx, owner, sessionIdHash, data, now, expiresAt)
}

func (d *PostgresDatabase) TouchBrowserSession(tx *sql.Tx, owner, sessionIdHash string,
	now, expiresAt time.Time) (bool, error) {
	return d.CommonDB.TouchBrowserSession(tx, owner, sessionIdHash, now, expiresAt)
}

func (d *PostgresDatabase) DeleteBrowserSession(tx *sql.Tx, owner, sessionIdHash string) error {
	return d.CommonDB.DeleteBrowserSession(tx, owner, sessionIdHash)
}

func (d *PostgresDatabase) DeleteExpiredBrowserSessions(tx *sql.Tx, now time.Time) error {
	return d.CommonDB.DeleteExpiredBrowserSessions(tx, now)
}
