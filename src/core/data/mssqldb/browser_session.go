package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

// CreateBrowserSession is written here rather than delegated because SQL Server has no
// LastInsertId: the id comes back through OUTPUT INSERTED.id, exactly as CreateCode does
// it.
func (d *MsSQLDatabase) CreateBrowserSession(tx *sql.Tx, browserSession *models.BrowserSession) error {

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
		For(sqlbuilder.SQLServer)

	insertBuilder := browserSessionStruct.WithoutTag("pk").InsertInto("browser_sessions", browserSession)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

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

func (d *MsSQLDatabase) GetBrowserSessionByOwnerAndSessionIdHash(tx *sql.Tx, owner, sessionIdHash string,
	now time.Time) (*models.BrowserSession, error) {
	return d.CommonDB.GetBrowserSessionByOwnerAndSessionIdHash(tx, owner, sessionIdHash, now)
}

func (d *MsSQLDatabase) UpdateBrowserSessionData(tx *sql.Tx, owner, sessionIdHash, data string,
	now, expiresAt time.Time) (bool, error) {
	return d.CommonDB.UpdateBrowserSessionData(tx, owner, sessionIdHash, data, now, expiresAt)
}

func (d *MsSQLDatabase) TouchBrowserSession(tx *sql.Tx, owner, sessionIdHash string,
	now, expiresAt time.Time) (bool, error) {
	return d.CommonDB.TouchBrowserSession(tx, owner, sessionIdHash, now, expiresAt)
}

func (d *MsSQLDatabase) DeleteBrowserSession(tx *sql.Tx, owner, sessionIdHash string) error {
	return d.CommonDB.DeleteBrowserSession(tx, owner, sessionIdHash)
}

func (d *MsSQLDatabase) DeleteExpiredBrowserSessions(tx *sql.Tx, now time.Time) error {
	return d.CommonDB.DeleteExpiredBrowserSessions(tx, now)
}
