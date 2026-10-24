package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The statements of a session's records, held on all four engines to what each asks of the
// engine: user sessions, the clients a session has signed in to, browser sessions and consents
// (#644).
//
// Most of these exist for their condition or for what they leave alone. A promotion writes its one
// generation and no other column; the lowering at an authenticator's removal reaches only the
// user's sessions that claim more than a password, in one statement; a browser session is read,
// written and touched only while it is live, and the conditional writes only while it still holds
// what the store read. Both are in the statement's text and nowhere else, so this reads the text
// with each placeholder rendered as the value it binds, one expected statement for all four
// engines, as the users' narrow writes are read. The columns of a read of whole records are left
// to the record mapping test.

const (
	sessionUserId       = 7
	sessionId           = 9
	sessionClientId     = 3
	sessionIdentifier   = "sid-1"
	sessionOwner        = "authserver"
	sessionIdHash       = "hash-1"
	sessionData         = "sealed-new"
	sessionExpectedData = "sealed-old"
)

var sessionExpiresAt = time.Date(2004, 4, 4, 0, 0, 0, 0, time.UTC)

// browserSessionRow is one live browser session as the engine answers a read of whole records.
func browserSessionRow() *scriptedRows {
	return &scriptedRows{
		cols: []string{"id", "created_at", "updated_at", "owner", "session_id_hash", "data", "last_accessed", "expires_at"},
		values: [][]driver.Value{{int64(1), issuedAt, issuedAt, sessionOwner, sessionIdHash, sessionData,
			issuedAt, sessionExpiresAt}},
	}
}

func sessionStatements() []narrowWrite {
	return []narrowWrite{
		// User sessions.
		{
			name: "GetUserSessionById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionById(ctx, nil, sessionId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_sessions WHERE id = 9"},
		},
		{
			name: "GetUserSessionBySessionIdentifier",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionBySessionIdentifier(ctx, nil, sessionIdentifier)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_sessions WHERE session_identifier = 'sid-1'"},
		},
		{
			name: "GetUserSessionBySessionIdentifier with an empty identifier",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionBySessionIdentifier(ctx, nil, "")
				return nil, err
			},
		},
		{
			name: "GetUserSessionsByUserId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionsByUserId(ctx, nil, sessionUserId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_sessions WHERE user_id = 7"},
		},
		{
			name: "DeleteUserSession",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteUserSession(ctx, nil, sessionId)
			},
			statements: []string{"DELETE FROM user_sessions WHERE id = 9"},
		},
		{
			name: "AcquireUserSessionRow",
			run: func(ctx context.Context, d *Database) (any, error) {
				return inTxBool(ctx, d, func(ctx context.Context, d *Database, tx *sql.Tx) (bool, error) {
					return d.AcquireUserSessionRow(ctx, tx, sessionIdentifier)
				})
			},
			answer:     true,
			statements: []string{"UPDATE user_sessions SET updated_at = <now> WHERE session_identifier = 'sid-1'"},
		},
		{
			name:  "AcquireUserSessionRow when the session is gone",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return inTxBool(ctx, d, func(ctx context.Context, d *Database, tx *sql.Tx) (bool, error) {
					return d.AcquireUserSessionRow(ctx, tx, sessionIdentifier)
				})
			},
			answer:     false,
			statements: []string{"UPDATE user_sessions SET updated_at = <now> WHERE session_identifier = 'sid-1'"},
		},
		{
			name: "PromoteUserSessionGeneration",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.PromoteUserSessionGeneration(ctx, nil, sessionId, 4)
			},
			statements: []string{"UPDATE user_sessions SET auth_state_generation = 4, updated_at = <now> WHERE id = 9"},
		},
		{
			name: "PromoteUserSessionOtpConfigGeneration",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.PromoteUserSessionOtpConfigGeneration(ctx, nil, sessionId, 4)
			},
			statements: []string{"UPDATE user_sessions SET otp_config_generation = 4, updated_at = <now> WHERE id = 9"},
		},
		{
			name: "LowerUserSessionsToPassword",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.LowerUserSessionsToPassword(ctx, nil, sessionUserId, "pwd")
			},
			statements: []string{
				"UPDATE user_sessions SET auth_methods = 'pwd', " +
					"acr_level = CASE WHEN acr_level = 'urn:goiabada:level2_mandatory' THEN 'urn:goiabada:level2_optional' ELSE acr_level END, " +
					"auth_time = password_auth_time, updated_at = <now> " +
					"WHERE user_id = 7 AND (auth_methods <> 'pwd' OR acr_level = 'urn:goiabada:level2_mandatory')",
			},
		},

		// The clients a session has signed in to.
		{
			name: "GetUserSessionClientById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionClientById(ctx, nil, sessionId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_session_clients WHERE id = 9"},
		},
		{
			name: "GetUserSessionClientsByUserSessionId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionClientsByUserSessionId(ctx, nil, sessionId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_session_clients WHERE user_session_id = 9"},
		},
		{
			name: "GetUserSessionClientsByUserSessionIds",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionClientsByUserSessionIds(ctx, nil, []int64{4, 5})
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_session_clients WHERE user_session_id IN (4, 5)"},
		},
		{
			name: "GetUserSessionsClientByIds",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserSessionsClientByIds(ctx, nil, []int64{4, 5})
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_session_clients WHERE id IN (4, 5)"},
		},
		{
			name: "DeleteUserSessionClient",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteUserSessionClient(ctx, nil, sessionId)
			},
			statements: []string{"DELETE FROM user_session_clients WHERE id = 9"},
		},

		// Browser sessions.
		{
			name: "GetBrowserSessionByOwnerAndSessionIdHash",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetBrowserSessionByOwnerAndSessionIdHash(ctx, nil, sessionOwner, sessionIdHash, issuedAt)
				return nil, err
			},
			statements: []string{
				"SELECT <columns> FROM browser_sessions " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name: "UpdateBrowserSessionData",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.UpdateBrowserSessionData(ctx, nil, sessionOwner, sessionIdHash, sessionData, issuedAt, sessionExpiresAt)
			},
			answer: true,
			statements: []string{
				"UPDATE browser_sessions SET data = 'sealed-new', last_accessed = 2001-01-01T00:00:00Z, " +
					"expires_at = 2004-04-04T00:00:00Z, updated_at = 2001-01-01T00:00:00Z " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name:  "UpdateBrowserSessionData when the session is gone",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.UpdateBrowserSessionData(ctx, nil, sessionOwner, sessionIdHash, sessionData, issuedAt, sessionExpiresAt)
			},
			answer: false,
			statements: []string{
				"UPDATE browser_sessions SET data = 'sealed-new', last_accessed = 2001-01-01T00:00:00Z, " +
					"expires_at = 2004-04-04T00:00:00Z, updated_at = 2001-01-01T00:00:00Z " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name: "TouchBrowserSession",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TouchBrowserSession(ctx, nil, sessionOwner, sessionIdHash, issuedAt, sessionExpiresAt)
			},
			answer: true,
			statements: []string{
				"UPDATE browser_sessions SET last_accessed = 2001-01-01T00:00:00Z, expires_at = 2004-04-04T00:00:00Z, " +
					"updated_at = 2001-01-01T00:00:00Z " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			// MySQL counts rows changed, so a touch writing what the row already holds reports none,
			// and the session is confirmed by a read under the same predicate.
			name:  "TouchBrowserSession when no row changed and the session is live",
			execs: []*scriptedExec{{rowsAffected: 0}},
			rows:  []*scriptedRows{browserSessionRow()},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TouchBrowserSession(ctx, nil, sessionOwner, sessionIdHash, issuedAt, sessionExpiresAt)
			},
			answer: true,
			statements: []string{
				"UPDATE browser_sessions SET last_accessed = 2001-01-01T00:00:00Z, expires_at = 2004-04-04T00:00:00Z, " +
					"updated_at = 2001-01-01T00:00:00Z " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
				"SELECT <columns> FROM browser_sessions " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name:  "TouchBrowserSession when the session is gone",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TouchBrowserSession(ctx, nil, sessionOwner, sessionIdHash, issuedAt, sessionExpiresAt)
			},
			answer: false,
			statements: []string{
				"UPDATE browser_sessions SET last_accessed = 2001-01-01T00:00:00Z, expires_at = 2004-04-04T00:00:00Z, " +
					"updated_at = 2001-01-01T00:00:00Z " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
				"SELECT <columns> FROM browser_sessions " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name: "DeleteBrowserSession",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteBrowserSession(ctx, nil, sessionOwner, sessionIdHash)
			},
			statements: []string{"DELETE FROM browser_sessions WHERE owner = 'authserver' AND session_id_hash = 'hash-1'"},
		},
		{
			name: "UpdateBrowserSessionDataIfUnchanged",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.UpdateBrowserSessionDataIfUnchanged(ctx, nil, sessionOwner, sessionIdHash,
					sessionExpectedData, sessionData, issuedAt, sessionExpiresAt)
			},
			answer: true,
			statements: []string{
				"UPDATE browser_sessions SET data = 'sealed-new', last_accessed = 2001-01-01T00:00:00Z, " +
					"expires_at = 2004-04-04T00:00:00Z, updated_at = 2001-01-01T00:00:00Z " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND data = 'sealed-old' " +
					"AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name:  "UpdateBrowserSessionDataIfUnchanged when another write landed",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.UpdateBrowserSessionDataIfUnchanged(ctx, nil, sessionOwner, sessionIdHash,
					sessionExpectedData, sessionData, issuedAt, sessionExpiresAt)
			},
			answer: false,
			statements: []string{
				"UPDATE browser_sessions SET data = 'sealed-new', last_accessed = 2001-01-01T00:00:00Z, " +
					"expires_at = 2004-04-04T00:00:00Z, updated_at = 2001-01-01T00:00:00Z " +
					"WHERE owner = 'authserver' AND session_id_hash = 'hash-1' AND data = 'sealed-old' " +
					"AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name: "DeleteBrowserSessionIfUnchanged",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.DeleteBrowserSessionIfUnchanged(ctx, nil, sessionOwner, sessionIdHash, sessionExpectedData, issuedAt)
			},
			answer: true,
			statements: []string{
				"DELETE FROM browser_sessions WHERE owner = 'authserver' AND session_id_hash = 'hash-1' " +
					"AND data = 'sealed-old' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name:  "DeleteBrowserSessionIfUnchanged when another write landed",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.DeleteBrowserSessionIfUnchanged(ctx, nil, sessionOwner, sessionIdHash, sessionExpectedData, issuedAt)
			},
			answer: false,
			statements: []string{
				"DELETE FROM browser_sessions WHERE owner = 'authserver' AND session_id_hash = 'hash-1' " +
					"AND data = 'sealed-old' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name: "DeleteExpiredBrowserSessions",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteExpiredBrowserSessions(ctx, nil, staleBefore)
			},
			statements: []string{"DELETE FROM browser_sessions WHERE expires_at < 2003-03-03T00:00:00Z"},
		},

		// Consents.
		{
			name: "GetUserConsentById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetUserConsentById(ctx, nil, sessionId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_consents WHERE id = 9"},
		},
		{
			name: "GetConsentByUserIdAndClientId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetConsentByUserIdAndClientId(ctx, nil, sessionUserId, sessionClientId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_consents WHERE user_id = 7 AND client_id = 3"},
		},
		{
			name: "GetConsentsByUserId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetConsentsByUserId(ctx, nil, sessionUserId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM user_consents WHERE user_id = 7"},
		},
		{
			name: "DeleteUserConsent",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteUserConsent(ctx, nil, sessionId)
			},
			statements: []string{"DELETE FROM user_consents WHERE id = 9"},
		},
		{
			name: "DeleteAllUserConsent",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteAllUserConsent(ctx, nil)
			},
			statements: []string{"DELETE FROM user_consents"},
		},
	}
}

// inTxBool runs a write answering a bool inside a transaction, for the writes that refuse to run
// outside one.
func inTxBool(ctx context.Context, d *Database, write func(ctx context.Context, d *Database, tx *sql.Tx) (bool, error)) (any, error) {
	return inTx(ctx, d, func(tx *sql.Tx) (any, error) {
		return write(ctx, d, tx)
	})
}

func TestSessionStatements_SendTheirStatementOnEveryEngine(t *testing.T) {
	assertNarrowWritesOnEveryEngine(t, sessionStatements(), true)
}

// TestSessionStatements_TheEnginesPageAClientsSessions holds the page of a client's sessions to its
// join, its total order and each engine's paging, with the page size and the offset each bound to
// the clause that reads it, and the count beside it to the same join and condition.
func TestSessionStatements_TheEnginesPageAClientsSessions(t *testing.T) {
	const page = "SELECT <columns> FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = 3 ORDER BY user_sessions.last_accessed DESC, user_sessions.id DESC "
	const count = "SELECT count(*) FROM user_sessions " +
		"INNER JOIN user_session_clients ON user_sessions.id = user_session_clients.user_session_id " +
		"WHERE user_session_clients.client_id = 3"
	run := func(ctx context.Context, d *Database) (any, error) {
		_, _, err := d.GetUserSessionsByClientIdPaginated(ctx, nil, sessionClientId, 3, 10)
		return nil, err
	}

	for _, dialect := range allDialects {
		paging := "LIMIT 10 OFFSET 20"
		if dialect == data.MSSQL {
			paging = "OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY"
		}
		t.Run(string(dialect), func(t *testing.T) {
			assertNarrowWriteOn(t, narrowWrite{run: run, statements: []string{page + paging, count}}, dialect, true)
		})
	}
}

// cutoff is a cleanup's cutoff as the expected statements spell it: the clock less the duration,
// which a rendering of its own value cannot pin, since the clock moves.
var cutoff = regexp.MustCompile(`< [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z`)

// TestSessionStatements_TheCleanupsCutOffAtTheClockLessTheDuration holds the two session reapers to
// their columns and to a cutoff in the past: a session idle past its timeout, or older than its
// lifetime, and no other.
func TestSessionStatements_TheCleanupsCutOffAtTheClockLessTheDuration(t *testing.T) {
	for _, c := range []struct {
		name string
		run  func(ctx context.Context, d *Database) error
		want string
	}{
		{"DeleteIdleSessions", func(ctx context.Context, d *Database) error {
			return d.DeleteIdleSessions(ctx, nil, time.Hour)
		}, "DELETE FROM user_sessions WHERE last_accessed <cutoff>"},
		{"DeleteExpiredSessions", func(ctx context.Context, d *Database) error {
			return d.DeleteExpiredSessions(ctx, nil, time.Hour)
		}, "DELETE FROM user_sessions WHERE started <cutoff>"},
	} {
		for _, dialect := range allDialects {
			t.Run(c.name+"/"+string(dialect), func(t *testing.T) {
				script := &scriptedDriver{}
				started := time.Now().UTC()
				require.NoError(t, c.run(context.Background(), scriptedDBFor(t, script, dialect)))
				finished := time.Now().UTC()

				require.Len(t, script.statements, 1)
				require.Len(t, script.execArgs, 1)
				rendered, problems := renderStatement(dialect, script.statements[0], script.execArgs[0], started)
				assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
				assert.Equal(t, c.want, cutoff.ReplaceAllString(rendered, "<cutoff>"))

				require.Len(t, script.execArgs[0], 1)
				at, ok := script.execArgs[0][0].(time.Time)
				require.True(t, ok, "the cutoff is bound as a time")
				assert.False(t, at.Before(started.Add(-time.Hour)), "the cutoff is the clock less the duration")
				assert.False(t, at.After(finished.Add(-time.Hour)), "the cutoff is the clock less the duration")
			})
		}
	}
}
