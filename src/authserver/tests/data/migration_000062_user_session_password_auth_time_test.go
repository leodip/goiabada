package datatests

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000062 sits between.
const (
	beforePasswordAuthTime000062 = 61
	passwordAuthTime000062       = 62
)

// TestMigration000062_UserSessionPasswordAuthTime exercises the migration that gives a session the
// time its password was entered, against a REAL engine of the configured dialect (#542 review). A
// stored session's password time can't be recovered, so the migration ends every session first.
//
// The properties:
//
//  1. Every session stored before it is gone, and the clients each one authorized with it.
//  2. user_sessions.password_auth_time exists, NOT NULL, and a session written at head round-trips it.
//  3. The down migration drops the column and keeps the sessions written since, and 000062 applies
//     again after it.
//  4. A session inserted as the previous release inserts one, naming no password_auth_time, is
//     refused once 000062 has run, rather than stored with a time nobody entered: during a rolling
//     upgrade that release goes on serving while this one migrates, and its sign-ins fail until it
//     stops. The migration itself never fails on a row that release wrote, which is why the server
//     engines add the column with a default they drop at once and delete the sessions last.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000062_UserSessionPasswordAuthTime
func TestMigration000062_UserSessionPasswordAuthTime(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the ORM at head, then carried down to 000061: the ORM writes every column the
	// record carries, so it can only write at head.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}
	user := &record.User{Subject: fake.UUID(), Email: fake.Email(), Enabled: true}
	require.NoError(t, h.DB.CreateUser(ctx, nil, user))
	client := &record.Client{ClientIdentifier: "m62_" + fake.LetterN(6), Description: "Migration 000062 test client"}
	require.NoError(t, h.DB.CreateClient(ctx, nil, client))

	seedSession := func() *record.UserSession {
		now := time.Now().UTC().Truncate(time.Microsecond)
		session := &record.UserSession{
			SessionIdentifier: fake.UUID(), Started: now, LastAccessed: now, AuthTime: now, PasswordAuthTime: now.Add(-time.Minute),
			AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory, IpAddress: "192.0.2.1", UserId: user.Id,
		}
		require.NoError(t, h.DB.CreateUserSession(ctx, nil, session))
		require.NoError(t, h.DB.CreateUserSessionClient(ctx, nil, &record.UserSessionClient{
			UserSessionId: session.Id, ClientId: client.Id, Started: now, LastAccessed: now,
		}))
		return session
	}
	seedSession()
	seedSession()

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforePasswordAuthTime000062), "roll back to 000061 on %s", dbType())
	_, exists := columnNames000046(dumpTable(t, h, "user_sessions"))["password_auth_time"]
	require.Falsef(t, exists, "user_sessions.password_auth_time must not exist at 000061 on %s", dbType())
	assert.Equalf(t, 2, count000062(t, h, "user_sessions"), "3. the down keeps the sessions on %s", dbType())

	// 1.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, passwordAuthTime000062), "apply 000062 on %s", dbType())
	assert.Zerof(t, count000062(t, h, "user_sessions"), "1. every stored session is ended on %s", dbType())
	assert.Zerof(t, count000062(t, h, "user_session_clients"), "1. and the clients each one authorized on %s", dbType())

	// 2.
	column := dumpTable(t, h, "user_sessions").column(t, "password_auth_time")
	assert.Falsef(t, column.Nullable, "user_sessions.password_auth_time must be NOT NULL on %s", dbType())
	// 4.
	const ts = "'2026-01-01 00:00:00'"
	_, err := h.SQL.Exec(fmt.Sprintf(`INSERT INTO user_sessions
		(session_identifier, started, last_accessed, auth_methods, acr_level, auth_time,
		 ip_address, device_name, device_type, device_os, user_agent, user_id)
		VALUES ('%s', %s, %s, 'pwd', 'urn:goiabada:level1', %s, '127.0.0.1', 'device', 'Desktop', 'Linux', '', %d)`,
		fake.UUID(), ts, ts, ts, user.Id))
	assert.Errorf(t, err, "4. a session naming no password_auth_time is refused on %s", dbType())
	assert.Zerof(t, count000062(t, h, "user_sessions"), "4. and nothing is stored on %s", dbType())

	written := seedSession()
	read, err := h.DB.GetUserSessionById(ctx, nil, written.Id)
	require.NoError(t, err)
	assert.Truef(t, read.PasswordAuthTime.Equal(written.PasswordAuthTime), "2. the password's instant round-trips on %s", dbType())

	// 3.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforePasswordAuthTime000062), "roll back 000062 on %s", dbType())
	assert.Equalf(t, 1, count000062(t, h, "user_sessions"), "3. the down keeps the session written since on %s", dbType())
	require.NoErrorf(t, h.Migrator.Migrate(ctx, passwordAuthTime000062), "re-apply 000062 on %s", dbType())
	assert.Zerof(t, count000062(t, h, "user_sessions"), "the re-applied up ends it as well on %s", dbType())
}

func count000062(t *testing.T, h *isolatedDB, table string) int {
	t.Helper()
	var n int
	require.NoErrorf(t, h.SQL.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&n), "count %s on %s", table, dbType())
	return n
}
