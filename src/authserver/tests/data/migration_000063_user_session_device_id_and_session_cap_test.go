package datatests

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000063 sits between.
const (
	beforeDeviceIdAndSessionCap000063 = 62
	deviceIdAndSessionCap000063       = 63
)

// deviceId000063 is a device identifier as it is stored: the SHA-256 of a cookie value, in hex. This
// one is the digest of the empty string, written out so the fixture is 64 characters by
// construction rather than by a call this test shares with the code.
const deviceId000063 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// TestMigration000063_UserSessionDeviceIdAndSessionCap exercises the migration that stores a
// session's device identifier and the per-user session cap (#564 decision 11), against a REAL engine
// of the configured dialect.
//
// The properties:
//
//  1. Neither column exists at 000062; at 000063 both are NOT NULL with a default, declared as this
//     engine's file spells them.
//  2. Existing rows take the defaults: a session stored before the upgrade has an empty device
//     identifier, which matches nothing, and an existing settings row has a cap of 20, the same as a
//     new installation (decision 5).
//  3. A session inserted as the previous release inserts one during a rolling upgrade, naming no
//     device_id, is stored with an empty identifier rather than refused.
//  4. At head both round-trip: a 64-character identifier, and caps of 0 (no limit) and 1000 (the
//     bound), each stored as written rather than replaced by the default.
//  5. The down migration drops both columns and keeps the rows, and 000063 applies again after it
//     with its defaults. On SQL Server that is the named default constraints working.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000063_UserSessionDeviceIdAndSessionCap
func TestMigration000063_UserSessionDeviceIdAndSessionCap(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the ORM at head, then carried down to 000062: the ORM writes every column the
	// record carries, so it can only write at head. The values written here are not the defaults, so
	// reading the defaults back after the re-apply shows the migration put them there.
	migrateToHead000063(t, h)
	user := &record.User{Subject: fake.UUID(), Email: fake.Email(), Enabled: true}
	require.NoError(t, h.DB.CreateUser(ctx, nil, user))
	settings := settings000063(7)
	require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))
	stored := session000063(user.Id, deviceId000063)
	require.NoError(t, h.DB.CreateUserSession(ctx, nil, stored))

	// 1.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDeviceIdAndSessionCap000063), "roll back to 000062 on %s", dbType())
	assertColumnsAbsent000063(t, h, "at 000062")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, deviceIdAndSessionCap000063), "apply 000063 on %s", dbType())
	assertColumns000063(t, h, "after apply")

	// 2.
	assert.Emptyf(t, deviceIdOf000063(t, h, stored.SessionIdentifier),
		"2. a session stored before the upgrade has an empty device identifier on %s", dbType())
	assert.Equalf(t, 20, sessionCapOf000063(t, h, settings.Id),
		"2. an existing installation's cap is 20, as a new one's is, on %s", dbType())

	// 3.
	previousRelease := insertSessionWithoutDeviceId000063(t, h, user.Id)
	assert.Emptyf(t, deviceIdOf000063(t, h, previousRelease),
		"3. a session the previous release inserts is stored with an empty device identifier on %s", dbType())

	// 4.
	migrateToHead000063(t, h)
	written := session000063(user.Id, deviceId000063)
	require.NoError(t, h.DB.CreateUserSession(ctx, nil, written))
	read, err := h.DB.GetUserSessionById(ctx, nil, written.Id)
	require.NoError(t, err)
	require.NotNil(t, read)
	assert.Equalf(t, deviceId000063, read.DeviceId, "4. the device identifier round-trips on %s", dbType())

	for _, sessionCap := range []int{0, 1000} {
		settings.MaxUserSessionsPerUser = sessionCap
		require.NoError(t, h.DB.UpdateSettings(ctx, nil, settings))
		readSettings, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
		require.NoError(t, err)
		require.NotNil(t, readSettings)
		assert.Equalf(t, sessionCap, readSettings.MaxUserSessionsPerUser, "4. a cap of %d round-trips on %s", sessionCap, dbType())
	}

	// 5.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDeviceIdAndSessionCap000063), "roll back 000063 on %s", dbType())
	assertColumnsAbsent000063(t, h, "after rolling back")
	assert.Equalf(t, 3, count000062(t, h, "user_sessions"), "5. the down keeps the sessions on %s", dbType())
	assert.Equalf(t, 1, count000062(t, h, "settings"), "5. and the settings row on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, deviceIdAndSessionCap000063), "re-apply 000063 on %s", dbType())
	assertColumns000063(t, h, "after down/up round trip")
	assert.Emptyf(t, deviceIdOf000063(t, h, written.SessionIdentifier),
		"5. the identifier dropped with the column reads empty once it is back on %s", dbType())
	assert.Equalf(t, 20, sessionCapOf000063(t, h, settings.Id),
		"5. the cap dropped with the column reads 20 once it is back on %s", dbType())
	roundTripped := insertSessionWithoutDeviceId000063(t, h, user.Id)
	assert.Emptyf(t, deviceIdOf000063(t, h, roundTripped), "5. the default still applies after down then up on %s", dbType())
}

func migrateToHead000063(t *testing.T, h *isolatedDB) {
	t.Helper()
	if err := h.Migrator.Up(context.Background()); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoErrorf(t, err, "migrate to head on %s", dbType())
	}
}

func settings000063(sessionCap int) *record.Settings {
	return &record.Settings{
		AppName:                         "Migration 000063",
		Issuer:                          "https://m63.test",
		PasswordPolicy:                  record.PasswordPolicyLow,
		TokenExpirationInSeconds:        300,
		UserSessionIdleTimeoutInSeconds: 7200,
		UserSessionMaxLifetimeInSeconds: 86400,
		MaxUserSessionsPerUser:          sessionCap,
		AESEncryptionKeyLegacy:          []byte{},
		SMTPPasswordEncrypted:           []byte{},
	}
}

func session000063(userId int64, deviceId string) *record.UserSession {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &record.UserSession{
		SessionIdentifier: fake.UUID(), Started: now, LastAccessed: now, AuthTime: now, PasswordAuthTime: now,
		AuthMethods: "pwd", AcrLevel: record.AcrLevel1, IpAddress: "192.0.2.1", DeviceId: deviceId, UserId: userId,
	}
}

// assertColumns000063 holds the declared shape of both columns: present, NOT NULL, defaulted, and the
// type this engine's migration file spells. The type is compared per dialect because the four files
// deliberately differ.
func assertColumns000063(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	deviceId := dumpTable(t, h, "user_sessions").column(t, "device_id")
	assert.Falsef(t, deviceId.Nullable, "[%s] user_sessions.device_id must be NOT NULL on %s", phase, dbType())
	assert.Truef(t, deviceId.HasDefault, "[%s] user_sessions.device_id must carry a default on %s", phase, dbType())
	assert.Equalf(t, deviceIdType000063(), deviceId.Type, "[%s] user_sessions.device_id's type on %s", phase, dbType())

	sessionCap := dumpTable(t, h, "settings").column(t, "max_user_sessions_per_user")
	assert.Falsef(t, sessionCap.Nullable, "[%s] settings.max_user_sessions_per_user must be NOT NULL on %s", phase, dbType())
	assert.Truef(t, sessionCap.HasDefault, "[%s] settings.max_user_sessions_per_user must carry a default on %s", phase, dbType())
	assert.Equalf(t, sessionCapType000063(), sessionCap.Type, "[%s] settings.max_user_sessions_per_user's type on %s", phase, dbType())
}

func assertColumnsAbsent000063(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	_, exists := columnNames000046(dumpTable(t, h, "user_sessions"))["device_id"]
	assert.Falsef(t, exists, "[%s] user_sessions.device_id must not exist on %s", phase, dbType())
	_, exists = columnNames000046(dumpTable(t, h, "settings"))["max_user_sessions_per_user"]
	assert.Falsef(t, exists, "[%s] settings.max_user_sessions_per_user must not exist on %s", phase, dbType())
}

// deviceIdType000063 and sessionCapType000063 are the types each engine's 000063 file declares,
// written out rather than derived so that editing one file and forgetting the others fails here.
// 64 characters is a SHA-256 in hex.
func deviceIdType000063() string {
	switch dbType() {
	case data.MySQL:
		return "varchar(64)"
	case data.Postgres:
		return "character varying(64)"
	case data.MSSQL:
		return "nvarchar(64)"
	default:
		return "TEXT"
	}
}

func sessionCapType000063() string {
	switch dbType() {
	case data.MySQL, data.MSSQL:
		return "int"
	case data.Postgres:
		return "integer"
	default:
		return "INTEGER"
	}
}

// insertSessionWithoutDeviceId000063 inserts a session naming every column the previous release
// writes and not device_id, with raw SQL: the Go model always names the column, so only a
// hand-written statement can stand in for that release's insert.
func insertSessionWithoutDeviceId000063(t *testing.T, h *isolatedDB, userId int64) string {
	t.Helper()
	const ts = "'2026-01-01 00:00:00'"
	identifier := fake.UUID()
	_, err := h.SQL.Exec(fmt.Sprintf(`INSERT INTO user_sessions
		(session_identifier, started, last_accessed, auth_methods, acr_level, auth_time, password_auth_time,
		 ip_address, device_name, device_type, device_os, user_agent, user_id)
		VALUES ('%s', %s, %s, 'pwd', 'urn:goiabada:level1', %s, %s, '127.0.0.1', 'device', 'Desktop', 'Linux', '', %d)`,
		identifier, ts, ts, ts, ts, userId))
	require.NoErrorf(t, err, "insert a session naming no device_id on %s", dbType())
	return identifier
}

func deviceIdOf000063(t *testing.T, h *isolatedDB, identifier string) string {
	t.Helper()
	var deviceId string
	q := fmt.Sprintf("SELECT device_id FROM user_sessions WHERE session_identifier = '%s'", identifier)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&deviceId), "read the device_id of session %s on %s", identifier, dbType())
	return deviceId
}

func sessionCapOf000063(t *testing.T, h *isolatedDB, settingsId int64) int {
	t.Helper()
	var sessionCap int
	q := fmt.Sprintf("SELECT max_user_sessions_per_user FROM settings WHERE id = %d", settingsId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&sessionCap), "read the session cap on %s", dbType())
	return sessionCap
}
