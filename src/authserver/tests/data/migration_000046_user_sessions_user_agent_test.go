package datatests

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000046_UserSessionsUserAgent is #281's column, and it is the only tier that proves
// the four hand-written SQL files agree. It runs against an ISOLATED database of the configured
// dialect (see migration_testdb_helper.go), so it can look at the schema below 000046 as well as
// above it.
//
// What is asserted:
//
//   - The column is absent at 000045 and present NOT NULL with a default at 000046, declared as
//     this engine's file spells it. The default's recorded TEXT differs per engine, so what is
//     compared is that the default EXISTS and what it does: a row inserted without the column
//     reads back the empty string. That is decision 7's legacy row, and the sweep's rule that an
//     empty header matches an empty header rests on it.
//   - A 512-byte value round-trips byte for byte through CreateUserSession and
//     GetUserSessionBySessionIdentifier, which is the path StartNewUserSession writes through.
//     512 is the width useragent.Bound cuts to.
//   - A 512-byte value made of 128 four-byte runes round-trips too. That is the BYTE bound of
//     useragent.Bound proved on the engine that does not count bytes: SQL Server's NVARCHAR(512)
//     counts UTF-16 units and a 4-byte rune is two of them, so 128 runes is 256 units and fits,
//     where a 512-RUNE bound would have handed it 1024 units and been refused.
//   - Down then up again leaves the column present with its default. On SQL Server that only
//     works because the default constraint is named, which is what the down drops first.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000046_UserSessionsUserAgent
func TestMigration000046_UserSessionsUserAgent(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(45), "migrate to 000045")

	_, exists := columnNames000046(dumpTable(t, h, "user_sessions"))["user_agent"]
	require.False(t, exists, "user_sessions.user_agent must not exist at 000045 on any engine")

	require.NoError(t, h.Migrator.Migrate(46), "apply 000046")
	assertUserAgentColumn000046(t, h, "after apply")

	// Decision 7's legacy row, seeded exactly as a pre-upgrade row arrives: a session written by
	// a binary that did not know the column, which the migration defaults rather than backfills.
	userId := seedUser000046(t, h)
	legacy := seedSessionWithoutUserAgent000046(t, h, userId)

	read, err := h.DB.GetUserSessionBySessionIdentifier(nil, legacy)
	require.NoError(t, err, "read back the legacy session")
	require.NotNil(t, read, "the legacy session must be there")
	assert.Equal(t, "", read.UserAgent,
		"a row inserted without user_agent must read back empty: that is what leaves a legacy row sweepable only by another header-less client")

	assertUserAgentRoundTrip000046(t, h, userId, "512 ASCII bytes", strings.Repeat("a", 512))

	// 128 emoji, 4 bytes each. The rune count is asserted beside the byte length so a later edit
	// to the literal cannot quietly turn this into a second ASCII case.
	fourByteRunes := strings.Repeat("\U0001F600", 128)
	require.Len(t, fourByteRunes, 512, "the 4-byte-rune fixture must be exactly 512 bytes")
	require.Equal(t, 128, utf8.RuneCountInString(fourByteRunes), "512 bytes of 4-byte runes is 128 runes")
	assertUserAgentRoundTrip000046(t, h, userId, "512 bytes of 4-byte runes", fourByteRunes)

	require.NoError(t, h.Migrator.Migrate(45), "roll back 000046")
	_, exists = columnNames000046(dumpTable(t, h, "user_sessions"))["user_agent"]
	assert.False(t, exists, "user_sessions.user_agent must be gone after rolling back 000046")

	require.NoError(t, h.Migrator.Migrate(46), "re-apply 000046")
	assertUserAgentColumn000046(t, h, "after down/up round trip")

	// The default survives the round trip, which on SQL Server is the named constraint working: an
	// unnamed one would have blocked the down, and a down that dropped it without the up putting
	// it back would leave the column with no default at all.
	roundTripped := seedSessionWithoutUserAgent000046(t, h, seedUser000046(t, h))
	read, err = h.DB.GetUserSessionBySessionIdentifier(nil, roundTripped)
	require.NoError(t, err, "read back the session seeded after the round trip")
	require.NotNil(t, read)
	assert.Equal(t, "", read.UserAgent, "the default must still apply after down then up")
}

// assertUserAgentColumn000046 holds the declared shape: present, NOT NULL, defaulted, and the type
// this engine's migration file spells. The type is compared per dialect because the four files
// deliberately differ, and comparing them is the whole reason this test runs on four engines.
func assertUserAgentColumn000046(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	column := dumpTable(t, h, "user_sessions").column(t, "user_agent")

	assert.Falsef(t, column.Nullable, "[%s] user_sessions.user_agent must be NOT NULL on %s", phase, dbType())
	assert.Truef(t, column.HasDefault,
		"[%s] user_sessions.user_agent must carry a default on %s: a pre-upgrade row has nothing to be backfilled from",
		phase, dbType())
	assert.Equalf(t, userAgentType000046(), column.Type,
		"[%s] user_sessions.user_agent must be declared %s on %s", phase, userAgentType000046(), dbType())

	// codes.user_agent is the column this one mirrors, and 512 serving both is what lets one
	// useragent.Bound call cut for both writers. Widening one without the other breaks that, so
	// the two are compared rather than each asserted against a literal.
	assert.Equalf(t, dumpTable(t, h, "codes").column(t, "user_agent").Type, column.Type,
		"[%s] user_sessions.user_agent must be declared exactly as codes.user_agent is on %s", phase, dbType())
}

// assertUserAgentRoundTrip000046 writes a value through CreateUserSession and reads it back through
// GetUserSessionBySessionIdentifier, which is the path StartNewUserSession uses. Byte for byte: a
// value silently truncated or re-encoded by the driver would still be a string of the right shape,
// and the sweep compares these for equality.
func assertUserAgentRoundTrip000046(t *testing.T, h *isolatedDB, userId int64, name, userAgent string) {
	t.Helper()

	t.Run(name, func(t *testing.T) {
		identifier := fake.UUID()
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		session := &models.UserSession{
			SessionIdentifier: identifier,
			Started:           now,
			LastAccessed:      now,
			AuthMethods:       "pwd",
			AcrLevel:          "urn:goiabada:level1",
			AuthTime:          now,
			IpAddress:         "127.0.0.1",
			DeviceName:        "device",
			DeviceType:        "Desktop",
			DeviceOS:          "Linux",
			UserAgent:         userAgent,
			UserId:            userId,
		}
		require.NoErrorf(t, h.DB.CreateUserSession(nil, session), "create a session carrying %s", name)

		read, err := h.DB.GetUserSessionBySessionIdentifier(nil, identifier)
		require.NoErrorf(t, err, "read back the session carrying %s", name)
		require.NotNil(t, read)

		assert.Equalf(t, userAgent, read.UserAgent, "%s must round-trip byte for byte on %s", name, dbType())
		assert.Lenf(t, read.UserAgent, 512, "%s must read back at its full 512 bytes on %s", name, dbType())
	})
}

// userAgentType000046 is the type each engine's 000046 file declares, written out rather than
// derived so that editing one file and forgetting the others fails here.
func userAgentType000046() string {
	switch dbType() {
	case "mysql":
		return "varchar(512)"
	case "postgres":
		return "character varying(512)"
	case "mssql":
		return "nvarchar(512)"
	default:
		return "TEXT"
	}
}

func columnNames000046(shape tableShape) map[string]struct{} {
	names := make(map[string]struct{}, len(shape.Columns))
	for _, c := range shape.Columns {
		names[c.Name] = struct{}{}
	}
	return names
}

// seedUser000046 inserts a minimal users row with raw SQL, following seedPreMigration000031User:
// user_sessions.user_id is a foreign key, so the round trip needs an owner, and nothing about the
// owner is under test.
func seedUser000046(t *testing.T, h *isolatedDB) int64 {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()
	subject := fake.UUID()
	q := fmt.Sprintf(`INSERT INTO users
		(enabled, subject, username, email, email_verified, phone_number_verified,
		 password_hash, otp_enabled)
		VALUES (%s, '%s', '%s', '%s', %s, %s, 'x', %s)`,
		trueLit, subject, "mig45-"+subject[:8], "mig45-"+subject[:8]+"@test.local",
		falseLit, falseLit, falseLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed user")

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id),
		"read back seeded user id")
	return id
}

// seedSessionWithoutUserAgent000046 inserts a user_sessions row naming every NOT NULL column
// EXCEPT user_agent, with raw SQL rather than CreateUserSession: the Go model always names the
// column, so only a hand-written statement can stand in for a row a pre-upgrade binary wrote.
//
// The datetime literal is one string for all four engines, per seedPreMigration000031Session.
func seedSessionWithoutUserAgent000046(t *testing.T, h *isolatedDB, userId int64) string {
	t.Helper()

	const ts = "'2026-01-01 00:00:00'"
	identifier := fake.UUID()
	q := fmt.Sprintf(`INSERT INTO user_sessions
		(session_identifier, started, last_accessed, auth_methods, acr_level, auth_time,
		 ip_address, device_name, device_type, device_os, user_id)
		VALUES ('%s', %s, %s, 'pwd', 'urn:goiabada:level1', %s,
		 '127.0.0.1', 'device', 'Desktop', 'Linux', %d)`,
		identifier, ts, ts, ts, userId)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed a session with no user_agent, as a pre-upgrade binary wrote it")
	return identifier
}
