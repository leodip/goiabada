package datatests

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000097 sits between. Literals: nothing in production code names this
// number.
const (
	beforeLowerUnearnedLevel000097 = 96
	lowerUnearnedLevel000097       = 97
)

// releaseNoteQuery000097 is the query the release notes give an operator, verbatim (#199
// decision 4), to list before upgrading the stored sign-ins the migration will lower.
const releaseNoteQuery000097 = `SELECT codes.id, users.email, clients.client_identifier, codes.created_at
FROM codes
JOIN users ON users.id = codes.user_id
JOIN clients ON clients.id = codes.client_id
WHERE codes.acr_level = 'urn:goiabada:level2_mandatory'
  AND codes.auth_methods NOT LIKE '%otp%'
  AND codes.auth_methods NOT LIKE '%recovery_code%';`

// signInShape000097 is one stored sign-in: the level and methods it is stored with, and the level
// it must hold once 000097 has run, written out rather than derived.
type signInShape000097 struct {
	level, methods string
	want           string
	// realNames is true when every method the row names is one some release has written: pwd, otp
	// or recovery_code. The release-note query tests for substrings, so it lists exactly the rows
	// the migration lowers only over those (#199 decision 4).
	realNames bool
	why       string
}

func signInShapes000097() []signInShape000097 {
	const (
		level1    = "urn:goiabada:level1"
		optional  = "urn:goiabada:level2_optional"
		mandatory = "urn:goiabada:level2_mandatory"
	)
	return []signInShape000097{
		{mandatory, "pwd", level1, true,
			"the highest level with a password alone: the unearned level this migration exists for"},
		{mandatory, "", level1, true,
			"the highest level with no methods recorded, which claims the most with the least behind it"},
		{mandatory, "pwd otp", mandatory, true, "a one-time code was entered"},
		{mandatory, "pwd recovery_code", mandatory, true, "a recovery code was entered"},
		{mandatory, "otp pwd", mandatory, true, "the methods in another order still name a one-time code"},
		{mandatory, "recovery_code pwd", mandatory, true, "the methods in another order still name a recovery code"},
		{mandatory, "otp", mandatory, true, "a one-time code as the only method still names a second factor"},
		{mandatory, "pwd xotp", level1, false, "xotp is a lookalike that contains otp but is not the name"},
		{mandatory, "pwd otpx", level1, false, "otpx starts with otp but is not the name"},
		{mandatory, "pwd recoveryXcode", level1, false,
			"recoveryXcode matches recovery_code only where _ is read as a wildcard"},
		{mandatory, "pwd recovery_codes", level1, false, "recovery_codes starts with recovery_code but is not the name"},
		{mandatory, "pwd OTP", level1, false, "the name is case-exact, so OTP names no second factor"},
		{mandatory, "pwd Recovery_Code", level1, false, "the name is case-exact, so Recovery_Code names no second factor"},
		{mandatory, "pwd\totp", level1, false,
			"a tab is not the list's separator, so pwd<tab>otp is one name, neither otp nor recovery_code; issuance reads it so too"},
		{mandatory, "pwd\trecovery_code", level1, false,
			"a tab is not the list's separator, so pwd<tab>recovery_code names no second factor"},
		{mandatory, "pwd  otp", mandatory, true,
			"two spaces leave an empty name between them, and otp is still named whole; issuance reads it so too"},
		{mandatory, "pwd o\u00adtp", level1, false,
			"a soft hyphen inside otp, which a linguistic collation ignores: the name is matched character for character"},
		{mandatory, "pwd recovery\u00ad_code", level1, false,
			"a soft hyphen inside recovery_code, which a linguistic collation ignores"},
		{level1, "pwd", level1, true, "the lowest level is never touched"},
		{optional, "pwd", optional, true, "level2_optional is never touched"},
		{optional, "pwd xotp", optional, false, "level2_optional is never touched, whatever its methods"},
	}
}

// TestMigration000097_LowerUnearnedACRLevel exercises the migration that lowers to level1 every
// stored sign-in at level2_mandatory whose methods name neither otp nor recovery_code (#199
// decisions 2 and 3), against a REAL engine of the configured dialect: the methods are matched as
// whole, case-exact names, which each engine is asked to do in its own SQL.
//
// The properties:
//
//  1. Each shape holds the level its table entry gives, once 000097 has run, and every other
//     column of every row is as it was.
//  2. The release-note query, run before migrating, lists exactly the rows the migration then
//     lowers among those naming only methods some release has written.
//  3. The down migration leaves every row as the up left it, and 000097 applies again after it,
//     changing nothing more.
//  4. The grant lives on and nobody is signed out (#199 decision 1): a live offline refresh token
//     of a lowered sign-in, and a live browser session stored at the level the migration lowers in
//     codes, are byte for byte as they were across the up, the down and the re-applied up.
//
// Every baseline is read at 000096, straight after seeding, so nothing a migration writes, the
// down's included, is part of what the rows are compared against.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000097_LowerUnearnedACRLevel
func TestMigration000097_LowerUnearnedACRLevel(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded at 000096 itself, so no down migration runs before the baselines are read, and in SQL
	// naming the columns 000096 carries, so a column a later migration adds to one of these tables
	// cannot break the seed (migration_seed_sql_test.go).
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeLowerUnearnedLevel000097), "migrate to 000096 on %s", dbType())
	userID := seedUser(t, h, userSeed{Enabled: true})
	// Enabled, as seedClient leaves it, so the grant below is one its client can still refresh.
	clientID := seedClient(t, h, "m97_"+fake.LetterN(6))

	shapes := signInShapes000097()
	ids := make([]int64, len(shapes))
	for i, s := range shapes {
		ids[i] = createSignIn000097(t, h, clientID, userID, s.level, s.methods)
	}
	// 4. The first shape is the one the migration exists for: a password alone at the highest
	// level. Its grant's live offline refresh token, and a live browser session of the user stored
	// at that same unearned pair.
	require.Equal(t, "pwd", shapes[0].methods, "the first shape is the password-only sign-in at the highest level")
	refreshTokenID := createOfflineRefreshToken000097(t, h, ids[0])
	sessionID := createBrowserSession000097(t, h, userID)

	before := make([]map[string]string, len(shapes))
	for i := range shapes {
		before[i] = codeRow000097(t, h, ids[i])
		require.Equalf(t, shapes[i].level, before[i]["acr_level"], "seeded level of %q", shapes[i].methods)
		require.Equalf(t, shapes[i].methods, before[i]["auth_methods"], "seeded methods of %q", shapes[i].methods)
	}
	refreshTokenBefore := row000097(t, h, "refresh_tokens", refreshTokenID)
	require.Equalf(t, ids[0], mustInt000097(t, refreshTokenBefore["code_id"]), "the refresh token belongs to the lowered sign-in")
	// The stored shape of an offline grant, as the issuer writes it: no session identifier, which
	// stays on the sign-in, and a maximum lifetime instead.
	require.Empty(t, refreshTokenBefore["session_identifier"], "an offline refresh token stores no session identifier")
	require.NotEqual(t, "<NULL>", refreshTokenBefore["max_lifetime"], "an offline refresh token stores its maximum lifetime")
	require.NotEmpty(t, before[0]["session_identifier"], "the lowered sign-in keeps its session identifier")
	sessionBefore := row000097(t, h, "user_sessions", sessionID)

	// 2, first half: what the release-note query lists before the upgrade.
	listed := releaseNoteQueryIDs000097(t, h)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, lowerUnearnedLevel000097), "apply 000097 on %s", dbType())

	// 1.
	after := make([]map[string]string, len(shapes))
	for i, s := range shapes {
		after[i] = codeRow000097(t, h, ids[i])
		assert.Equalf(t, s.want, after[i]["acr_level"],
			"1. on %s a sign-in at %s with methods %q must hold %s: %s", dbType(), s.level, s.methods, s.want, s.why)
		for column, value := range before[i] {
			if column == "acr_level" {
				continue
			}
			assert.Equalf(t, value, after[i][column],
				"1. on %s 000097 changes only the level: codes.%s of the sign-in with methods %q moved", dbType(), column, s.methods)
		}
	}

	// 4.
	assertGrantAndSessionKept000097(t, h, "the up", refreshTokenID, refreshTokenBefore, sessionID, sessionBefore)

	// 2, second half: among the rows naming only real methods, the query listed exactly the ones
	// the migration lowered.
	for i, s := range shapes {
		if !s.realNames {
			continue
		}
		lowered := before[i]["acr_level"] != after[i]["acr_level"]
		assert.Equalf(t, lowered, slices.Contains(listed, ids[i]),
			"2. on %s the release-note query must list the sign-in at %s with methods %q exactly when 000097 lowers it (lowered: %v)",
			dbType(), s.level, s.methods, lowered)
	}

	// 3.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeLowerUnearnedLevel000097), "roll back 000097 on %s", dbType())
	for i, s := range shapes {
		assert.Equalf(t, after[i], codeRow000097(t, h, ids[i]),
			"3. on %s the down migration is a no-op: the sign-in with methods %q stays as the up left it", dbType(), s.methods)
	}
	assertGrantAndSessionKept000097(t, h, "the down", refreshTokenID, refreshTokenBefore, sessionID, sessionBefore)
	require.NoErrorf(t, h.Migrator.Migrate(ctx, lowerUnearnedLevel000097), "re-apply 000097 on %s", dbType())
	for i, s := range shapes {
		assert.Equalf(t, after[i], codeRow000097(t, h, ids[i]),
			"3. on %s the re-applied up changes nothing more on the sign-in with methods %q", dbType(), s.methods)
	}
	assertGrantAndSessionKept000097(t, h, "the re-applied up", refreshTokenID, refreshTokenBefore, sessionID, sessionBefore)
}

// assertGrantAndSessionKept000097 checks property 4 after the migration step named by step: the
// refresh token and the browser session are each the row they were at seeding, every column.
func assertGrantAndSessionKept000097(t *testing.T, h *isolatedDB, step string,
	refreshTokenID int64, refreshTokenBefore map[string]string, sessionID int64, sessionBefore map[string]string) {
	t.Helper()
	refreshToken := row000097(t, h, "refresh_tokens", refreshTokenID)
	assert.Equalf(t, refreshTokenBefore, refreshToken,
		"4. on %s %s leaves the lowered sign-in's offline refresh token as it was: the grant lives on", dbType(), step)
	assert.Equalf(t, "false", boolText000097(refreshToken["revoked"]),
		"4. on %s the refresh token is still live after %s", dbType(), step)
	assert.Equalf(t, sessionBefore, row000097(t, h, "user_sessions", sessionID),
		"4. on %s %s leaves the browser session as it was: nobody is signed out", dbType(), step)
}

// createOfflineRefreshToken000097 stores a live offline refresh token of the sign-in codeID in the
// shape the token issuer writes one (issuance.TokenIssuer, refresh_token_row.go): the family's
// first token, with no session identifier and a maximum lifetime, and returns its id. The columns
// are 000096's; auth_state_generation and dpop_jkt are left to their default and NULL, as for the
// unbound token of a sign-in at the default generation.
func createOfflineRefreshToken000097(t *testing.T, h *isolatedDB, codeID int64) int64 {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	jti := "m97jti_" + fake.LetterN(8)
	return seedRow000097(t, h, "refresh_tokens", "refresh_token_jti", jti, map[string]any{
		"created_at":                 now,
		"updated_at":                 now,
		"code_id":                    codeID,
		"refresh_token_jti":          jti,
		"previous_refresh_token_jti": "",
		"first_refresh_token_jti":    jti,
		"session_identifier":         "",
		"refresh_token_type":         "Offline",
		"scope":                      "openid offline_access",
		"issued_at":                  now,
		"expires_at":                 now.Add(30 * 24 * time.Hour),
		"max_lifetime":               now.Add(365 * 24 * time.Hour),
		"revoked":                    false,
	})
}

// createBrowserSession000097 stores a live browser session of userID at the highest level with a
// password alone, the pair the migration lowers in codes and leaves in sessions, and returns its id.
// The columns are 000096's; the ones with a default are left to it.
func createBrowserSession000097(t *testing.T, h *isolatedDB, userID int64) int64 {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	sessionIdentifier := "m97session_" + fake.LetterN(8)
	return seedRow000097(t, h, "user_sessions", "session_identifier", sessionIdentifier, map[string]any{
		"created_at":         now,
		"updated_at":         now,
		"session_identifier": sessionIdentifier,
		"started":            now,
		"last_accessed":      now,
		"auth_time":          now,
		"password_auth_time": now,
		"auth_methods":       "pwd",
		"acr_level":          string(record.ACRLevel2Mandatory),
		"ip_address":         "192.0.2.1",
		"device_name":        "",
		"device_type":        "",
		"device_os":          "",
		"user_id":            userID,
	})
}

// boolText000097 reads a boolean column as row000097 renders it on any engine: SQLite, SQL Server
// and MySQL hand back 0 or 1 (or true or false), PostgreSQL true or false.
func boolText000097(value string) string {
	switch value {
	case "1", "true":
		return "true"
	case "0", "false":
		return "false"
	}
	return value
}

// mustInt000097 parses an id column as row000097 renders it.
func mustInt000097(t *testing.T, value string) int64 {
	t.Helper()
	id, err := strconv.ParseInt(value, 10, 64)
	require.NoErrorf(t, err, "parse %q as an id", value)
	return id
}

// createSignIn000097 stores one sign-in of client and user at level with methods, in 000096's
// columns, and returns its id. revoked and auth_state_generation are left to their defaults.
func createSignIn000097(t *testing.T, h *isolatedDB, clientID, userID int64, level, methods string) int64 {
	t.Helper()
	random := fake.LetterN(8)
	now := time.Now().UTC().Truncate(time.Second)
	codeHash := "m97hash_" + random
	return seedRow000097(t, h, "codes", "code_hash", codeHash, map[string]any{
		"created_at":         now,
		"updated_at":         now,
		"client_id":          clientID,
		"user_id":            userID,
		"code_hash":          codeHash,
		"redirect_uri":       "https://example.com/callback",
		"scope":              "openid offline_access",
		"state":              "m97state_" + random,
		"nonce":              "m97nonce_" + random,
		"ip_address":         "192.0.2.1",
		"user_agent":         "migration 000097 test",
		"response_mode":      "query",
		"authenticated_at":   now,
		"session_identifier": "m97session_" + random,
		"acr_level":          level,
		"auth_methods":       methods,
		"used":               true,
	})
}

// seedRow000097 inserts one row of table with exactly the columns values names, bound through the
// engine's placeholders, and reads its id back by the unique value key holds in column keyColumn.
func seedRow000097(t *testing.T, h *isolatedDB, table, keyColumn, key string, values map[string]any) int64 {
	t.Helper()
	columns := make([]string, 0, len(values))
	for column := range values {
		columns = append(columns, column)
	}
	slices.Sort(columns)
	args := make([]any, len(columns))
	for i, column := range columns {
		args[i] = values[column]
	}
	insert := "INSERT INTO " + table + " (" + strings.Join(columns, ", ") + ") VALUES (" + seedBinds(len(args)) + ")"
	_, err := h.SQL.ExecContext(context.Background(), insert, args...)
	require.NoErrorf(t, err, "seed %s on %s", table, dbType())

	var id int64
	require.NoErrorf(t, h.SQL.QueryRowContext(context.Background(),
		"SELECT id FROM "+table+" WHERE "+keyColumn+" = "+seedBindAt(1), key).Scan(&id),
		"read back the seeded %s id on %s", table, dbType())
	return id
}

// codeRow000097 reads every column of one codes row in SQL, as text, so a column the migration
// should not touch is compared whatever it is.
func codeRow000097(t *testing.T, h *isolatedDB, id int64) map[string]string {
	t.Helper()
	return row000097(t, h, "codes", id)
}

// row000097 reads every column of the row of table with id in SQL, as text.
func row000097(t *testing.T, h *isolatedDB, table string, id int64) map[string]string {
	t.Helper()
	rows, err := h.SQL.Query(fmt.Sprintf("SELECT * FROM %s WHERE id = %d", table, id))
	require.NoErrorf(t, err, "read %s.id=%d on %s", table, id, dbType())
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	require.NoError(t, err)
	require.Truef(t, rows.Next(), "%s.id=%d is gone on %s; this migration deletes nothing", table, id, dbType())
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	require.NoError(t, rows.Scan(pointers...))
	require.NoError(t, rows.Err())

	row := make(map[string]string, len(columns))
	for i, column := range columns {
		switch v := values[i].(type) {
		case []byte:
			row[column] = string(v)
		case nil:
			row[column] = "<NULL>"
		default:
			row[column] = fmt.Sprint(v)
		}
	}
	return row
}

// releaseNoteQueryIDs000097 runs the release notes' query and returns the codes ids it lists.
func releaseNoteQueryIDs000097(t *testing.T, h *isolatedDB) []int64 {
	t.Helper()
	rows, err := h.SQL.Query(releaseNoteQuery000097)
	require.NoErrorf(t, err, "run the release-note query on %s", dbType())
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var (
			id                      int64
			email, clientIdentifier string
			createdAt               any
		)
		require.NoError(t, rows.Scan(&id, &email, &clientIdentifier, &createdAt))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	return ids
}
