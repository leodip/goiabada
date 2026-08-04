package datatests

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000026_CodeRevoked exercises the migration that introduces the
// termination marker (#129). It runs against an ISOLATED database of the configured
// dialect (see migration_testdb_helper.go).
//
// The properties, in the order they appear below:
//
//  1. Absent at 000025, so the column found afterwards is the one 000026 added.
//  2. Declared NOT NULL with a default of false. A DEFAULT of true here would mark
//     every authorization code in the table as revoked at deployment, refusing every
//     redemption and every refresh in flight, and it would pass every behavioural
//     test in the suite because the ORM always writes the column explicitly and so
//     never exercises the default.
//  3. A codes row that predates the column reads revoked = false afterwards. This is
//     property 2 proved on the engine rather than in the DDL, and it is what keeps
//     authorizations already in flight working across the deployment.
//  4. The down migration works and re-applying is clean. Only the 000024 and 000025
//     tests execute a down migration at all, and this one has the same engine-specific
//     hazard 000024 has: SQL Server refuses to drop a column while a default
//     constraint depends on it, so 000026 names its constraint and drops it by name.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000026_CodeRevoked
func TestMigration000026_CodeRevoked(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(25), "migrate to 000025")

	// 1. Absent before the migration.
	exists, _, _ := codeRevokedShape000026(t, h)
	assert.False(t, exists, "codes.revoked must not exist at 000025")

	require.NoError(t, h.Migrator.Migrate(26), "apply 000026")

	// 2. NOT NULL, defaulting to false.
	assertCodeRevokedShape000026(t, h, "after apply")

	// 3. A row that predates the column lands at false.
	//
	// Seeded through the ORM at 000026 and then carried DOWN to 000025 and back up,
	// rather than seeded with raw SQL at 000025. Both prove the same thing, and the
	// round trip costs a dozen lines instead of a hand-written insert covering the
	// twenty NOT NULL columns of codes plus the clients and users rows its foreign
	// keys require, with per-dialect datetime and boolean literals for each.
	codeId := seedCode000026(t, h)

	require.NoError(t, h.Migrator.Migrate(25), "roll back 000026")
	require.NoError(t, h.Migrator.Migrate(26), "re-apply 000026")

	assert.False(t, readCodeRevoked000026(t, h, codeId),
		"a codes row that predates the column must land revoked = false")

	// 4. The column survives the round trip with its shape intact.
	assertCodeRevokedShape000026(t, h, "after down/up round trip")
}

// seedCode000026 inserts a client, a user and a code through the ORM against the
// isolated database, returning the code's id. The shared helpers in code_test.go
// cannot be reused: they write to the package-level `database`, which is the fully
// migrated shared test database rather than this one.
func seedCode000026(t *testing.T, h *isolatedDB) int64 {
	t.Helper()
	random := gofakeit.LetterN(6)

	client := &models.Client{
		ClientIdentifier: "mig26_client_" + random,
		Description:      "Migration 000026 test client",
	}
	require.NoError(t, h.DB.CreateClient(nil, client), "seed client")

	user := &models.User{
		Enabled:  true,
		Subject:  uuid.New(),
		Username: "mig26_" + random,
	}
	require.NoError(t, h.DB.CreateUser(nil, user), "seed user")

	// Two fields are here for engine-specific reasons, both found by running this on
	// all four rather than by reading the schema. The challenge fields, because SQLite
	// declares codes.code_challenge and codes.code_challenge_method NOT NULL where the
	// other three allow NULL. AuthenticatedAt, because a zero time.Time reaches MySQL
	// as '0000-00-00', which it rejects outright.
	code := &models.Code{
		ClientId:            client.Id,
		UserId:              user.Id,
		CodeHash:            "mig26_hash_" + random,
		CodeChallenge:       sql.NullString{String: "mig26_challenge_" + random, Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "mig26_state_" + random,
		Nonce:               "mig26_nonce_" + random,
		IpAddress:           "192.168.1.1",
		UserAgent:           "migration test",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   "mig26_session_" + random,
		AcrLevel:            "1",
		AuthMethods:         "pwd",
	}
	require.NoError(t, h.DB.CreateCode(nil, code), "seed code")

	return code.Id
}

func readCodeRevoked000026(t *testing.T, h *isolatedDB, codeId int64) bool {
	t.Helper()
	var revoked bool
	q := fmt.Sprintf("SELECT revoked FROM codes WHERE id = %d", codeId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&revoked), "read codes.revoked")
	return revoked
}

func assertCodeRevokedShape000026(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	exists, notNull, def := codeRevokedShape000026(t, h)
	require.Truef(t, exists, "[%s] codes.revoked must exist", phase)
	assert.Truef(t, notNull, "[%s] codes.revoked must be NOT NULL", phase)
	assert.Equalf(t, "0", def,
		"[%s] codes.revoked must default to false, got %q", phase, def)
}

// codeRevokedShape000026 reports whether codes.revoked exists, whether it is NOT NULL,
// and its default expression normalised to "0" for false. It follows
// generationColumnShape000024, with two differences: absence is a result rather than a
// scan error, since this test asserts absence at 000025, and the default is a boolean,
// which PostgreSQL reports as `false` where the other three report `0`. Both spellings
// normalise to "0" so one expectation covers every engine.
func codeRevokedShape000026(t *testing.T, h *isolatedDB) (bool, bool, string) {
	t.Helper()

	const table, col = "codes", "revoked"
	var q string
	switch dbType() {
	case "mysql":
		q = fmt.Sprintf(`SELECT IS_NULLABLE, COLUMN_DEFAULT FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = '%s' AND column_name = '%s'`, table, col)
	case "postgres":
		q = fmt.Sprintf(`SELECT is_nullable, column_default FROM information_schema.columns
			WHERE table_name = '%s' AND column_name = '%s'`, table, col)
	case "mssql":
		q = fmt.Sprintf(`SELECT CAST(c.is_nullable AS VARCHAR(1)), dc.definition
			FROM sys.columns c
			LEFT JOIN sys.default_constraints dc
			  ON dc.parent_object_id = c.object_id AND dc.parent_column_id = c.column_id
			WHERE c.object_id = OBJECT_ID('dbo.%s') AND c.name = '%s'`, table, col)
	default: // sqlite
		q = fmt.Sprintf(`SELECT CAST("notnull" AS TEXT), dflt_value
			FROM pragma_table_info('%s') WHERE name = '%s'`, table, col)
	}

	var nullFlag, def sql.NullString
	err := h.SQL.QueryRow(q).Scan(&nullFlag, &def)
	if err == sql.ErrNoRows {
		return false, false, ""
	}
	require.NoErrorf(t, err, "column metadata: %s.%s", table, col)

	notNull := false
	switch dbType() {
	case "mysql", "postgres":
		notNull = strings.EqualFold(nullFlag.String, "NO")
	case "mssql":
		notNull = nullFlag.String == "0"
	default: // sqlite
		notNull = nullFlag.String == "1"
	}

	// Defaults come back variously as `0`, `'0'`, `((0))` and `false`.
	normalised := strings.Trim(strings.TrimSpace(def.String), "()' ")
	if strings.EqualFold(normalised, "false") {
		normalised = "0"
	}
	return true, notNull, normalised
}
