package datatests

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000029_CreatedViaDCR exercises the migration that introduces the
// self-registration marker and backfills it from the dcr_ identifier prefix (#108).
// It runs against an ISOLATED database of the configured dialect (see
// migration_testdb_helper.go).
//
// The properties, in the order they appear below:
//
//  1. Absent at 000028, so the column found afterwards is the one 000029 added.
//
//  2. Declared NOT NULL with a default of false. A DEFAULT of true would mark every
//     administrator-created client as self-registered, which is the marking the consent
//     screen's "unverified" notice reads, and it would pass every behavioural test in
//     the suite because the ORM always writes the column explicitly and so never
//     exercises the default.
//
//  3. The backfill, against rows that predate the column. Four clients, each varying
//     one thing from the one above it, all seeded with ConsentRequired: false:
//
//     | identifier   | created_via_dcr | consent_required | what fails without it     |
//     |--------------|-----------------|------------------|---------------------------|
//     | dcr_<rand>   | true            | true             | the backfill itself, and  |
//     |              |                 |                  | its consent flip          |
//     | dcrX9999_... | false           | false            | ESCAPE '!' , since `_` is |
//     |              |                 |                  | a single-char wildcard    |
//     | mydcr_<rand> | false           | false            | the prefix being anchored |
//     | plain_<rand> | false           | false            | the NOT NULL default of   |
//     |              |                 |                  | false, on the engine      |
//
//  4. The down migration works and re-applying is clean. This has the engine-specific
//     hazard 000024 and 000026 have: SQL Server refuses to drop a column while a default
//     constraint depends on it, so 000029 names its constraint and drops it by name.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000029_CreatedViaDCR
func TestMigration000029_CreatedViaDCR(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(28), "migrate to 000028")

	// 1. Absent before the migration.
	exists, _, _ := createdViaDCRShape000029(t, h)
	assert.False(t, exists, "clients.created_via_dcr must not exist at 000028")

	require.NoError(t, h.Migrator.Migrate(29), "apply 000029")

	// 2. NOT NULL, defaulting to false.
	assertCreatedViaDCRShape000029(t, h, "after apply")

	// 3. The backfill, against rows that predate the column.
	//
	// Seeded through the ORM at the HEAD migration and then carried DOWN to 000028 and
	// back up, rather than seeded with raw SQL at 000028. Both prove the same thing, and
	// the round trip costs a dozen lines instead of a hand-written insert covering every
	// NOT NULL column of clients with per-dialect boolean literals for each. Seeding at
	// head rather than at 000029 is what keeps this test working when later migrations
	// arrive, since the ORM writes every column the Go models carry.
	// ErrNoChange is tolerated because 000029 is currently head, so Up() has nothing to
	// do. Calling it anyway is what keeps the seed at head once later migrations land:
	// the ORM writes every column the Go models carry, so seeding at 000029 would break
	// the moment a migration adds one, exactly as it broke the 000026 test when #111
	// landed users.last_otp_step at 000027.
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}

	random := gofakeit.LetterN(6)
	cases := []struct {
		identifier  string
		wantDCR     bool
		wantConsent bool
		why         string
	}{
		{"dcr_" + random, true, true,
			"an identifier the DCR handler actually produces must be backfilled, consent included"},
		{"dcrX9999_" + random, false, false,
			"`_` is a single-character wildcard, so LIKE 'dcr_%' without ESCAPE '!' matches this on all four engines"},
		{"mydcr_" + random, false, false,
			"the prefix must be anchored at the start of the identifier"},
		{"plain_" + random, false, false,
			"an ordinary administrator-created client must be untouched, and lands at the column's default"},
	}

	ids := make([]int64, len(cases))
	for i, c := range cases {
		client := &models.Client{
			ClientIdentifier: c.identifier,
			Description:      "Migration 000029 test client",
			ConsentRequired:  false,
			CreatedViaDCR:    false,
		}
		require.NoErrorf(t, h.DB.CreateClient(nil, client), "seed client %s", c.identifier)
		ids[i] = client.Id
	}

	require.NoError(t, h.Migrator.Migrate(28), "roll back to 000028")
	require.NoError(t, h.Migrator.Migrate(29), "re-apply 000029")

	for i, c := range cases {
		gotDCR, gotConsent := readClientFlags000029(t, h, ids[i])
		assert.Equalf(t, c.wantDCR, gotDCR,
			"%s: created_via_dcr, because %s", c.identifier, c.why)
		assert.Equalf(t, c.wantConsent, gotConsent,
			"%s: consent_required, because %s", c.identifier, c.why)
	}

	// 4. The column survives the round trip with its shape intact.
	assertCreatedViaDCRShape000029(t, h, "after down/up round trip")
}

func readClientFlags000029(t *testing.T, h *isolatedDB, clientId int64) (bool, bool) {
	t.Helper()
	var createdViaDCR, consentRequired bool
	q := fmt.Sprintf("SELECT created_via_dcr, consent_required FROM clients WHERE id = %d", clientId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&createdViaDCR, &consentRequired),
		"read clients.created_via_dcr and clients.consent_required")
	return createdViaDCR, consentRequired
}

func assertCreatedViaDCRShape000029(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	exists, notNull, def := createdViaDCRShape000029(t, h)
	require.Truef(t, exists, "[%s] clients.created_via_dcr must exist", phase)
	assert.Truef(t, notNull, "[%s] clients.created_via_dcr must be NOT NULL", phase)
	assert.Equalf(t, "0", def,
		"[%s] clients.created_via_dcr must default to false, got %q", phase, def)
}

// createdViaDCRShape000029 reports whether clients.created_via_dcr exists, whether it is
// NOT NULL, and its default expression normalised to "0" for false. It follows
// codeRevokedShape000026: absence is a result rather than a scan error, since this test
// asserts absence at 000028, and PostgreSQL reports a boolean default as `false` where
// the other three report `0`, so both spellings normalise to "0".
func createdViaDCRShape000029(t *testing.T, h *isolatedDB) (bool, bool, string) {
	t.Helper()

	const table, col = "clients", "created_via_dcr"
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
