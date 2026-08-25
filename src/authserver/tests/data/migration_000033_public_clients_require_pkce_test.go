package datatests

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000033_PublicClientsRequirePKCE exercises the migration that brings
// clients.pkce_required into line with the rule that a public client always requires PKCE
// (#245). It runs against an ISOLATED database of the configured dialect (see
// migration_testdb_helper.go).
//
// The migration is data-only: one UPDATE, no column and no schema change. What it has to get
// right is its predicate, and a wrong predicate here fails SILENTLY rather than erroring, in
// both directions. Too narrow and a public client keeps a NULL that the console renders as
// "inherit; currently optional"; too wide and it rewrites confidential clients, which is the
// one thing the migration must not do, because the whole point of the rule is that it is
// public-only.
//
// The properties, in the order they appear below:
//
//  1. The four seeded clients still hold what they were seeded with once the migration is
//     rolled back. That is what makes property 2 mean anything: without it, "became true"
//     could be describing the seed rather than the UPDATE. It also pins that the down
//     migration is a genuine no-op that neither errors nor touches data.
//
//  2. The conversion, and its boundary. Four clients, each varying one thing:
//
//     | is_public | seeded pkce_required | after 000033   | what fails without it        |
//     |-----------|----------------------|----------------|------------------------------|
//     | true      | false                | true           | the conversion #245 is about |
//     | true      | NULL                 | true           | the NULL half of the         |
//     |           |                      |                | predicate                    |
//     | false     | false                | false, as before| the public-only boundary    |
//     | false     | NULL                 | NULL, as before| the same boundary, strictly  |
//
//     Rows 3 and 4 are the ones that matter, and each names its rejecting mechanism: the
//     WHERE is_public predicate is the only thing in the migration that can leave them alone,
//     since nothing else in the file writes clients. Row 4 is the stricter of the two,
//     because a predicate widened to "or pkce_required IS NULL" would still leave row 3
//     correct. Read back as sql.NullBool, since NULL and false are different states here:
//     NULL means "inherit the global setting" and is exactly what decision 7 migrates away
//     from.
//
//  3. Re-applying is harmless. The round trip performs the UPDATE a second time over rows it
//     has already converted, which is what the "one predicate covers both and re-running is
//     harmless" claim in the migration's own comment amounts to.
//
// Seeded through the ORM at HEAD and then carried down and back up, following 000029: a
// hand-written insert would have to cover every NOT NULL column of clients with per-dialect
// boolean literals, and it would break the moment a later migration adds one. The down being
// a documented no-op is what makes the round trip work here, since it leaves the seeded
// values in place for the re-applied up to convert.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000033_PublicClientsRequirePKCE
func TestMigration000033_PublicClientsRequirePKCE(t *testing.T) {
	h := newIsolatedDB(t)

	// ErrNoChange is tolerated because 000033 is currently head, so Up() may have nothing to
	// do. Calling it anyway is what keeps the seed at head once later migrations land: the ORM
	// writes every column the Go models carry, so seeding at 000033 would break the moment a
	// migration adds one.
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}

	no, yes := false, true
	random := gofakeit.LetterN(6)
	cases := []struct {
		name     string
		isPublic bool
		seeded   *bool
		want     sql.NullBool
		why      string
	}{
		{
			name: "public_explicit_false", isPublic: true, seeded: &no,
			want: sql.NullBool{Bool: true, Valid: true},
			why:  "a public client whose administrator turned PKCE off is what #245 is about",
		},
		{
			name: "public_null", isPublic: true, seeded: nil,
			want: sql.NullBool{Bool: true, Valid: true},
			why: "NULL must move too, or the console renders the client as inheriting a " +
				"global setting that can later be turned off",
		},
		{
			name: "confidential_explicit_false", isPublic: false, seeded: &no,
			want: sql.NullBool{Bool: false, Valid: true},
			why:  "the mandate is public-only, so a confidential opt-out survives untouched",
		},
		{
			name: "confidential_null", isPublic: false, seeded: nil,
			want: sql.NullBool{Valid: false},
			why: "the same boundary, strictly: the migration fills no NULL it was not asked " +
				"to, so this client keeps inheriting the global setting",
		},
		{
			// A fifth client, already correct, so the UPDATE has a row it must leave as it
			// found it rather than only rows it changes.
			name: "public_already_true", isPublic: true, seeded: &yes,
			want: sql.NullBool{Bool: true, Valid: true},
			why:  "already compliant, and re-running the conversion over it must be a no-op",
		},
	}

	ids := make([]int64, len(cases))
	for i, c := range cases {
		client := &models.Client{
			ClientIdentifier: fmt.Sprintf("mig33_%s_%s", c.name, random),
			Description:      "Migration 000033 test client",
			IsPublic:         c.isPublic,
			PKCERequired:     c.seeded,
		}
		require.NoErrorf(t, h.DB.CreateClient(nil, client), "seed client %s", c.name)
		ids[i] = client.Id
	}

	// 1. The down is a no-op: it must not error, and the seeded values must survive it. This
	// is what stops property 2 below describing the seed instead of the UPDATE.
	require.NoError(t, h.Migrator.Migrate(32), "roll back to 000032")
	for i, c := range cases {
		seeded := sql.NullBool{Valid: false}
		if c.seeded != nil {
			seeded = sql.NullBool{Bool: *c.seeded, Valid: true}
		}
		assert.Equalf(t, seeded, readPKCERequired000033(t, h, ids[i]),
			"%s: pkce_required at 000032 must still be what the seed wrote, or the "+
				"assertion after the migration proves nothing", c.name)
	}

	// 2 and 3. Re-apply, which is also the second time this UPDATE runs over the rows it
	// already converted.
	require.NoError(t, h.Migrator.Migrate(33), "re-apply 000033")
	for i, c := range cases {
		assert.Equalf(t, c.want, readPKCERequired000033(t, h, ids[i]),
			"%s: pkce_required after 000033, because %s", c.name, c.why)
	}
}

// readPKCERequired000033 reads clients.pkce_required as a NullBool. The column is nullable on
// all four engines and NULL is a distinct state from false, meaning "inherit the global
// setting", so scanning into a plain bool would collapse the two rows this test exists to
// tell apart.
func readPKCERequired000033(t *testing.T, h *isolatedDB, clientId int64) sql.NullBool {
	t.Helper()
	var pkceRequired sql.NullBool
	q := fmt.Sprintf("SELECT pkce_required FROM clients WHERE id = %d", clientId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&pkceRequired), "read clients.pkce_required")
	return pkceRequired
}
