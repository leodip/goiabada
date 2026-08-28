package datatests

import (
	"errors"
	"fmt"
	"testing"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emailBackfillCase is one seeded users row and what BackfillLowercaseEmails must do to it.
//
// ONE set of expectations, on all four engines, and that is the point rather than a
// simplification. It carried two until migration 000040 landed: MySQL and SQL Server folded
// case in the UNIQUE index on email, so a case-variant pair could not be seeded there at all
// and the second member's insert was refused, while SQLite and PostgreSQL accepted both rows.
// 000040 pins every string column to a case-sensitive collation, so the pair is now permitted
// on all four and the collision policy runs on all four.
type emailBackfillCase struct {
	seed        string
	want        string
	wantEnabled bool

	why string
}

// TestBackfillLowercaseEmails exercises the startup pass that brings every stored address down
// to its lowercase form and settles a pair that differs only by case (#221, #283). It runs
// against an ISOLATED database of the configured dialect (see migration_testdb_helper.go).
//
// The data tier is the tier that matters for it. The rule is written once in Go precisely
// because SQL cannot express it identically on four engines, and the fact that claim rests on is
// a fact about an engine: SQLite's own LOWER() maps ASCII only through modernc.org/sqlite, so
// the Ädmin case below is untouched there by any LOWER()-based statement. That is not
// observable from any other tier.
//
// The properties, in the order they appear below:
//
//  1. Every seeded shape lands on its stated address and its stated enabled flag, and a
//     disabled non-survivor keeps its address exactly as it was stored.
//
//  2. The pair can be seeded on EVERY engine, which is #283's own goal read from the other
//     side: before migration 000040 the insert was refused on MySQL and SQL Server. Asserted
//     rather than assumed, because if it stopped holding the collision expectations below
//     would be unreachable on two engines and nothing else would say so.
//
//  3. The counts returned match the rows that moved, so a pass that reported work it did not
//     do would fail here as well as one that did work it did not report.
//
//  4. A second run reports nothing and moves nothing. That is not decoration: a disabled
//     non-survivor deliberately KEEPS its mixed-case address, so it is selected by every later
//     scan, and only the enabled check stops it being counted again on every restart.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestBackfillLowercaseEmails
func TestBackfillLowercaseEmails(t *testing.T) {
	h := newIsolatedDB(t)
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding")
	}

	// Seeded in this order on purpose: the mixed-case member of each pair is written FIRST, so
	// it holds the lower id. A rule that fell back to the lowest id unconditionally would then
	// keep the row that cannot sign in, which is the outcome the survivor rule exists to avoid,
	// and a fixture seeded the other way round would agree with both rules.
	cases := []emailBackfillCase{
		{
			seed: "carol@x.com", want: "carol@x.com", wantEnabled: true,
			why: "already lowercase and alone, so nothing may touch it",
		},
		{
			seed: "Dave@x.com", want: "dave@x.com", wantEnabled: true,
			why: "mixed case and alone, the unambiguous repair",
		},
		{
			seed: "Bob@x.com", want: "Bob@x.com", wantEnabled: false,
			why: "the non-survivor of a pair: disabled, address untouched, because nothing here deletes, renames or merges an account",
		},
		{
			seed: "bob@x.com", want: "bob@x.com", wantEnabled: true,
			why: "the survivor of the pair: it is the row that signs in today and it keeps the address",
		},
		{
			seed: "ERIN@x.com", want: "erin@x.com", wantEnabled: true,
			why: "no member of this group is already lowercase, so the lowest id takes the address",
		},
		{
			seed: "Erin@x.com", want: "Erin@x.com", wantEnabled: false,
			why: "the loser of the fallback, disabled with its address intact",
		},
		{
			seed: "Ädmin@x.com", want: "ädmin@x.com", wantEnabled: true,
			why: "the case that separates Go's lowercase mapping from SQL's: SQLite's LOWER() is ASCII-only through modernc.org/sqlite, so a LOWER()-based statement would leave this row exactly as it is and the address would still be unreachable",
		},
	}

	ids := make(map[string]int64, len(cases))
	for i, c := range cases {
		user := &models.User{
			Enabled:  true,
			Subject:  uuid.New(),
			Username: fmt.Sprintf("emailbackfill%d", i),
			Email:    c.seed,
		}
		// 2. Every seed lands, on every engine, the case-variant pairs included. Before
		// migration 000040 the second member of a pair was refused on MySQL and SQL Server,
		// because idx_email folded case there.
		require.NoErrorf(t, h.DB.CreateUser(nil, user),
			"seed %q: since 000040 every engine holds a case-variant pair, so this insert must succeed on %s too",
			c.seed, dbType())
		ids[c.seed] = user.Id
	}

	lowercased, disabled, err := h.DB.BackfillLowercaseEmails()
	require.NoError(t, err, "BackfillLowercaseEmails")

	// 1 and 3.
	wantLowercased, wantDisabled := 0, 0
	for _, c := range cases {
		id, seeded := ids[c.seed]
		if !seeded {
			continue
		}

		want, wantEnabled := c.want, c.wantEnabled
		if want != c.seed {
			wantLowercased++
		}
		if !wantEnabled {
			wantDisabled++
		}

		got, err := h.DB.GetUserById(nil, id)
		require.NoErrorf(t, err, "read back the row seeded as %q", c.seed)
		require.NotNilf(t, got, "the row seeded as %q must still exist: this pass never deletes", c.seed)
		assert.Equalf(t, want, got.Email, "%q must end up as %q: %s", c.seed, want, c.why)
		assert.Equalf(t, wantEnabled, got.Enabled, "%q must end up enabled=%v: %s", c.seed, wantEnabled, c.why)
	}

	assert.Equalf(t, wantLowercased, lowercased,
		"the pass must report the rows it lowercased, and %d rows changed address on %s", wantLowercased, dbType())
	assert.Equalf(t, wantDisabled, disabled,
		"the pass must report the rows it disabled, and %d rows lost enabled on %s", wantDisabled, dbType())

	// 4. Idempotent and resumable, on BackfillEncryptedOTPSecrets' terms.
	lowercased2, disabled2, err := h.DB.BackfillLowercaseEmails()
	require.NoError(t, err, "second BackfillLowercaseEmails")
	assert.Zerof(t, lowercased2, "a second run has nothing left to lowercase on %s", dbType())
	assert.Zerof(t, disabled2, "a second run must not re-disable the non-survivors it already disabled on %s: they keep their mixed-case address on purpose, so they are selected by every later scan", dbType())

	for _, c := range cases {
		id, seeded := ids[c.seed]
		if !seeded {
			continue
		}
		want, wantEnabled := c.want, c.wantEnabled

		got, err := h.DB.GetUserById(nil, id)
		require.NoErrorf(t, err, "read back %q after the second run", c.seed)
		require.NotNil(t, got)
		assert.Equalf(t, want, got.Email, "%q must be unchanged by a second run", c.seed)
		assert.Equalf(t, wantEnabled, got.Enabled, "%q must be unchanged by a second run", c.seed)
	}
}
