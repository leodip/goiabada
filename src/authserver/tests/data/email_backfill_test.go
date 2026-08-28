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
// It has two sets of expectations because the engines do not agree about what can be SEEDED.
// MySQL and SQL Server fold case in the UNIQUE index on email, so a case-variant pair has
// never been able to exist there and the second member's insert is refused; SQLite and
// PostgreSQL accept both rows, which is the condition the collision policy exists for. The
// same seed therefore ends up a colliding pair on two engines and a lone mixed-case row on the
// other two, and both outcomes are stated rather than one being derived from the other.
type emailBackfillCase struct {
	seed        string
	want        string // on SQLite and PostgreSQL
	wantEnabled bool

	refusedWhenFolding bool   // the insert itself must fail on MySQL and SQL Server
	wantFolding        string // on MySQL and SQL Server, when it is seeded at all
	wantEnabledFolding bool

	why string
}

// TestBackfillLowercaseEmails exercises the startup pass that brings every stored address down
// to its lowercase form and settles a pair that differs only by case (#221, #283). It runs
// against an ISOLATED database of the configured dialect (see migration_testdb_helper.go).
//
// The data tier is the tier that matters for it. The rule is written once in Go precisely
// because SQL cannot express it identically on four engines, and the two facts that claim holds
// on are both facts about an engine: that MySQL and SQL Server cannot hold the pair at all, and
// that SQLite's own LOWER() maps ASCII only, so the Ädmin case below is untouched there by any
// LOWER()-based statement. Neither is observable from any other tier.
//
// The properties, in the order they appear below:
//
//  1. Every seeded shape lands on its stated address and its stated enabled flag, and a
//     disabled non-survivor keeps its address exactly as it was stored.
//
//  2. The pair cannot even be seeded where the index folds, which is what makes the plain
//     lowercase safe on those two engines rather than merely untested.
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

	folds := emailIndexFoldsCase()

	// Seeded in this order on purpose: the mixed-case member of each pair is written FIRST, so
	// it holds the lower id. A rule that fell back to the lowest id unconditionally would then
	// keep the row that cannot sign in, which is the outcome the survivor rule exists to avoid,
	// and a fixture seeded the other way round would agree with both rules.
	cases := []emailBackfillCase{
		{
			seed: "carol@x.com", want: "carol@x.com", wantEnabled: true,
			wantFolding: "carol@x.com", wantEnabledFolding: true,
			why: "already lowercase and alone, so nothing may touch it",
		},
		{
			seed: "Dave@x.com", want: "dave@x.com", wantEnabled: true,
			wantFolding: "dave@x.com", wantEnabledFolding: true,
			why: "mixed case and alone, the unambiguous repair",
		},
		{
			seed: "Bob@x.com", want: "Bob@x.com", wantEnabled: false,
			wantFolding: "bob@x.com", wantEnabledFolding: true,
			why: "the non-survivor of a pair: disabled, address untouched, because nothing here deletes, renames or merges an account. Where the index folds it is not a pair at all and is simply lowercased",
		},
		{
			seed: "bob@x.com", want: "bob@x.com", wantEnabled: true,
			refusedWhenFolding: true,
			why:                "the survivor of the pair: it is the row that signs in today and it keeps the address",
		},
		{
			seed: "ERIN@x.com", want: "erin@x.com", wantEnabled: true,
			wantFolding: "erin@x.com", wantEnabledFolding: true,
			why: "no member of this group is already lowercase, so the lowest id takes the address",
		},
		{
			seed: "Erin@x.com", want: "Erin@x.com", wantEnabled: false,
			refusedWhenFolding: true,
			why:                "the loser of the fallback, disabled with its address intact",
		},
		{
			seed: "Ädmin@x.com", want: "ädmin@x.com", wantEnabled: true,
			wantFolding: "ädmin@x.com", wantEnabledFolding: true,
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
		err := h.DB.CreateUser(nil, user)

		// 2. Where the index folds, the second member of a pair must be refused. That refusal
		// is the whole reason those two engines need no collision policy, so it is asserted
		// rather than assumed: if it ever stopped holding, the plain expectations below would
		// be wrong and nothing else would say so.
		if folds && c.refusedWhenFolding {
			require.Errorf(t, err,
				"seeding %q beside its case variant must be refused on %s: the UNIQUE index folds case there, which is why a pair cannot exist and the backfill cannot collide",
				c.seed, dbType())
			continue
		}

		require.NoErrorf(t, err, "seed %q", c.seed)
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
		if folds {
			want, wantEnabled = c.wantFolding, c.wantEnabledFolding
		}
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
		if folds {
			want, wantEnabled = c.wantFolding, c.wantEnabledFolding
		}

		got, err := h.DB.GetUserById(nil, id)
		require.NoErrorf(t, err, "read back %q after the second run", c.seed)
		require.NotNil(t, got)
		assert.Equalf(t, want, got.Email, "%q must be unchanged by a second run", c.seed)
		assert.Equalf(t, wantEnabled, got.Enabled, "%q must be unchanged by a second run", c.seed)
	}
}

// emailIndexFoldsCase reports whether the configured engine's UNIQUE index on users.email
// compares case-insensitively, which decides whether a case-variant pair can be seeded at all.
// True on MySQL (utf8mb4_0900_ai_ci) and SQL Server (Latin1_General_100_CI_AI_SC_UTF8), false
// on SQLite (BINARY) and PostgreSQL (a deterministic libc collation).
func emailIndexFoldsCase() bool {
	return dbType() == "mysql" || dbType() == "mssql"
}
