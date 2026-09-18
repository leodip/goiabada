package datatests

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// beforeLowercaseEmails000047 is the version these tests seed at: the one below the migration
// under test. Derived from the constant so a renumbering moves both together.
const beforeLowercaseEmails000047 = datafactory.LowercaseEmailsVersion - 1

// lowercaseCase000047 is one seeded address and whether THIS engine's own LOWER() reduces it the
// way Go's strings.ToLower does.
//
// agrees is the whole per-engine table, and it is a measurement rather than a guess. Migration
// 000047 repairs exactly what `WHERE email <> LOWER(email)` selects, so where the engine and Go
// disagree the migration reports success and leaves an address no credential path can reach, all
// of them lowercasing in Go before they look a user up. That divergence is what the four-engine
// tier is rationed for: it is invisible on sqlite-only runs for two of the five characters here
// and invisible on every engine but SQL Server for two others.
type lowercaseCase000047 struct {
	raw    string
	agrees map[string]bool // engine name -> does its LOWER() agree with Go on this address
	why    string
}

// lowercaseCases000047 is the table, measured against the dev stack at #351 stage 2:
//
//	character          go        sqlite      mysql   postgres   mssql
//	U+00C4  Ä          ä         unchanged   ä       ä          ä
//	U+0130  İ          i         unchanged   i       i          i
//	U+0391  Α          α         unchanged   α       α          α
//	U+1E9E  ẞ          ß         unchanged   ß       ß          unchanged
//	U+212A  K kelvin   k         unchanged   k       k          unchanged
//
// SQLite maps ASCII only through modernc.org/sqlite, which is what #283 cited when it wrote this
// rule in Go rather than in SQL. SQL Server leaves U+1E9E and U+212A alone at the collation
// 000040 installs, which decision 17 had recorded as Unicode-aware and is not.
func lowercaseCases000047() []lowercaseCase000047 {
	all := map[string]bool{"sqlite": true, "mysql": true, "postgres": true, "mssql": true}
	asciiOnly := map[string]bool{"sqlite": false, "mysql": true, "postgres": true, "mssql": true}
	notMsSQL := map[string]bool{"sqlite": false, "mysql": true, "postgres": true, "mssql": false}

	return []lowercaseCase000047{
		{"Legacy.User@Example.COM", all,
			"pure ASCII, which every engine folds: the legacy row this migration exists for"},
		{"already.lower@example.com", all,
			"already its own lowercase form, so the predicate must not select it and nothing must change"},
		{"ÄDMIN@X1.example.com", asciiOnly,
			"non-ASCII beside ASCII. On sqlite the predicate DOES select this row and the UPDATE writes a value that is still not the form a sign-in looks up, which is worse than being skipped: the migration touched it and left it wrong"},
		{"İstanbul@x2.example.com", asciiOnly,
			"U+0130 lowercases to plain 'i' in Go, and sqlite leaves it: a row that looks untouched because nothing else in it is uppercase"},
		{"Αlpha@x3.example.com", asciiOnly,
			"Greek capital alpha, the case that says the sqlite gap is the whole non-ASCII alphabet rather than Latin accents"},
		{"ẞharp@x4.example.com", notMsSQL,
			"U+1E9E is the character that falsified decision 17's premise: SQL Server leaves it, so this is not a sqlite special case and cannot be a character list"},
		{"Kelvin@x5.example.com", notMsSQL,
			"the Kelvin sign, which Go folds to plain ASCII 'k'. Two engines leave it, and one of them is not the one anybody expected"},
	}
}

// engineName000047 is the engine this run is against, spelled the way the case table keys it.
func engineName000047() string {
	if dbType() == "" {
		return "sqlite"
	}
	return dbType()
}

// TestMigration000047_LowercaseEmails exercises the migration that replaced
// commondb.BackfillLowercaseEmails, and the pre-flight that guards it, against a REAL engine of
// the configured dialect (see migration_testdb_helper.go).
//
// This is the tier that matters for this change. The whole design rests on a claim about SQL that
// only a live engine can settle: that `LOWER()` means four different things, and that the Go-side
// pre-flight refuses exactly the rows the SQL will not reach. Nothing but the data tier runs
// mysql, postgres and mssql at all, and two of the five characters below diverge only on mssql.
//
// The properties, in order:
//
//  1. Every seeded address lands on what THIS engine's LOWER() makes of it, and the case table
//     says per engine whether that is the value Go would have produced.
//
//  2. The pre-flight names exactly the rows the migration then fails to bring to their Go
//     lowercase form. That is the load-bearing one: it ties the Go rule and the SQL predicate
//     together at their boundary, where each being separately plausible is what would let a row
//     fall between them.
//
//  3. idx_email is still UNIQUE afterwards and still bites, since lowercasing a column under a
//     unique index is the one thing this migration could break.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000047_LowercaseEmails
func TestMigration000047_LowercaseEmails(t *testing.T) {
	h := newIsolatedDB(t)
	engine := engineName000047()

	// To head first, then back down, on migration_000034's pattern: the ORM writes every column
	// the Go models carry, so seeding at an older version only works if the columns are there.
	// 000047's down is a no-op, so stepping back to 000046 undoes nothing and changes no shape.
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}
	require.NoError(t, h.Migrator.Migrate(beforeLowercaseEmails000047), "roll back to 000046")

	cases := lowercaseCases000047()
	ids := make([]int64, len(cases))
	for i, c := range cases {
		ids[i] = seedUserEmail000047(t, h, i, c.raw)
	}

	// 2, first half: what the pre-flight says BEFORE the migration runs. Collected here so the
	// same set can be compared against what the migration actually leaves behind.
	preflightErr := datafactory.CheckEmailCaseBeforeMigrating(h.DB, beforeLowercaseEmails000047, datafactory.LowercaseEmailsVersion)

	// Ordinary upgrades must not be refused, so the engines that agree about all five characters
	// have to pass this table outright. That is what says the refusals below are about the rows.
	anyDisagreement := false
	for _, c := range cases {
		if !c.agrees[engine] {
			anyDisagreement = true
		}
	}
	if !anyDisagreement {
		require.NoErrorf(t, preflightErr,
			"on %s every address here is one the engine reduces the way Go does, so the upgrade must go through", engine)
	} else {
		require.Errorf(t, preflightErr,
			"on %s at least one address will not be reduced the way Go does, and a silent survival is what this check exists to prevent", engine)
	}

	// The migration itself. It must SUCCEED on every engine: nothing seeded here collides, and a
	// row the engine cannot reduce is left behind rather than failing the statement, which is
	// precisely why the pre-flight and not the UPDATE is what refuses.
	require.NoErrorf(t, h.Migrator.Migrate(datafactory.LowercaseEmailsVersion), "apply 000047 on %s", engine)

	// 1 and 2, second half.
	var leftBehind []int64
	for i, c := range cases {
		got := storedEmail000047(t, h, ids[i])
		want := strings.ToLower(c.raw)

		if c.agrees[engine] {
			assert.Equalf(t, want, got,
				"on %s %q must end up as %q: %s", engine, c.raw, want, c.why)
			continue
		}

		assert.NotEqualf(t, want, got,
			"on %s %q is NOT supposed to reach %q -- if it did, the case table is wrong about this engine and the pre-flight is refusing an upgrade for no reason: %s",
			engine, c.raw, want, c.why)
		leftBehind = append(leftBehind, ids[i])
	}

	// 2, the tie. Every row the engine could not bring to its Go lowercase form is a row the
	// pre-flight named, and no row it named came through clean.
	for _, id := range leftBehind {
		require.Errorf(t, preflightErr,
			"users.id=%d survived 000047 still not lowercase on %s, so the pre-flight had to have refused", id, engine)
		assert.Containsf(t, preflightErr.Error(), fmt.Sprintf("users.id=%d", id),
			"users.id=%d survived 000047 still not lowercase on %s, and the pre-flight did not name it: that row reaches production unreachable by every sign-in path, which is the silent outcome the whole check exists to prevent",
			id, engine)
	}
	if preflightErr != nil {
		for i, c := range cases {
			if c.agrees[engine] {
				assert.NotContainsf(t, preflightErr.Error(), fmt.Sprintf("users.id=%d", ids[i]),
					"on %s the engine reduces %q the way Go does, so naming it would send an operator to fix a row that is fine", engine, c.raw)
			}
		}
	}

	// 3. Lowercasing a column under a UNIQUE index is the one thing this migration could break.
	assertEmailIndex000047(t, h, "after applying 000047")

	// The down migration is a no-op and re-applying is clean: the repaired values stay repaired,
	// which the file says, because the original casing is recorded nowhere.
	require.NoError(t, h.Migrator.Migrate(beforeLowercaseEmails000047), "roll back 000047")
	assert.Equal(t, strings.ToLower(cases[0].raw), storedEmail000047(t, h, ids[0]),
		"the down migration is a no-op: a repaired address must stay repaired")
	require.NoError(t, h.Migrator.Migrate(datafactory.LowercaseEmailsVersion), "re-apply 000047")
	assertEmailIndex000047(t, h, "after a down/up round trip")
}

// TestMigration000047_ACollisionWouldFailTheMigration is why the pre-flight is a refusal rather
// than a warning, demonstrated rather than reasoned: on a database holding two addresses that
// differ only by case, 000047's UPDATE really does fail.
//
// That failure is the expensive one. The migrator writes a dirty marker before each file runs and
// clears it after; a dirty database refuses to start with ErrDirty; and `migrate` has no force
// verb, so recovery means hand-editing schema_migrations in SQL. So this test asserts both halves
// in the order that matters: the pre-flight refuses first, and the migration would indeed have
// failed had it not.
//
// A collision is representable on all four engines HERE, after 000040 has relaxed MySQL's and SQL
// Server's folding collation. On an upgrade from a released version it can only pre-exist on
// SQLite and PostgreSQL, which is #351 decision 15's finding; the refusal costs nothing either
// way and this is the cheapest place to show the failure it prevents.
func TestMigration000047_ACollisionWouldFailTheMigration(t *testing.T) {
	h := newIsolatedDB(t)

	if err := h.Migrator.Up(); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}
	require.NoError(t, h.Migrator.Migrate(beforeLowercaseEmails000047), "roll back to 000046")

	upper := seedUserEmail000047(t, h, 0, "Collide@example.com")
	lower := seedUserEmail000047(t, h, 1, "collide@example.com")

	err := datafactory.CheckEmailCaseBeforeMigrating(h.DB, beforeLowercaseEmails000047, datafactory.LowercaseEmailsVersion)
	require.Errorf(t, err, "two addresses differing only by case must refuse the upgrade on %s", engineName000047())
	assert.Contains(t, err.Error(), fmt.Sprintf("users.id=%d", upper))
	assert.Contains(t, err.Error(), fmt.Sprintf("users.id=%d", lower),
		"both rows must be named: the operator has to decide which account keeps the address, and this server will not choose")

	// And the refusal is not theatre. Nothing else in this suite shows that the alternative is a
	// failed migration rather than a tidier one.
	assert.Errorf(t, h.Migrator.Migrate(datafactory.LowercaseEmailsVersion),
		"lowercasing both rows onto one value must trip the UNIQUE idx_email on %s; if this passes, the unique index is not being enforced and the pre-flight is guarding nothing",
		engineName000047())
}

// seedUserEmail000047 stores raw verbatim and returns the row's id.
//
// Through the ORM rather than raw SQL: the placeholder differs on all four engines and the models
// write every column the table needs. The data layer stores what it is given -- the lowercasing
// every endpoint does lives in the handlers -- which is exactly why a legacy database can hold one
// of these and this migration has to exist.
func seedUserEmail000047(t *testing.T, h *isolatedDB, n int, raw string) int64 {
	t.Helper()

	user := &models.User{
		Enabled:      true,
		Subject:      fmt.Sprintf("00000000-0000-0000-0000-0000000470%02d", n),
		Username:     fmt.Sprintf("mig47user%d", n),
		Email:        raw,
		PasswordHash: "not-a-real-hash",
	}
	require.NoErrorf(t, h.DB.CreateUser(nil, user), "seed user with email %q", raw)
	return user.Id
}

// storedEmail000047 reads one address back through the ORM, which is what a credential path would
// read, so a difference here is a difference a sign-in would meet.
func storedEmail000047(t *testing.T, h *isolatedDB, id int64) string {
	t.Helper()
	user, err := h.DB.GetUserById(nil, id)
	require.NoErrorf(t, err, "read back users.id=%d", id)
	require.NotNilf(t, user, "users.id=%d is gone; this migration deletes nothing", id)
	return user.Email
}

// assertEmailIndex000047 checks that idx_email is still UNIQUE in the catalog and still enforced,
// because "declared" and "enforced" are different claims and the second is the one that matters.
func assertEmailIndex000047(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	shape := describeIndex(t, h, "users", "idx_email")
	require.Truef(t, shape.Exists, "[%s] idx_email is missing on %s", phase, engineName000047())
	assert.Truef(t, shape.Unique,
		"[%s] idx_email must still be UNIQUE: it is what makes an email case collision impossible to create, and this migration writes to the column it covers",
		phase)

	taken := &models.User{
		Enabled:      true,
		Subject:      "00000000-0000-0000-0000-000000047099",
		Username:     "mig47dup",
		Email:        strings.ToLower(lowercaseCases000047()[0].raw),
		PasswordHash: "not-a-real-hash",
	}
	assert.Errorf(t, h.DB.CreateUser(nil, taken),
		"[%s] a second row holding an address already stored must be refused", phase)
}

// TestNewDatabase_RefusesAnEmailCaseCollisionAtStartup is the OTHER entry point. The pre-flight
// guards two of them and they are reached by different callers: `migrate to` comes through
// OpenDatabase, and every server start comes through NewDatabase, which migrates to head on the
// way out. A check wired into one of them only would leave whichever it missed able to trip
// idx_email and leave the schema dirty, which is the state decision 16 exists to prevent.
//
// sqlite only: NewDatabase takes a config.DatabaseConfig, and a DSN pointing at a throwaway file
// is the one way to reach it without touching the shared test database this tier runs against.
// What is under test is the wiring rather than any engine's LOWER(), and the engines are
// TestMigration000047_LowercaseEmails' business.
func TestNewDatabase_RefusesAnEmailCaseCollisionAtStartup(t *testing.T) {
	if engineName000047() != "sqlite" {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the wiring under test is engine-independent")
	}

	dsn := filepath.Join(t.TempDir(), "startup_preflight.db")
	cfg := &config.DatabaseConfig{Type: "sqlite", DSN: dsn}

	// A database sitting one below 000047 with a collision already in it, which is what a legacy
	// deployment upgrading across this release looks like.
	seed, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: dsn}, false)
	require.NoError(t, err, "open the throwaway database")
	m, err := seed.NewMigrator()
	require.NoError(t, err)
	require.NoError(t, m.Migrate(beforeLowercaseEmails000047), "step the throwaway database to 000046")
	require.NoError(t, seed.CreateUser(nil, &models.User{
		Enabled: true, Subject: "00000000-0000-0000-0000-000000047101",
		Username: "mig47start0", Email: "Startup@example.com", PasswordHash: "not-a-real-hash",
	}))
	require.NoError(t, seed.CreateUser(nil, &models.User{
		Enabled: true, Subject: "00000000-0000-0000-0000-000000047102",
		Username: "mig47start1", Email: "startup@example.com", PasswordHash: "not-a-real-hash",
	}))
	require.NoError(t, seed.DB.Close(), "close the seeding handle before the server opens its own")

	opened, err := datafactory.NewDatabase(cfg,
		config.GetAESEncryptionKey(), config.GetAESEncryptionKeyPrevious(), false)

	require.Error(t, err, "startup must refuse a database holding a collision rather than migrate it")
	assert.Nil(t, opened, "a refused startup must hand back no database")
	assert.Contains(t, err.Error(), "Startup@example.com",
		"the refusal is the only message the operator gets, and it has to name the rows")

	// And it refused BEFORE writing anything, which is the whole reason it is a pre-flight.
	check, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: dsn}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = check.DB.Close() })
	checkMigrator, err := check.NewMigrator()
	require.NoError(t, err)
	version, dirty, err := checkMigrator.Version()
	require.NoError(t, err)
	assert.Equal(t, beforeLowercaseEmails000047, version,
		"the schema must not have moved, so the operator can fix the rows and start the server again")
	assert.False(t, dirty,
		"a dirty database refuses to start and there is no supported way back, which is exactly what checking before Migrate avoids")
}
