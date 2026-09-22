package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/bootstrap"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedConfig is a single-step first run: the seed stores the given client secret and startup
// continues, so no bootstrap file is involved.
func seedConfig(adminEmail string) bootstrap.Config {
	return bootstrap.Config{
		AdminEmail:          adminEmail,
		AdminPassword:       "SeedTest_p4ssword!",
		AppName:             "Goiabada",
		AuthServerBaseURL:   "https://localhost:8080",
		AdminConsoleBaseURL: "https://localhost:8081",
		OAuthClientSecret:   "seed-test-client-secret",
	}
}

func migratedIsolatedDB(t *testing.T) *isolatedDB {
	t.Helper()
	h := newIsolatedDB(t)
	if err := h.Migrator.Up(context.Background()); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding")
	}
	return h
}

// TestSeederLowercasesAdminEmail pins the first-run half of #221: GOIABADA_ADMIN_EMAIL used to
// reach users.email verbatim, with no ToLower anywhere on the path, so an operator who set
// Admin@Example.com got an admin account that could not sign in AT ALL on SQLite or PostgreSQL.
// Both compare "=" exactly, and the password form and the ROPC grant each look the account up
// by the lowercased address, so the two spellings never met.
//
// It runs against an ISOLATED database (see migration_testdb_helper.go) because it seeds a
// whole deployment, which the shared test database already has.
//
// The stored value is asserted, not merely the lookup. On MySQL and SQL Server the lookup
// answers today whatever the case, because the collation folds it, so a test that only asked
// whether the admin can be found would pass on two of the four engines with the defect intact
// and stop passing on those two the moment #283 pins a case-sensitive collation.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestSeederLowercasesAdminEmail
func TestSeederLowercasesAdminEmail(t *testing.T) {
	h := migratedIsolatedDB(t)

	const givenEmail = "Admin@Example.com"
	const wantEmail = "admin@example.com"

	outcome, err := bootstrap.Run(context.Background(), h.DB, seedConfig(givenEmail))
	require.NoError(t, err, "seed a fresh deployment with a mixed-case admin address")
	require.Equal(t, bootstrap.Continue, outcome)

	user, err := h.DB.GetUserByEmail(context.Background(), nil, wantEmail)
	require.NoError(t, err, "look the admin up the way both credential paths do")
	require.NotNilf(t, user,
		"the seeded admin must be reachable by the lowercased address: that is the only spelling the password form and the ROPC grant ever ask for")

	assert.Equalf(t, wantEmail, user.Email,
		"the seeder must store %q lowercased. Storing %q verbatim is what locks the admin out on the two engines that compare exactly, and it is invisible on the two that fold",
		givenEmail, givenEmail)
}

var errSeedFault = errors.New("injected seed failure")

// seedFaultDB fails the seed on a real engine at the two points that matter to #424 decision 14:
// after the settings insert has executed, which draws the settings row's id from the engine's
// counter, and at the commit, after all nineteen writes have run. The commit is failed by
// cancelling the transaction's context once the body has returned, which database/sql answers by
// rolling back.
type seedFaultDB struct {
	data.Database
	failAfterSettings bool
	failCommit        bool
}

func (f *seedFaultDB) CreateInitialSettings(ctx context.Context, tx *sql.Tx, settings *models.Settings) error {
	if err := f.Database.CreateInitialSettings(ctx, tx, settings); err != nil {
		return err
	}
	if f.failAfterSettings {
		return errSeedFault
	}
	return nil
}

func (f *seedFaultDB) RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if !f.failCommit {
		return f.Database.RunInTransaction(ctx, fn)
	}
	txCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	return f.Database.RunInTransaction(txCtx, func(tx *sql.Tx) error {
		err := fn(tx)
		cancel()
		return err
	})
}

// seededRowCounts answers the row count of every table the seed writes.
func seededRowCounts(t *testing.T, h *isolatedDB) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range []string{"clients", "redirect_uris", "users", "resources", "permissions",
		"clients_permissions", "users_permissions", "key_pairs", "settings"} {
		var n int
		require.NoError(t, h.SQL.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n), table)
		counts[table] = n
	}
	return counts
}

// TestSeed_AFailedFirstSeedLeavesNothingAndTheNextSeeds is #424's atomicity on every engine. The
// unit tier proves it on SQLite, where a write made outside the transaction hangs; here, a write
// that escaped the transaction would survive the rollback and be counted, and the reseed would
// fail on it. And on PostgreSQL, MySQL and SQL Server the failed attempt consumes the settings
// row's id, which the engines do not give back: the reseed's row is asserted at id 1 and IsEmpty
// false, which held only on SQLite before the seed named the id (decision 14).
func TestSeed_AFailedFirstSeedLeavesNothingAndTheNextSeeds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault seedFaultDB
	}{
		{"after the settings insert executed", seedFaultDB{failAfterSettings: true}},
		{"at the commit", seedFaultDB{failCommit: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := migratedIsolatedDB(t)
			ctx := context.Background()
			before := seededRowCounts(t, h)
			faults := tc.fault
			faults.Database = h.DB

			outcome, err := bootstrap.Run(ctx, &faults, seedConfig("admin@example.com"))

			require.Error(t, err)
			assert.Equal(t, bootstrap.Refused, outcome)
			isEmpty, err := h.DB.IsEmpty(ctx)
			require.NoError(t, err)
			assert.True(t, isEmpty, "the failed seed left the database empty")
			assert.Equal(t, before, seededRowCounts(t, h), "and every one of its writes was rolled back")

			outcome, err = bootstrap.Run(ctx, h.DB, seedConfig("admin@example.com"))

			require.NoError(t, err, "the next start seeds")
			assert.Equal(t, bootstrap.Continue, outcome)
			settings, err := h.DB.GetSettingsById(ctx, nil, 1)
			require.NoError(t, err)
			require.NotNil(t, settings, "the reseed's settings row is at id 1, whatever the failed attempt drew")
			isEmpty, err = h.DB.IsEmpty(ctx)
			require.NoError(t, err)
			assert.False(t, isEmpty)
			client, err := h.DB.GetClientByClientIdentifier(ctx, nil, constants.AdminConsoleClientIdentifier)
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}
