package datatests

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/bootstrap"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
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
// It runs against an ISOLATED database (see migration_testdb_helper_test.go) because it seeds a
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

	outcome, err := bootstrap.Run(context.Background(), h.DB, dataCipher, seedConfig(givenEmail))
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

// TestSeed_TheAuthServerPermissionsAreTheBuiltIns holds a fresh deployment's authserver resource
// to exactly the built-in permissions, on every engine. The list and the seed have to agree: the
// resource's permissions save demands every built-in by its row, so a built-in the seed does not
// write answers every save of that resource with a 500. userinfo is in neither since #449.
func TestSeed_TheAuthServerPermissionsAreTheBuiltIns(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	outcome, err := bootstrap.Run(ctx, h.DB, dataCipher, seedConfig("admin@example.com"))
	require.NoError(t, err)
	require.Equal(t, bootstrap.Continue, outcome)

	resource, err := h.DB.GetResourceByResourceIdentifier(ctx, nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, resource)
	permissions, err := h.DB.GetPermissionsByResourceId(ctx, nil, resource.Id)
	require.NoError(t, err)
	identifiers := make([]string, 0, len(permissions))
	for _, p := range permissions {
		identifiers = append(identifiers, p.PermissionIdentifier)
	}
	assert.ElementsMatchf(t, builtin.AuthServerPermissionIdentifiers(), identifiers,
		"the seed must write the built-in permissions and no other on %s", dbType())
	assert.Len(t, identifiers, 7)
}

// TestSeed_TheAdministrativeDescriptionsStateTheBoundary holds a fresh deployment's built-in
// permission descriptions to the wording #402 decision 3 sets, which the console shows where an
// operator picks a permission to grant: manage, manage-users, manage-clients and manage-settings
// say what reaches an administrator and what does not, and the other three keep theirs. Migration
// 000058 writes the same wording on an installation seeded before it, and the two must not drift,
// which is why the expected map is the migration test's own.
func TestSeed_TheAdministrativeDescriptionsStateTheBoundary(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	outcome, err := bootstrap.Run(ctx, h.DB, dataCipher, seedConfig("admin@example.com"))
	require.NoError(t, err)
	require.Equal(t, bootstrap.Continue, outcome)

	resource, err := h.DB.GetResourceByResourceIdentifier(ctx, nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, resource)
	permissions, err := h.DB.GetPermissionsByResourceId(ctx, nil, resource.Id)
	require.NoError(t, err)
	descriptions := map[string]string{}
	for _, p := range permissions {
		descriptions[p.PermissionIdentifier] = p.Description
	}
	assert.Equalf(t, boundaryDescriptions000058, descriptions,
		"the seed must write the built-in permissions with the descriptions that state the boundary on %s", dbType())
	for identifier, description := range descriptions {
		assert.LessOrEqualf(t, len(description), 100,
			"%s's description must fit the API's 100-character limit, so the console can save it back unchanged", identifier)
	}
}

var errSeedFault = errors.New("injected seed failure")

// seedFaultDB fails the seed on a real engine at the two points that matter to #424 decision 14:
// after the settings insert has executed, which draws the settings row's id from the engine's
// counter, and at the commit, after all eighteen writes have run. The commit is failed by
// cancelling the transaction's context once the body has returned, which database/sql answers by
// rolling back.
type seedFaultDB struct {
	data.Database
	failAfterSettings bool
	failCommit        bool
}

func (f *seedFaultDB) CreateInitialSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error {
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

			outcome, err := bootstrap.Run(ctx, &faults, dataCipher, seedConfig("admin@example.com"))

			require.Error(t, err)
			assert.Equal(t, bootstrap.Refused, outcome)
			isEmpty, err := h.DB.IsEmpty(ctx)
			require.NoError(t, err)
			assert.True(t, isEmpty, "the failed seed left the database empty")
			assert.Equal(t, before, seededRowCounts(t, h), "and every one of its writes was rolled back")

			outcome, err = bootstrap.Run(ctx, h.DB, dataCipher, seedConfig("admin@example.com"))

			require.NoError(t, err, "the next start seeds")
			assert.Equal(t, bootstrap.Continue, outcome)
			settings, err := h.DB.GetSettingsById(ctx, nil, 1)
			require.NoError(t, err)
			require.NotNil(t, settings, "the reseed's settings row is at id 1, whatever the failed attempt drew")
			isEmpty, err = h.DB.IsEmpty(ctx)
			require.NoError(t, err)
			assert.False(t, isEmpty)
			client, err := h.DB.GetClientByClientIdentifier(ctx, nil, builtin.AdminConsoleClientIdentifier)
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

// TestSeed_SeveralStartsOnOneEmptyDatabaseAllCarryOn is several replicas starting at once on an
// empty database, on every engine (#542 decision 2). Each finds it empty and seeds; one seed
// commits, and every other loses its first insert on the admin console client's unique key, which
// each engine reports its own way and the data layer answers as ErrUniqueViolation. Each loser
// rolls back whole and carries on with the database the winner seeded, where it used to exit 1 on
// the duplicate key and be restarted to find just that.
//
// The starts are held together after their emptiness checks, so every one of them seeds: left to
// themselves, a start arriving after the winner's commit would read the database as seeded and
// carry on without racing at all, and the test would pass with the race unhandled.
func TestSeed_SeveralStartsOnOneEmptyDatabaseAllCarryOn(t *testing.T) {
	h := migratedIsolatedDB(t)
	const starts = 3

	var together sync.WaitGroup
	together.Add(starts)
	outcomes := make([]bootstrap.Outcome, starts)
	failures := make([]error, starts)
	var done sync.WaitGroup
	for i := range starts {
		done.Go(func() {
			db := &checkEmptinessTogether{Database: h.DB, together: &together}
			outcomes[i], failures[i] = bootstrap.Run(context.Background(), db, dataCipher, seedConfig("admin@example.com"))
		})
	}
	done.Wait()

	for i := range starts {
		require.NoErrorf(t, failures[i], "start %d carries on, whichever of them seeded", i)
		assert.Equalf(t, bootstrap.Continue, outcomes[i], "start %d", i)
	}
	counts := seededRowCounts(t, h)
	assert.Equal(t, 1, counts["clients"], "one seed committed, and only one")
	assert.Equal(t, 1, counts["users"])
	assert.Equal(t, 1, counts["settings"])
	assert.Equal(t, 2, counts["key_pairs"])
}

// checkEmptinessTogether holds each start after its first emptiness check until every start has
// made one, which is the moment several replicas starting together all pass.
type checkEmptinessTogether struct {
	data.Database
	together *sync.WaitGroup
	once     sync.Once
}

func (c *checkEmptinessTogether) IsEmpty(ctx context.Context) (bool, error) {
	isEmpty, err := c.Database.IsEmpty(ctx)
	c.once.Do(func() {
		c.together.Done()
		c.together.Wait()
	})
	return isEmpty, err
}

// TestFirstStart_SeveralReplicasOnOneEmptyDatabaseAllComeUp is a whole first start as main makes
// it up to the listener, NewDatabase and then the seed, made by three replicas at once on one empty
// database (#542 decision 2). Every one comes up: one migrates while the others wait for the
// migration lock and then find nothing to migrate, the email case pre-flight runs under that lock
// and never reads a schema part way up, and the seeds race as the case above has them race.
//
// The migration half is not forced the way the seed is: whether a waiting start would have read the
// schema mid-chain before the pre-flight moved under the lock depends on timing, and the migrator's
// own tests are where that is proved deterministically. This is the composition, on the engines that
// have replicas.
func TestFirstStart_SeveralReplicasOnOneEmptyDatabaseAllComeUp(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("a SQLite database belongs to one process; replicas need a server engine")
	}
	h := newIsolatedDB(t)
	cfg := appConfig.Database
	cfg.Name = h.Name
	const starts = 3

	var together sync.WaitGroup
	together.Add(starts)
	outcomes := make([]bootstrap.Outcome, starts)
	failures := make([]error, starts)
	var done sync.WaitGroup
	for i := range starts {
		done.Go(func() {
			opened, err := datafactory.NewDatabase(context.Background(), &cfg, dataKey, nil, false)
			if err != nil {
				failures[i] = err
				together.Done()
				return
			}
			defer func() { _ = opened.Close() }()
			db := &checkEmptinessTogether{Database: opened, together: &together}
			outcomes[i], failures[i] = bootstrap.Run(context.Background(), db, dataCipher, seedConfig("admin@example.com"))
		})
	}
	done.Wait()

	for i := range starts {
		require.NoErrorf(t, failures[i], "replica %d comes up", i)
		assert.Equalf(t, bootstrap.Continue, outcomes[i], "replica %d", i)
	}
	version, dirty, err := h.Migrator.Version(context.Background())
	require.NoError(t, err)
	assert.Equal(t, h.Migrator.Head(), version, "the schema is at head")
	assert.False(t, dirty)
	counts := seededRowCounts(t, h)
	assert.Equal(t, 1, counts["clients"], "one seed committed, and only one")
	assert.Equal(t, 1, counts["settings"])
}
