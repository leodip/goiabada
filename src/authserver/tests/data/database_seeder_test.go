package datatests

import (
	"errors"
	"testing"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/leodip/goiabada/core/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	h := newIsolatedDB(t)
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding")
	}

	const givenEmail = "Admin@Example.com"
	const wantEmail = "admin@example.com"

	seeder := data.NewDatabaseSeeder(h.DB, givenEmail, "SeedTest_p4ssword!", "Goiabada",
		"https://localhost:8080", "https://localhost:8081")
	require.NoError(t, seeder.Seed(), "seed a fresh deployment with a mixed-case admin address")

	user, err := h.DB.GetUserByEmail(nil, wantEmail)
	require.NoError(t, err, "look the admin up the way both credential paths do")
	require.NotNilf(t, user,
		"the seeded admin must be reachable by the lowercased address: that is the only spelling the password form and the ROPC grant ever ask for")

	assert.Equalf(t, wantEmail, user.Email,
		"the seeder must store %q lowercased. Storing %q verbatim is what locks the admin out on the two engines that compare exactly, and it is invisible on the two that fold",
		givenEmail, givenEmail)
}
