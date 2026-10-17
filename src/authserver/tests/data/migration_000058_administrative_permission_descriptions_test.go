package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// describeAdministrativeBoundary000058 is the version of the migration that rewrites the seeded
// descriptions of four administrative permissions so they state what each can and cannot do (#402
// decision 3).
const describeAdministrativeBoundary000058 = 58

// seededDescriptions000058 is what an installation seeded before #402 carries on the authserver
// resource: the seed's own wording, and 000012's for the four granular scopes.
var seededDescriptions000058 = map[string]string{
	builtin.ManageAccountPermissionIdentifier:   "View and update user account data for the current user",
	builtin.ManagePermissionIdentifier:          "Manage the authorization server via the admin console",
	builtin.AdminReadPermissionIdentifier:       "Read-only access to all admin API endpoints",
	builtin.ManageUsersPermissionIdentifier:     "Manage users, groups, and permissions",
	builtin.ManageClientsPermissionIdentifier:   "Manage OAuth2 clients",
	builtin.ManageSettingsPermissionIdentifier:  "Manage system settings and signing keys",
	builtin.BrowserSessionsPermissionIdentifier: "Read and write admin console browser sessions",
}

// boundaryDescriptions000058 is the same resource after 000058: the wording #402 decision 3 sets
// for manage, manage-users, manage-clients and manage-settings, and the other three as they were.
var boundaryDescriptions000058 = map[string]string{
	builtin.ManageAccountPermissionIdentifier:   "View and update user account data for the current user",
	builtin.ManagePermissionIdentifier:          "Full administration, including administrators and administrative permissions",
	builtin.AdminReadPermissionIdentifier:       "Read-only access to all admin API endpoints",
	builtin.ManageUsersPermissionIdentifier:     "Manage users and groups that are not administrators, and their non-administrative permissions",
	builtin.ManageClientsPermissionIdentifier:   "Manage OAuth2 clients that are not administrators",
	builtin.ManageSettingsPermissionIdentifier:  "Manage system settings, except email and audit logging, and signing keys",
	builtin.BrowserSessionsPermissionIdentifier: "Read and write admin console browser sessions",
}

// descriptionsFixture000058 is a database at 000057 holding the authserver resource with its seven
// built-in permissions, and a second resource whose own permissions share four of those identifiers
// and their seeded wording, which 000058 must not touch: it rewrites the authserver resource's rows
// and no other.
type descriptionsFixture000058 struct {
	h          *isolatedDB
	authserver *record.Resource
	other      *record.Resource
}

// seedDescriptionsFixture000058 migrates a fresh database to 000057 and writes the authserver
// resource's seven permissions with the descriptions given, and the other resource's four with
// the seeded wording.
func seedDescriptionsFixture000058(t *testing.T, h *isolatedDB, authserverDescriptions map[string]string) *descriptionsFixture000058 {
	t.Helper()
	ctx := context.Background()
	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058-1), "migrate an empty database up to %d on %s",
		describeAdministrativeBoundary000058-1, dbType())

	f := &descriptionsFixture000058{h: h}
	// Seeded through the shared SQL seeds rather than the ORM: the database is at 000057, the
	// records follow the head schema, and the next column any migration adds to resources or
	// permissions would break the seeding for a reason this migration does not own (#510).
	f.authserver = &record.Resource{
		Id:                 seedResource(t, h, builtin.AuthServerResourceIdentifier, "Authorization server (system-level)"),
		ResourceIdentifier: builtin.AuthServerResourceIdentifier,
	}
	for identifier, description := range authserverDescriptions {
		seedPermission(t, h, f.authserver.Id, identifier, description)
	}

	f.other = &record.Resource{
		Id:                 seedResource(t, h, "mig58-other", "Migration 000058 test resource"),
		ResourceIdentifier: "mig58-other",
	}
	for identifier, description := range f.otherDescriptions() {
		seedPermission(t, h, f.other.Id, identifier, description)
	}

	require.Equal(t, authserverDescriptions, f.descriptions(t, f.authserver), "the fixture: the authserver resource as written")
	require.Equal(t, f.otherDescriptions(), f.descriptions(t, f.other), "the fixture: the other resource as written")
	return f
}

// otherDescriptions is the other resource's four permissions: the identifiers 000058 rewrites, each
// with the wording it rewrites on the authserver resource.
func (f *descriptionsFixture000058) otherDescriptions() map[string]string {
	out := map[string]string{}
	for _, identifier := range []string{
		builtin.ManagePermissionIdentifier,
		builtin.ManageUsersPermissionIdentifier,
		builtin.ManageClientsPermissionIdentifier,
		builtin.ManageSettingsPermissionIdentifier,
	} {
		out[identifier] = seededDescriptions000058[identifier]
	}
	return out
}

// descriptions reads a resource's permissions as identifier to description. Read in SQL rather
// than through GetPermissionsByResourceId, for the seeds' reason: the read runs below head, and the
// ORM's SELECT names every column the record declares, so the next column any migration adds to
// permissions would fail it for a reason this migration does not own (#510).
func (f *descriptionsFixture000058) descriptions(t *testing.T, resource *record.Resource) map[string]string {
	t.Helper()
	rows, err := f.h.SQL.QueryContext(context.Background(), fmt.Sprintf(
		"SELECT permission_identifier, description FROM permissions WHERE resource_id = %d", resource.Id))
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var identifier, description string
		require.NoError(t, rows.Scan(&identifier, &description))
		out[identifier] = description
	}
	require.NoError(t, rows.Err())
	return out
}

// TestMigration000058_RewritesTheSeededDescriptions exercises the migration against a REAL engine
// of the configured dialect, over an installation that still carries every seeded description.
//
// The properties, in order:
//
//  1. Up rewrites manage, manage-users, manage-clients and manage-settings on the authserver
//     resource to decision 3's wording, leaves admin-read, manage-account and browser-sessions as
//     they were, and leaves another resource's permissions of the same identifiers and wording
//     alone.
//  2. Down puts the seeded wording back where 000058's wording remains.
//  3. Up again rewrites them again, which is what an operator who rolled back and retried does.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000058
func TestMigration000058_RewritesTheSeededDescriptions(t *testing.T) {
	h := newIsolatedDB(t)
	ctx := context.Background()
	f := seedDescriptionsFixture000058(t, h, seededDescriptions000058)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058), "apply 000058 on %s", dbType())
	assert.Equalf(t, boundaryDescriptions000058, f.descriptions(t, f.authserver),
		"000058 must rewrite the four seeded descriptions it names on the authserver resource, and no other, on %s", dbType())
	assert.Equalf(t, f.otherDescriptions(), f.descriptions(t, f.other),
		"000058 must rewrite the authserver resource's permissions only, on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058-1), "roll back 000058 on %s", dbType())
	assert.Equalf(t, seededDescriptions000058, f.descriptions(t, f.authserver),
		"000058's down must restore the seeded wording on %s", dbType())
	assert.Equalf(t, f.otherDescriptions(), f.descriptions(t, f.other),
		"000058's down must touch the authserver resource's permissions only, on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058), "re-apply 000058 on %s", dbType())
	assert.Equalf(t, boundaryDescriptions000058, f.descriptions(t, f.authserver),
		"000058 must be re-appliable after a down/up round trip on %s", dbType())
}

// TestMigration000058_KeepsAnOperatorsOwnWording holds the migration to its predicate: a description
// an operator has edited is theirs, and neither direction overwrites it. Every one of the seven rows
// carries an edit, each a near miss of the wording a direction looks for (a different case, a
// trailing word), so a predicate that matched on the identifier alone, or loosely on the text, is
// seen on every row it would rewrite.
func TestMigration000058_KeepsAnOperatorsOwnWording(t *testing.T) {
	h := newIsolatedDB(t)
	ctx := context.Background()

	edited := map[string]string{}
	for identifier, description := range seededDescriptions000058 {
		edited[identifier] = description + " (edited)"
	}
	edited[builtin.ManageUsersPermissionIdentifier] = "manage users, groups, and permissions"
	f := seedDescriptionsFixture000058(t, h, edited)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058), "apply 000058 on %s", dbType())
	assert.Equalf(t, edited, f.descriptions(t, f.authserver),
		"000058 must keep every description an operator has edited on %s", dbType())

	// The down is held the same way: a row an operator edited after 000058 keeps their wording.
	afterUp := map[string]string{}
	for identifier, description := range boundaryDescriptions000058 {
		afterUp[identifier] = description + " (edited)"
	}
	for identifier, description := range afterUp {
		// Written in SQL rather than through UpdatePermission: the write happens at 000058,
		// the record follows the head schema, and the next column any migration adds to
		// permissions would break it (#510). The description is all the edit is of.
		_, err := f.h.SQL.ExecContext(ctx, fmt.Sprintf(
			"UPDATE permissions SET description = '%s' WHERE permission_identifier = '%s' AND resource_id = %d",
			description, identifier, f.authserver.Id))
		require.NoErrorf(t, err, "write the operator's edit of %s", identifier)
	}
	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058-1), "roll back 000058 on %s", dbType())
	assert.Equalf(t, afterUp, f.descriptions(t, f.authserver),
		"000058's down must keep every description an operator has edited on %s", dbType())
}

// TestMigration000058_AnEmptyDatabase holds both directions to a database with no authserver
// resource, which is every fresh installation before the seed runs: neither has a row to rewrite,
// and neither may fail.
func TestMigration000058_AnEmptyDatabase(t *testing.T) {
	h := newIsolatedDB(t)
	ctx := context.Background()

	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058), "migrate an empty database through 000058 on %s", dbType())
	require.NoErrorf(t, h.Migrator.Migrate(ctx, describeAdministrativeBoundary000058-1), "roll back 000058 on an empty database on %s", dbType())
}
