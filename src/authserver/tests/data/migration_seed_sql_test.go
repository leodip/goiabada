package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/require"
)

// The SQL seeds the per-migration tests share (#510). The repository's CRUD writes every column
// the current Go record declares, so it only fits the schema at head: the next migration that adds
// a column to users, groups, resources, permissions, one of the three grant tables, user_consents,
// user_session_clients, web_origins or clients would break every test that seeds one of those
// tables below head, on every engine, for a reason unrelated to the migration under test. #499 hit
// exactly that for clients; seedClient, which it wrote for that, lives here beside the rest.
//
// Each helper names only the columns every version it is used at carries, so a column a later
// migration adds is simply absent from the statement. Identifiers and descriptions the tests write
// are plain ASCII with no quote or backslash, inlined as engine-neutral literals, as in the
// h.SQL.Exec seeds of 000046 and 000055. Free text a fixture controls is bound through sqlbuilder
// instead: users, for 000048's and 000059's OTP ciphertext, which no literal can carry, and
// web_origins, whose fixtures carry a backslash, which MySQL's default sql_mode reads as an escape
// inside a literal. A write that is what its test tests -- 000039's codes, 000046's user_sessions,
// 000055's duplicate refusals -- keeps the ORM, with a comment saying so where it stands.

// userSeed is the users row a migration test needs: the NOT NULL columns every version from the
// oldest seed onwards carries, plus the OTP pair only 000048's and 000059's fixtures hold a value
// for. Empty fields are generated, the username and email derived from the subject, so two seeds
// in one database stay distinct on every unique key.
type userSeed struct {
	Enabled             bool
	Subject             string
	Username            string
	Email               string
	PasswordHash        string
	EmailVerified       bool
	PhoneNumberVerified bool
	OTPEnabled          bool
	// OTPSecretEncrypted is bound as bytes and its column named only when non-nil: no engine
	// shares a literal spelling for a blob, and only the two OTP migrations seed one.
	OTPSecretEncrypted []byte
}

// seedUser writes a users row and reads its id back by its subject. NOT NULL columns every seed
// version carries are named (created_at and updated_at are nullable and left to the engine);
// every other column -- the country pair, the verification codes, the address -- is nullable and
// none of the fixtures below head needs a value in one.
func seedUser(t *testing.T, h *isolatedDB, seed userSeed) int64 {
	t.Helper()

	if seed.Subject == "" {
		seed.Subject = fake.UUID()
	}
	if seed.Username == "" {
		seed.Username = "u-" + seed.Subject[:8]
	}
	// A distinct address rather than NULL: SQL Server's unique indexes treat two NULLs as
	// equal, and a fixture that seeds two users must not lose the second to idx_email there.
	if seed.Email == "" {
		seed.Email = seed.Subject + "@example.com"
	}
	if seed.PasswordHash == "" {
		seed.PasswordHash = "not-a-real-hash"
	}

	cols := []string{"enabled", "subject", "username", "email", "email_verified",
		"phone_number_verified", "password_hash", "otp_enabled",
		// The profile text columns every version carries, as empty strings rather than NULL:
		// GetUserById scans them into plain Go strings, which cannot hold SQL NULL, and the
		// ORM's insert used to leave exactly these non-NULL for the same reason.
		"given_name", "middle_name", "family_name", "nickname", "website", "gender", "locale",
		"zone_info_country_name", "zone_info", "phone_number", "address_line1", "address_line2",
		"address_locality", "address_region", "address_postal_code", "address_country",
		"phone_number_country_uniqueid", "phone_number_country_callingcode"}
	emptyStrings := make([]any, 18)
	for i := range emptyStrings {
		emptyStrings[i] = ""
	}
	values := append([]any{seed.Enabled, seed.Subject, seed.Username, seed.Email, seed.EmailVerified,
		seed.PhoneNumberVerified, seed.PasswordHash, seed.OTPEnabled}, emptyStrings...)
	if seed.OTPSecretEncrypted != nil {
		cols = append(cols, "otp_secret_encrypted")
		values = append(values, seed.OTPSecretEncrypted)
	}

	insert := sqlbuilder.NewInsertBuilder()
	insert.InsertInto("users").Cols(cols...).Values(values...)
	q, args := insert.BuildWithFlavor(seedFlavor())
	_, err := h.SQL.ExecContext(context.Background(), q, args...)
	require.NoError(t, err, "seed user %s", seed.Username)

	lookup := sqlbuilder.NewSelectBuilder()
	lookup.Select("id").From("users").Where(lookup.Equal("subject", seed.Subject))
	q, args = lookup.BuildWithFlavor(seedFlavor())
	var id int64
	require.NoError(t, h.SQL.QueryRowContext(context.Background(), q, args...).Scan(&id),
		"read back the seeded user id")
	return id
}

// seedFlavor is the configured engine's placeholder dialect, the one seedRefreshToken000039
// already binds its literal-hostile values with.
func seedFlavor() sqlbuilder.Flavor {
	switch dbType() {
	case data.MySQL:
		return sqlbuilder.MySQL
	case data.Postgres:
		return sqlbuilder.PostgreSQL
	case data.MSSQL:
		return sqlbuilder.SQLServer
	default:
		return sqlbuilder.SQLite
	}
}

// seedGroup writes a groups row with both include switches off, which is what the ORM wrote for
// the zero record every migration test seeds, and reads its id back by its identifier.
func seedGroup(t *testing.T, h *isolatedDB, identifier, description string) int64 {
	t.Helper()

	falseLit, _ := boolLiterals000031()
	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO %s (group_identifier, description, include_in_id_token, include_in_access_token) VALUES ('%s', '%s', %s, %s)",
		groupsTable(), identifier, description, falseLit, falseLit))
	require.NoError(t, err, "seed group %s", identifier)

	return seedIdByIdentifier(t, h, groupsTable(), "group_identifier", identifier)
}

// groupsTable is the groups table's name quoted per engine, because MySQL 8.0.2 made GROUPS a
// reserved word, so the bare name parses on three engines and fails on the fourth.
func groupsTable() string {
	switch dbType() {
	case data.MySQL:
		return "`groups`"
	case data.MSSQL:
		return "[groups]"
	default: // sqlite, postgres
		return `"groups"`
	}
}

// seedClient inserts a client with client_credentials_enabled off and reads its id back by an
// exact match on its identifier, which 000040 relies on to seed a case-variant pair. Every NOT
// NULL column without a default is named, so the insert does not depend on per-engine defaults
// agreeing.
func seedClient(t *testing.T, h *isolatedDB, identifier string) int64 {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()

	_, err := h.SQL.Exec(fmt.Sprintf(`INSERT INTO clients
		(client_identifier, enabled, consent_required, is_public, authorization_code_enabled,
		 client_credentials_enabled, token_expiration_in_seconds,
		 refresh_token_offline_idle_timeout_in_seconds, refresh_token_offline_max_lifetime_in_seconds,
		 include_open_id_connect_claims_in_access_token, default_acr_level)
		VALUES ('%s', %s, %s, %s, %s, %s, 300, 2592000, 5184000,
		        'default', 'urn:goiabada:level2_optional')`,
		identifier, trueLit, falseLit, falseLit, trueLit, falseLit))
	require.NoErrorf(t, err, "seed the %s client", identifier)

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT id FROM clients WHERE client_identifier = '%s'`, identifier)).Scan(&id),
		"read back the seeded client id")
	return id
}

// seedResource writes a resources row and reads its id back by its identifier.
func seedResource(t *testing.T, h *isolatedDB, identifier, description string) int64 {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO resources (resource_identifier, description) VALUES ('%s', '%s')", identifier, description))
	require.NoError(t, err, "seed resource %s", identifier)

	return seedIdByIdentifier(t, h, "resources", "resource_identifier", identifier)
}

// seedPermission writes a permissions row and reads its id back by identifier and resource.
func seedPermission(t *testing.T, h *isolatedDB, resourceId int64, identifier, description string) int64 {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO permissions (permission_identifier, description, resource_id) VALUES ('%s', '%s', %d)",
		identifier, description, resourceId))
	require.NoError(t, err, "seed the %s permission", identifier)

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT id FROM permissions WHERE permission_identifier = '%s' AND resource_id = %d", identifier, resourceId)).Scan(&id),
		"read back the seeded %s permission id", identifier)
	return id
}

// seedUserPermission, seedGroupPermission and seedClientPermission write one grant row each. No id
// back: no fixture reads a grant by it, and the tables carry no identifier to look one up by.
func seedUserPermission(t *testing.T, h *isolatedDB, userId, permissionId int64) {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO users_permissions (user_id, permission_id) VALUES (%d, %d)", userId, permissionId))
	require.NoError(t, err, "seed the user permission grant")
}

func seedGroupPermission(t *testing.T, h *isolatedDB, groupId, permissionId int64) {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO groups_permissions (group_id, permission_id) VALUES (%d, %d)", groupId, permissionId))
	require.NoError(t, err, "seed the group permission grant")
}

func seedClientPermission(t *testing.T, h *isolatedDB, clientId, permissionId int64) {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO clients_permissions (client_id, permission_id) VALUES (%d, %d)", clientId, permissionId))
	require.NoError(t, err, "seed the client permission grant")
}

// seedUserConsent writes a consent row below 000055, which has no key to refuse a second, and
// answers its id. The id is the MAXIMUM of the pair's rows rather than a lookup, because the
// absence of that key is this migration's subject: the row just written is the newest the pair
// holds, on every engine's auto-increment.
func seedUserConsent(t *testing.T, h *isolatedDB, userId, clientId int64, scope string) int64 {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO user_consents (user_id, client_id, scope, granted_at) VALUES (%d, %d, '%s', CURRENT_TIMESTAMP)",
		userId, clientId, scope))
	require.NoError(t, err, "seed a consent while no key refuses a second")

	return seedMaxId(t, h, "user_consents", fmt.Sprintf("user_id = %d AND client_id = %d", userId, clientId))
}

// seedUserSessionClient writes an association below 000055 and answers its id, for the same
// reason seedUserConsent reads a MAXIMUM back: started and last_accessed are NOT NULL but nothing
// asserts their values, so CURRENT_TIMESTAMP serves on every engine.
func seedUserSessionClient(t *testing.T, h *isolatedDB, sessionId, clientId int64) int64 {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO user_session_clients (user_session_id, client_id, started, last_accessed) VALUES (%d, %d, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
		sessionId, clientId))
	require.NoError(t, err, "seed an association while no key refuses a second")

	return seedMaxId(t, h, "user_session_clients", fmt.Sprintf("user_session_id = %d AND client_id = %d", sessionId, clientId))
}

// seedWebOrigin writes the origin verbatim and answers its id. Both statements bind the origin
// rather than inline it, because 000034's fixtures carry a backslash, which MySQL's default
// sql_mode reads as an escape inside a literal: inlined, MySQL stored a different origin than the
// fixture names. Bound, the row holds what the data layer's own write would -- the validation
// 000034 exists to backfill has only ever lived in the API handler.
func seedWebOrigin(t *testing.T, h *isolatedDB, clientId int64, origin string) int64 {
	t.Helper()

	insert := sqlbuilder.NewInsertBuilder()
	insert.InsertInto("web_origins").Cols("origin", "client_id").Values(origin, clientId)
	q, args := insert.BuildWithFlavor(seedFlavor())
	_, err := h.SQL.ExecContext(context.Background(), q, args...)
	require.NoError(t, err, "seed web origin %s", origin)

	lookup := sqlbuilder.NewSelectBuilder()
	lookup.Select("id").From("web_origins").Where(
		lookup.Equal("origin", origin), lookup.Equal("client_id", clientId))
	q, args = lookup.BuildWithFlavor(seedFlavor())
	var id int64
	require.NoError(t, h.SQL.QueryRowContext(context.Background(), q, args...).Scan(&id),
		"read back the seeded web origin id")
	return id
}

// seedIdByIdentifier reads the one row a fresh identifier has back.
func seedIdByIdentifier(t *testing.T, h *isolatedDB, table, column, identifier string) int64 {
	t.Helper()

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT id FROM %s WHERE %s = '%s'", table, column, identifier)).Scan(&id),
		"read back the seeded %s id", identifier)
	return id
}

// seedMaxId reads the newest row a predicate matches, which a seed that just inserted it is.
func seedMaxId(t *testing.T, h *isolatedDB, table, predicate string) int64 {
	t.Helper()

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT MAX(id) FROM %s WHERE %s", table, predicate)).Scan(&id),
		"read back the seeded %s id", table)
	return id
}

// assertUniqueRefusal holds a raw SQL refusal to its cause: the unique key the engine reports, in
// the engine's own spelling -- SQLite a column list, the other three the key's name -- so an
// insert refused for a different reason fails here rather than passing (#510). The two callers
// write duplicates of rows their fixture already holds, on indexes their migration created.
func assertUniqueRefusal(t *testing.T, err error, sqliteColumns, keyName string, msg string) {
	t.Helper()

	require.Error(t, err, msg)
	reported := keyName
	if dbType() == data.SQLite {
		reported = "UNIQUE constraint failed: " + sqliteColumns
	}
	require.ErrorContainsf(t, err, reported, "%s: the refusal must be the unique key, not another fault", msg)
}
