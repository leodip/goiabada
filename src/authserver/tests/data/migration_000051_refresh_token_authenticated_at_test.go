package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000051_RefreshTokenAuthenticatedAt exercises the migration that records an ROPC
// grant's authentication instant on its refresh tokens (#125). It runs against an ISOLATED
// database of the configured dialect (see migration_testdb_helper_test.go).
//
// The properties, in the order they appear below:
//
//  1. The column is absent at 000050, so what is found afterwards is what 000051 added.
//  2. It is present and NULLABLE afterwards. NULL is what every authorization-code token carries,
//     since its instant is on its code, and what every ROPC token issued before the migration
//     carries, which the token endpoint then refuses to refresh.
//  3. An ROPC refresh token seeded BEFORE the migration reads NULL, which is the refusal's premise
//     proved on the engine: nothing backfills it, because the family's first row, whose issued_at
//     was the instant, is reaped 30 days after issue by default while the family lives on.
//  4. The down drops the column and a down-then-up round trip lands back at 2 and 3.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000051_RefreshTokenAuthenticatedAt
func TestMigration000051_RefreshTokenAuthenticatedAt(t *testing.T) {
	h := newIsolatedDB(t)
	ctx := context.Background()

	require.NoError(t, h.Migrator.Migrate(ctx, 50), "migrate to 000050")

	// 1.
	exists, _, _ := columnShape000031(t, h, "refresh_tokens", "authenticated_at")
	require.False(t, exists, "refresh_tokens.authenticated_at must not exist at 000050")

	jti := seedPreMigration000051ROPCRefreshToken(t, h)

	require.NoError(t, h.Migrator.Migrate(ctx, 51), "apply 000051")

	// 2 and 3.
	assertAuthenticatedAtShape000051(t, h, "after apply")
	assertSeededTokenHasNoInstant000051(t, h, jti, "after apply")

	// 4.
	require.NoError(t, h.Migrator.Migrate(ctx, 50), "roll back 000051")
	exists, _, _ = columnShape000031(t, h, "refresh_tokens", "authenticated_at")
	assert.False(t, exists, "the down migration must drop refresh_tokens.authenticated_at")

	require.NoError(t, h.Migrator.Migrate(ctx, 51), "re-apply 000051")
	assertAuthenticatedAtShape000051(t, h, "after down/up round trip")
	assertSeededTokenHasNoInstant000051(t, h, jti, "after down/up round trip")
}

// seedPreMigration000051ROPCRefreshToken inserts an ROPC refresh token as a release before 000051
// wrote it: user_id and client_id set, no code. The client and the user go through the ORM, whose
// models match the 000050 schema for both tables; the token row is literal SQL, because the Go
// model already names authenticated_at. Literals rather than placeholders because the four
// dialects disagree on placeholder syntax, and every value here is test-controlled.
func seedPreMigration000051ROPCRefreshToken(t *testing.T, h *isolatedDB) string {
	t.Helper()
	random := fake.LetterN(6)

	client := &record.Client{ClientIdentifier: "mig51_client_" + random, Description: "Migration 000051 test client"}
	require.NoError(t, h.DB.CreateClient(context.Background(), nil, client), "seed client")
	user := &record.User{Enabled: true, Subject: fake.UUID(), Username: "mig51_" + random}
	require.NoError(t, h.DB.CreateUser(context.Background(), nil, user), "seed user")

	falseLit, _ := boolLiterals000031()
	jti := fake.UUID()
	q := fmt.Sprintf(`INSERT INTO refresh_tokens
		(user_id, client_id, refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti,
		 session_identifier, refresh_token_type, scope, revoked)
		VALUES (%d, %d, '%s', '', '%s', '', 'Offline', 'openid', %s)`,
		user.Id, client.Id, jti, jti, falseLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed a pre-000051 ROPC refresh token")
	return jti
}

func assertAuthenticatedAtShape000051(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	exists, notNull, _ := columnShape000031(t, h, "refresh_tokens", "authenticated_at")
	require.Truef(t, exists, "[%s] refresh_tokens.authenticated_at must exist", phase)
	assert.Falsef(t, notNull, "[%s] refresh_tokens.authenticated_at must be nullable: every "+
		"authorization-code token and every pre-000051 ROPC token carries NULL", phase)
}

// assertSeededTokenHasNoInstant000051 reads the seeded row back through the data layer the token
// endpoint uses, so NULL is shown to arrive as an invalid sql.NullTime, which is what the refusal
// tests, and the rest of the row as it was written.
func assertSeededTokenHasNoInstant000051(t *testing.T, h *isolatedDB, jti string, phase string) {
	t.Helper()
	token, err := h.DB.GetRefreshTokenByJti(context.Background(), nil, jti)
	require.NoErrorf(t, err, "[%s] read the seeded refresh token", phase)
	require.NotNilf(t, token, "[%s] the seeded refresh token is gone", phase)
	assert.Falsef(t, token.AuthenticatedAt.Valid, "[%s] a pre-000051 token must read no instant, got %v",
		phase, token.AuthenticatedAt)
	assert.Truef(t, token.UserId.Valid, "[%s] the rest of the row must survive", phase)
	assert.Equalf(t, "Offline", token.RefreshTokenType, "[%s] the rest of the row must survive", phase)
}
