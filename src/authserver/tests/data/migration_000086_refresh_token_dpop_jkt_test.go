package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000086 sits between. Literals: nothing in production code names this
// number.
const (
	beforeRefreshTokenDPoPJkt000086 = 85
	refreshTokenDPoPJkt000086       = 86
)

// Migration 000086 (#42 decision 11) adds refresh_tokens.dpop_jkt, the thumbprint of the DPoP key a
// public client's refresh-token family is bound to, on all four engines. This holds it to the claims
// its comments make, against an ISOLATED database of the configured dialect (see
// migration_testdb_helper_test.go):
//
//   - the column is absent at 000085, so what is found afterwards is what 000086 added;
//   - it is a 64-wide string, pinned case-sensitive, NULLABLE with no default: NULL is an unbound
//     family, which every existing row is;
//   - a refresh token written before the migration reads NULL, so no existing token is bound;
//   - nothing else in refresh_tokens changes, and the down migration drops the column, round trip
//     included.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000086_RefreshTokenDPoPJkt
func TestMigration000086_RefreshTokenDPoPJkt(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, beforeRefreshTokenDPoPJkt000086), "migrate to 85")
	before := dumpTable(t, h, "refresh_tokens")
	_, found := schemadump.TableShape(before).Column("dpop_jkt")
	require.False(t, found, "refresh_tokens.dpop_jkt must not exist at 000085")
	jti := seedPreMigration000086RefreshToken(t, h)

	require.NoError(t, h.Migrator.Migrate(ctx, refreshTokenDPoPJkt000086), "apply 000086")
	assertDPoPJktShape000086(t, h, before, "after apply")
	assertSeededTokenUnbound000086(t, h, jti, "after apply")

	require.NoError(t, h.Migrator.Migrate(ctx, beforeRefreshTokenDPoPJkt000086), "roll back to 85")
	assert.Equal(t, before, dumpTable(t, h, "refresh_tokens"), "the down migration must drop dpop_jkt and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, refreshTokenDPoPJkt000086), "apply 000086 again")
	assertDPoPJktShape000086(t, h, before, "after down then up")
	assertSeededTokenUnbound000086(t, h, jti, "after down then up")
}

func assertDPoPJktShape000086(t *testing.T, h *isolatedDB, before tableShape, when string) {
	t.Helper()

	stringCollation := map[data.Dialect]string{
		data.MySQL:    "utf8mb4_0900_as_cs",
		data.MSSQL:    "Latin1_General_100_CS_AS_KS_WS_SC_UTF8",
		data.Postgres: "default",
		data.SQLite:   "BINARY",
	}
	jktType := map[data.Dialect]string{
		data.MySQL: "varchar(64)", data.Postgres: "character varying(64)", data.MSSQL: "nvarchar(64)", data.SQLite: "TEXT",
	}
	engine := dbType()

	after := dumpTable(t, h, "refresh_tokens")
	jkt := after.column(t, "dpop_jkt")
	assert.Equalf(t, jktType[engine], jkt.Type, "dpop_jkt's type %s", when)
	assert.Truef(t, jkt.Nullable, "dpop_jkt is nullable: NULL is an unbound family %s", when)
	assert.Falsef(t, jkt.HasDefault, "dpop_jkt has no default %s", when)
	assert.Equalf(t, stringCollation[engine], jkt.Collation, "dpop_jkt's effective collation is the case-sensitive one %s", when)

	var others []columnShape
	for _, c := range after.Columns {
		if c.Name != "dpop_jkt" {
			others = append(others, c)
		}
	}
	assert.Equalf(t, before.Columns, others, "every other column is as it was %s", when)
	assert.Equalf(t, before.Indexes, after.Indexes, "the indexes are as they were %s", when)
	assert.Equalf(t, before.ForeignKeys, after.ForeignKeys, "the foreign keys are as they were %s", when)
}

// seedPreMigration000086RefreshToken inserts an ROPC refresh token as a release before 000086 wrote
// it, in SQL rather than through the ORM, whose record follows the head schema. Literals rather
// than placeholders because the four dialects disagree on placeholder syntax, and every value here
// is test-controlled.
func seedPreMigration000086RefreshToken(t *testing.T, h *isolatedDB) string {
	t.Helper()
	random := fake.LetterN(6)

	clientId := seedClient(t, h, "mig86_client_"+random)
	userId := seedUser(t, h, userSeed{Enabled: true, Subject: fake.UUID(), Username: "mig86_" + random})

	falseLit, _ := boolLiterals000031()
	jti := fake.UUID()
	_, err := h.SQL.Exec(fmt.Sprintf(`INSERT INTO refresh_tokens
		(user_id, client_id, refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti,
		 session_identifier, refresh_token_type, scope, revoked)
		VALUES (%d, %d, '%s', '', '%s', '', 'Offline', 'openid', %s)`,
		userId, clientId, jti, jti, falseLit))
	require.NoError(t, err, "seed a pre-000086 refresh token")
	return jti
}

// assertSeededTokenUnbound000086 reads the seeded row back in SQL, so NULL is shown to arrive as an
// unbound family. Not through the data layer, whose statements follow the head schema and would
// name any column a later migration adds.
func assertSeededTokenUnbound000086(t *testing.T, h *isolatedDB, jti string, when string) {
	t.Helper()
	var binding sql.NullString
	var tokenType string
	err := h.SQL.QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT dpop_jkt, refresh_token_type FROM refresh_tokens WHERE refresh_token_jti = '%s'", jti)).
		Scan(&binding, &tokenType)
	require.NoErrorf(t, err, "read the seeded refresh token %s", when)
	assert.Falsef(t, binding.Valid, "a refresh token from before 000086 is unbound %s, read %v", when, binding)
	assert.Equalf(t, "Offline", tokenType, "the rest of the row survives %s", when)
}
