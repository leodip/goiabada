package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000088 sits between. Literals: nothing in production code names this
// number.
const (
	beforeCodeDPoPJkt000088 = 87
	codeDPoPJkt000088       = 88
)

// Migration 000088 (#42 decision 14) adds codes.dpop_jkt, the thumbprint of the DPoP key an
// authorization request bound its code to with dpop_jkt, on all four engines. This holds it to the
// claims its comments make, against an ISOLATED database of the configured dialect (see
// migration_testdb_helper_test.go):
//
//   - the column is absent at 000087, so what is found afterwards is what 000088 added;
//   - it is a 64-wide string, pinned case-sensitive, NULLABLE with no default: NULL is a code bound
//     to no key, which every existing code is;
//   - a code written before the migration reads NULL, so no existing code is bound;
//   - nothing else in codes changes, and the down migration drops the column, round trip included.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000088_CodeDPoPJkt
func TestMigration000088_CodeDPoPJkt(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, beforeCodeDPoPJkt000088), "migrate to 87")
	before := dumpTable(t, h, "codes")
	_, found := schemadump.TableShape(before).Column("dpop_jkt")
	require.False(t, found, "codes.dpop_jkt must not exist at 000087")
	codeHash := seedPreMigration000088Code(t, h)

	require.NoError(t, h.Migrator.Migrate(ctx, codeDPoPJkt000088), "apply 000088")
	assertCodeDPoPJktShape000088(t, h, before, "after apply")
	assertSeededCodeUnbound000088(t, h, codeHash, "after apply")

	require.NoError(t, h.Migrator.Migrate(ctx, beforeCodeDPoPJkt000088), "roll back to 87")
	assert.Equal(t, before, dumpTable(t, h, "codes"), "the down migration must drop dpop_jkt and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, codeDPoPJkt000088), "apply 000088 again")
	assertCodeDPoPJktShape000088(t, h, before, "after down then up")
	assertSeededCodeUnbound000088(t, h, codeHash, "after down then up")
}

func assertCodeDPoPJktShape000088(t *testing.T, h *isolatedDB, before tableShape, when string) {
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

	after := dumpTable(t, h, "codes")
	jkt := after.column(t, "dpop_jkt")
	assert.Equalf(t, jktType[engine], jkt.Type, "dpop_jkt's type %s", when)
	assert.Truef(t, jkt.Nullable, "dpop_jkt is nullable: NULL is a code bound to no key %s", when)
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

// seedPreMigration000088Code inserts a code as a release before 000088 wrote it, in SQL rather than
// through the ORM, whose record follows the head schema. The values are test-controlled literals,
// but for authenticated_at, bound, since the four dialects disagree on a timestamp literal.
func seedPreMigration000088Code(t *testing.T, h *isolatedDB) string {
	t.Helper()
	random := fake.LetterN(6)

	clientId := seedClient(t, h, "mig88_client_"+random)
	userId := seedUser(t, h, userSeed{Enabled: true, Subject: fake.UUID(), Username: "mig88_" + random})

	falseLit, _ := boolLiterals000031()
	codeHash := "mig88_hash_" + random
	_, err := h.SQL.Exec(fmt.Sprintf(`INSERT INTO codes
		(code_hash, client_id, scope, state, nonce, redirect_uri, user_id, ip_address, user_agent,
		 response_mode, authenticated_at, session_identifier, acr_level, auth_methods, used)
		VALUES ('%s', %d, 'openid', 'state', 'nonce', 'https://example.com/cb', %d, '192.0.2.1', 'probe',
		        'query', %s, 'session', 'urn:goiabada:level1', 'pwd', %s)`,
		codeHash, clientId, userId, seedBindAt(1), falseLit),
		time.Now().UTC().Truncate(time.Second))
	require.NoError(t, err, "seed a pre-000088 code")
	return codeHash
}

// assertSeededCodeUnbound000088 reads the seeded row back in SQL, so NULL is shown to arrive as a
// code bound to no key. Not through the data layer, whose statements follow the head schema and
// would name any column a later migration adds.
func assertSeededCodeUnbound000088(t *testing.T, h *isolatedDB, codeHash string, when string) {
	t.Helper()
	var binding sql.NullString
	var scope string
	err := h.SQL.QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT dpop_jkt, scope FROM codes WHERE code_hash = '%s'", codeHash)).
		Scan(&binding, &scope)
	require.NoErrorf(t, err, "read the seeded code %s", when)
	assert.Falsef(t, binding.Valid, "a code from before 000088 is bound to no key %s, read %v", when, binding)
	assert.Equalf(t, "openid", scope, "the rest of the row survives %s", when)
}
