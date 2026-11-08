package datatests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000085 sits between. Literals: nothing in production code names this
// number.
const (
	beforeDPoPProofs000085 = 84
	dpopProofs000085       = 85
)

// Migration 000085 (#42 decision 9) creates dpop_proofs, the replay store, on all four engines. This
// holds the migration to the claims its comments make, against an ISOLATED database of the
// configured dialect (see migration_testdb_helper_test.go):
//
//   - proof_hash, a SHA-256 hex digest, 64 wide and pinned case-sensitive, is the primary key: a
//     second row of one proof is refused by the key, and that refusal is the replay;
//   - expires_at is a microsecond datetime, NOT NULL, with a plain index for the worker's sweep;
//   - there is no foreign key, and nothing else in the schema changes; the down migration drops the
//     table it created.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000085_DPoPProofs
func TestMigration000085_DPoPProofs(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, beforeDPoPProofs000085), "migrate to 84")
	before := listTables(t, h)
	assert.NotContains(t, before, "dpop_proofs",
		"the table must not exist before 000085, so what is found afterwards is what 000085 added")

	require.NoError(t, h.Migrator.Migrate(ctx, dpopProofs000085), "apply 000085")
	assertDPoPProofsShape(t, h, "after apply")
	assertDPoPProofsKey(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "dpop_proofs"), listTables(t, h),
		"000085 must add the one table and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, beforeDPoPProofs000085), "roll back to 84")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop dpop_proofs and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, dpopProofs000085), "apply 000085 again")
	assertDPoPProofsShape(t, h, "after down then up")
	assertDPoPProofsKey(t, h, "after down then up")
}

func assertDPoPProofsShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	stringCollation := map[data.Dialect]string{
		data.MySQL:    "utf8mb4_0900_as_cs",
		data.MSSQL:    "Latin1_General_100_CS_AS_KS_WS_SC_UTF8",
		data.Postgres: "default",
		data.SQLite:   "BINARY",
	}
	hashType := map[data.Dialect]string{
		data.MySQL: "varchar(64)", data.Postgres: "character varying(64)", data.MSSQL: "nvarchar(64)", data.SQLite: "TEXT",
	}
	expiresAtType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}
	engine := dbType()

	shape := dumpTable(t, h, "dpop_proofs")

	hash := shape.column(t, "proof_hash")
	assert.Equalf(t, hashType[engine], hash.Type, "proof_hash's type %s", when)
	assert.Falsef(t, hash.Nullable, "proof_hash is NOT NULL %s", when)
	assert.Equalf(t, stringCollation[engine], hash.Collation, "proof_hash's effective collation is the case-sensitive one %s", when)

	expiresAt := shape.column(t, "expires_at")
	assert.Equalf(t, expiresAtType[engine], expiresAt.Type, "expires_at keeps the microseconds Go writes %s", when)
	assert.Falsef(t, expiresAt.Nullable, "expires_at is NOT NULL %s", when)

	assert.Lenf(t, shape.Columns, 2, "the two columns and no more %s", when)
	assert.Emptyf(t, shape.ForeignKeys, "nothing references a proof %s", when)

	var primaryKeys, others []indexShape
	for _, index := range shape.Indexes {
		if index.Origin == schemadump.OriginPrimaryKey {
			primaryKeys = append(primaryKeys, index)
		} else {
			others = append(others, index)
		}
	}
	require.Lenf(t, primaryKeys, 1, "the hash is the primary key %s; indexes read: %v", when, shape.Indexes)
	assert.Truef(t, primaryKeys[0].Unique, "and the key is unique %s", when)
	assert.Equalf(t, []string{"proof_hash"}, primaryKeys[0].Columns, "over the hash alone %s", when)

	require.Lenf(t, others, 1, "one index beside the key, for the sweep %s; indexes read: %v", when, shape.Indexes)
	assert.Equalf(t, "idx_dpop_proofs_expires_at", others[0].Name, "the sweep's index %s", when)
	assert.Equalf(t, []string{"expires_at"}, others[0].Columns, "over expires_at alone %s", when)
	assert.Falsef(t, others[0].Unique, "and not unique: many proofs expire at one moment %s", when)
}

// assertDPoPProofsKey holds the key to what it does: a second insert of one hash is refused, where
// another hash, and the same hash in upper case, are accepted. Literals rather than placeholders,
// since the four dialects disagree on placeholder syntax; every value is test-controlled. The table
// is empty on entry, both times this is called.
func assertDPoPProofsKey(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()

	insert := func(hash string) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
			"INSERT INTO dpop_proofs (proof_hash, expires_at) VALUES ('%s', '2026-01-02 03:04:05')", hash))
		return err
	}
	count := func() int {
		var n int
		require.NoError(t, h.SQL.QueryRowContext(ctx, "SELECT COUNT(*) FROM dpop_proofs").Scan(&n))
		return n
	}

	hash := newProofHash(t)
	require.Zerof(t, count(), "the table starts empty %s", when)

	require.NoErrorf(t, insert(hash), "the first use of a proof is accepted %s", when)
	require.Errorf(t, insert(hash), "a second row of the same proof is refused by the key %s", when)
	assert.Equalf(t, 1, count(), "and writes nothing %s", when)

	assert.NoErrorf(t, insert(newProofHash(t)), "another proof is accepted %s", when)
	assert.NoErrorf(t, insert(strings.ToUpper(hash)), "and so is the same hash in upper case: the key is case-sensitive %s", when)
	assert.Equalf(t, 3, count(), "three proofs, three rows %s", when)

	_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
		"INSERT INTO dpop_proofs (proof_hash, expires_at) VALUES ('%s', NULL)", newProofHash(t)))
	require.Errorf(t, err, "a row with no expiry is refused: expires_at is NOT NULL %s", when)

	_, err = h.SQL.ExecContext(ctx, "DELETE FROM dpop_proofs")
	require.NoErrorf(t, err, "empty the table again %s", when)
}
