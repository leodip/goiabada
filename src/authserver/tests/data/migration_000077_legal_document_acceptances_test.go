package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000077 (#622, "What an acceptance records") creates legal_document_acceptances on all
// four engines: which user accepted which published version of a legal document, and when. This
// holds the migration to the claims its comments make, against an ISOLATED database of the
// configured dialect (see migration_testdb_helper_test.go):
//
//   - id is the key, accepted_at a NOT NULL microsecond datetime, user_id and
//     legal_document_version_id NOT NULL with the id columns' types;
//   - a user accepts a version once, so the pair is unique;
//   - deleting the user removes their acceptances, and a version accepted cannot be deleted, so what
//     a user accepted stays as long as the user does;
//   - nothing else in the schema changes, and the down migration drops the table.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000077_LegalDocumentAcceptances
func TestMigration000077_LegalDocumentAcceptances(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 76), "migrate to 76")
	before := listTables(t, h)
	assert.NotContains(t, before, "legal_document_acceptances",
		"the table must not exist before 000077, so what is found afterwards is what 000077 added")

	require.NoError(t, h.Migrator.Migrate(ctx, 77), "apply 000077")
	assertLegalDocumentAcceptancesShape(t, h, "after apply")
	assertLegalDocumentAcceptancesBehaviour(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "legal_document_acceptances"), listTables(t, h),
		"000077 must add the one table and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, 76), "roll back to 76")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop legal_document_acceptances and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 77), "apply 000077 again")
	assertLegalDocumentAcceptancesShape(t, h, "after down then up")
	assertLegalDocumentAcceptancesBehaviour(t, h, "after down then up")
}

func assertLegalDocumentAcceptancesShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	engine := dbType()
	idType := map[data.Dialect]string{
		data.MySQL: "bigint unsigned", data.Postgres: "bigint", data.MSSQL: "bigint", data.SQLite: "INTEGER",
	}[engine]
	timeType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}[engine]

	shape := dumpTable(t, h, "legal_document_acceptances")
	assert.Lenf(t, shape.Columns, 4, "id, accepted_at, user_id and legal_document_version_id %s", when)

	id := shape.column(t, "id")
	assert.Equalf(t, idType, id.Type, "id's type %s", when)
	assert.Truef(t, id.Generated, "id is generated %s", when)

	acceptedAt := shape.column(t, "accepted_at")
	assert.Equalf(t, timeType, acceptedAt.Type, "accepted_at keeps the microseconds Go writes %s", when)
	assert.Falsef(t, acceptedAt.Nullable, "accepted_at is NOT NULL %s", when)

	for _, column := range []string{"user_id", "legal_document_version_id"} {
		c := shape.column(t, column)
		assert.Equalf(t, idType, c.Type, "%s has the type of the id it names %s", column, when)
		assert.Falsef(t, c.Nullable, "%s is NOT NULL %s", column, when)
	}

	user := shape.foreignKey(t, "user_id")
	assert.Equalf(t, "users", user.RefTable, "user_id references users %s", when)
	assert.Equalf(t, "id", user.RefColumn, "by id %s", when)
	assert.Equalf(t, "CASCADE", user.OnDelete, "deleting the user removes their acceptances %s", when)

	version := shape.foreignKey(t, "legal_document_version_id")
	assert.Equalf(t, "legal_document_versions", version.RefTable, "legal_document_version_id references the versions %s", when)
	assert.Equalf(t, "id", version.RefColumn, "by id %s", when)
	assert.Equalf(t, "NO ACTION", version.OnDelete, "a version accepted is never deleted with its acceptances %s", when)
	assert.Lenf(t, shape.ForeignKeys, 2, "the two foreign keys and no more %s", when)

	pair := shape.index("idx_legal_document_acceptances_user_version")
	require.Truef(t, pair.Exists, "the pair's unique index %s; indexes read: %v", when, shape.Indexes)
	assert.Truef(t, pair.Unique, "a user accepts a version once %s", when)
	assert.Equalf(t, []string{"user_id", "legal_document_version_id"}, pair.Columns, "over the pair, user first %s", when)
	assert.NotEqualf(t, schemadump.OriginPrimaryKey, pair.Origin, "and it is not the key %s", when)

	byVersion := shape.index("idx_legal_document_acceptances_version_id")
	require.Truef(t, byVersion.Exists, "the version side's index, for the foreign key's checks %s; indexes read: %v", when, shape.Indexes)
	assert.Falsef(t, byVersion.Unique, "many users accept one version %s", when)
	assert.Equalf(t, []string{"legal_document_version_id"}, byVersion.Columns, "over legal_document_version_id alone %s", when)
}

// assertLegalDocumentAcceptancesBehaviour holds the key and the foreign keys to what they do. The
// users are written through the isolated handle's own data layer; the documents, the versions, the
// acceptances and the deletions are plain SQL on the tables under test, with literals because the
// four dialects disagree on placeholder syntax, and every value here is test-controlled.
func assertLegalDocumentAcceptancesBehaviour(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()
	exec := func(query string, args ...any) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(query, args...))
		return err
	}
	scalar := func(query string, args ...any) int64 {
		var n int64
		require.NoError(t, h.SQL.QueryRowContext(ctx, fmt.Sprintf(query, args...)).Scan(&n))
		return n
	}
	now := "'2026-10-31 12:00:00'"
	newUser := func() int64 {
		user := &record.User{Subject: fake.UUID(), Email: fake.LetterN(12) + "@example.com", Enabled: true}
		require.NoError(t, h.DB.CreateUser(ctx, nil, user), "CreateUser")
		return user.Id
	}

	shortName := "accepted-" + fake.LetterN(8)
	require.NoError(t, exec("INSERT INTO legal_documents (short_name, kind) VALUES ('%s', 'must_accept')", shortName))
	documentId := scalar("SELECT id FROM legal_documents WHERE short_name = '%s'", shortName)
	require.NoError(t, exec("INSERT INTO legal_document_versions (published_at, legal_document_id, version_number, title, markdown) VALUES (%s, %d, 1, 'Terms', 'Text')",
		now, documentId))
	versionId := scalar("SELECT id FROM legal_document_versions WHERE legal_document_id = %d", documentId)

	userId := newUser()
	otherUserId := newUser()
	acceptances := func(column string, id int64) int64 {
		return scalar("SELECT COUNT(*) FROM legal_document_acceptances WHERE %s = %d", column, id)
	}

	accept := "INSERT INTO legal_document_acceptances (accepted_at, user_id, legal_document_version_id) VALUES (%s, %d, %d)"
	require.NoErrorf(t, exec(accept, now, userId, versionId), "the first acceptance is accepted %s", when)
	require.Errorf(t, exec(accept, now, userId, versionId), "a second acceptance of the version by the user is refused by the key %s", when)
	assert.Equalf(t, int64(1), acceptances("user_id", userId), "and writes nothing %s", when)
	require.Errorf(t, exec(accept, now, userId, versionId+1_000_000), "an acceptance of no version is refused %s", when)
	require.Errorf(t, exec(accept, now, userId+1_000_000, versionId), "an acceptance by no user is refused %s", when)
	require.Errorf(t, exec("INSERT INTO legal_document_acceptances (user_id, legal_document_version_id) VALUES (%d, %d)",
		otherUserId, versionId), "an acceptance with no time is refused %s", when)
	require.NoError(t, exec(accept, now, otherUserId, versionId))

	require.Errorf(t, exec("DELETE FROM legal_document_versions WHERE id = %d", versionId),
		"a version accepted cannot be deleted %s", when)

	require.NoError(t, exec("DELETE FROM users WHERE id = %d", userId))
	assert.Equalf(t, int64(0), acceptances("user_id", userId), "deleting the user removed their acceptances %s", when)
	assert.Equalf(t, int64(1), acceptances("legal_document_version_id", versionId),
		"and left another user's acceptance of the version %s", when)

	require.NoError(t, exec("DELETE FROM users WHERE id = %d", otherUserId))
	require.NoError(t, exec("DELETE FROM legal_document_versions WHERE id = %d", versionId))
	require.NoError(t, exec("DELETE FROM legal_documents WHERE id = %d", documentId))
}
