package schemadump

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleSchema exercises every field of every shape in both polarities, so a round trip
// through it says the format carries what the shape holds rather than what one engine
// happens to fill in. The values are the awkward ones the four catalogs really report: a
// default holding a space and a quote, a masked and an unmasked name of each kind, an index
// on two columns, and a table whose columns are deliberately out of order on the way in.
//
// display_name is the case has_default exists for: a default whose expression is empty,
// which is what MySQL's catalog reports for DEFAULT ”. It has to encode differently from
// redirect_uri beside it, which has no default at all and the same empty expression.
func sampleSchema() Schema {
	return Schema{
		{Name: "clients", Table: TableShape{
			Columns: []ColumnShape{
				{Name: "redirect_uri", Type: "varchar(256)", Nullable: true, Default: "", Collation: "utf8mb4_0900_as_cs"},
				{Name: "display_name", Type: "varchar(100)", Nullable: false, Default: "", HasDefault: true,
					Collation: "utf8mb4_0900_as_cs"},
				{Name: "id", Type: "bigint unsigned", Nullable: false, Generated: true},
				{Name: "created_at", Type: "datetime2(6)", Nullable: false, Default: "(getdate())", HasDefault: true,
					DefaultName: "DF__clients__created__38996AB5", DefaultIsSystemNamed: true},
				{Name: "audit_details", Type: "json", Nullable: false, Default: `_utf8mb4'{}'`, HasDefault: true,
					DefaultName: "DF_clients_audit_details"},
			},
			Indexes: []IndexShape{
				{Name: "idx_clients_identifier", Exists: true, Unique: true, Columns: []string{"client_identifier"}, Origin: OriginCreated},
				{Name: "PK__clients__3213E83FD4F8DC0C", Exists: true, Unique: true, Columns: []string{"id"}, Origin: OriginPrimaryKey},
				{Name: "idx_clients_pair", Exists: true, Unique: false, Columns: []string{"a", "b"}, Origin: OriginCreated},
			},
			ForeignKeys: []ForeignKeyShape{
				{Column: "user_id", RefTable: "users", RefColumn: "id", OnDelete: "NO ACTION"},
				{Column: "group_id", RefTable: "groups", RefColumn: "id", OnDelete: "CASCADE"},
			},
		}},
		{Name: "audit_logs", Table: TableShape{
			Columns: []ColumnShape{
				{Name: "id", Type: "INTEGER", Nullable: false, Generated: true},
			},
		}},
	}
}

// sampleMigrated is the migration version the fixtures encode at. A number rather than a
// constant tied to the real chain: this file exercises the format, and pinning it to what
// the repository happens to have migrated to would make a round-trip case fail the next time
// a migration lands.
const sampleMigrated = 43

// sampleGolden is sampleSchema as one engine's whole golden record, which is what Encode now
// takes. Written as a helper because every case below needs the same three fields and only
// one of them varies per case.
func sampleGolden(d Dialect) Golden {
	return Golden{Dialect: d, Migrated: sampleMigrated, Schema: sampleSchema()}
}

// TestGoldenRoundTrip is the property the whole format rests on: Parse reads back exactly
// what Encode wrote, for every field. A fact the encoding drops is dropped from the
// committed record too, and because the same package writes the golden file and checks it,
// nothing downstream can recover it.
//
// The one field that does not survive verbatim is a name the engine invented, which is
// masked on purpose, so the expectation is the masked schema rather than the input.
func TestGoldenRoundTrip(t *testing.T) {
	for _, d := range []Dialect{SQLite, MySQL, Postgres, MSSQL} {
		encoded, err := Encode(sampleGolden(d))
		require.NoErrorf(t, err, "Encode on %s", d)

		got, err := Parse(encoded)
		require.NoErrorf(t, err, "Parse on %s", d)
		assert.Equal(t, d, got.Dialect, "the file names the engine that wrote it")
		assert.Equalf(t, sampleMigrated, got.Migrated,
			"the migration version survives the round trip on %s, which is what the version rule reads", d)
		assert.Equal(t, maskedSampleSchema(), got.Schema, "the parsed schema on %s", d)
	}
}

// maskedSampleSchema is sampleSchema as the golden file records it: sorted the way Encode
// orders, with the two engine-invented names replaced.
func maskedSampleSchema() Schema {
	return Schema{
		{Name: "audit_logs", Table: TableShape{
			Columns: []ColumnShape{{Name: "id", Type: "INTEGER", Generated: true}},
		}},
		{Name: "clients", Table: TableShape{
			Columns: []ColumnShape{
				{Name: "audit_details", Type: "json", Default: `_utf8mb4'{}'`, HasDefault: true,
					DefaultName: "DF_clients_audit_details"},
				{Name: "created_at", Type: "datetime2(6)", Default: "(getdate())", HasDefault: true,
					DefaultName: EngineNamedPlaceholder, DefaultIsSystemNamed: true},
				{Name: "display_name", Type: "varchar(100)", HasDefault: true, Collation: "utf8mb4_0900_as_cs"},
				{Name: "id", Type: "bigint unsigned", Generated: true},
				{Name: "redirect_uri", Type: "varchar(256)", Nullable: true, Collation: "utf8mb4_0900_as_cs"},
			},
			Indexes: []IndexShape{
				{Name: "idx_clients_pair", Exists: true, Columns: []string{"a", "b"}, Origin: OriginCreated},
				{Name: "idx_clients_identifier", Exists: true, Unique: true, Columns: []string{"client_identifier"}, Origin: OriginCreated},
				{Name: EngineNamedPlaceholder, Exists: true, Unique: true, Columns: []string{"id"}, Origin: OriginPrimaryKey},
			},
			ForeignKeys: []ForeignKeyShape{
				{Column: "group_id", RefTable: "groups", RefColumn: "id", OnDelete: "CASCADE"},
				{Column: "user_id", RefTable: "users", RefColumn: "id", OnDelete: "NO ACTION"},
			},
		}},
	}
}

// TestGoldenMasksOnlyEngineInventedNames pins the rule that makes the file committable at
// all. A SQL Server primary key name carries a random per-database suffix, so recording it
// would fail the per-engine assertion on every regeneration; a name a migration chose is
// what a later migration says when it drops the index, so recording it is the whole point.
//
// The question is answered from the catalog's origin and never from the name, which is why
// the fixture gives the CREATE INDEX entry a name that looks exactly like a generated one.
func TestGoldenMasksOnlyEngineInventedNames(t *testing.T) {
	schema := Schema{{Name: "t", Table: TableShape{
		Columns: []ColumnShape{{Name: "id", Type: "bigint"}},
		Indexes: []IndexShape{
			{Name: "PK__t__3213E83F", Exists: true, Unique: true, Columns: []string{"id"}, Origin: OriginPrimaryKey},
			{Name: "UQ__t__BF21A425", Exists: true, Unique: true, Columns: []string{"a"}, Origin: OriginUnique},
			{Name: "UQ__t__looks_generated_but_is_not", Exists: true, Columns: []string{"b"}, Origin: OriginCreated},
		},
	}}}

	encoded, err := Encode(Golden{Dialect: MSSQL, Migrated: sampleMigrated, Schema: schema})
	require.NoError(t, err)
	got, err := Parse(encoded)
	require.NoError(t, err)

	shape, ok := got.Schema.Table("t")
	require.True(t, ok)
	names := map[string]string{}
	for _, ix := range shape.Indexes {
		names[strings.Join(ix.Columns, ",")] = ix.Name
	}
	assert.Equal(t, EngineNamedPlaceholder, names["id"], "a primary key SQL Server named is masked")
	assert.Equal(t, EngineNamedPlaceholder, names["a"], "an inline UNIQUE the engine named is masked")
	assert.Equal(t, "UQ__t__looks_generated_but_is_not", names["b"],
		"origin decides, so a migration-chosen name survives however generated it looks")
}

// TestGoldenKeepsTwoMaskedIndexesApart answers decision 2's objection to masking, which is
// that two masked entries on one table become indistinguishable. client_logos has exactly
// that shape on three of the four engines: a primary key and a unique constraint, both named
// by the engine. Ordering by key columns before name is what keeps them apart.
func TestGoldenKeepsTwoMaskedIndexesApart(t *testing.T) {
	schema := Schema{{Name: "client_logos", Table: TableShape{
		Columns: []ColumnShape{{Name: "id", Type: "bigint"}},
		Indexes: []IndexShape{
			{Name: "UQ__client_l__BF21A425", Exists: true, Unique: true, Columns: []string{"client_id"}, Origin: OriginUnique},
			{Name: "PK__client_l__3213E83F", Exists: true, Unique: true, Columns: []string{"id"}, Origin: OriginPrimaryKey},
		},
	}}}

	encoded, err := Encode(Golden{Dialect: MSSQL, Migrated: sampleMigrated, Schema: schema})
	require.NoError(t, err)
	got, err := Parse(encoded)
	require.NoError(t, err)

	shape, _ := got.Schema.Table("client_logos")
	require.Len(t, shape.Indexes, 2, "both masked indexes survive")
	assert.Equal(t, []string{"client_id"}, shape.Indexes[0].Columns, "ordered by key columns, not by name")
	assert.Equal(t, OriginUnique, shape.Indexes[0].Origin)
	assert.Equal(t, []string{"id"}, shape.Indexes[1].Columns)
	assert.Equal(t, OriginPrimaryKey, shape.Indexes[1].Origin)
}

// TestGoldenIsDeterministic is what makes the per-engine assertion a comparison rather than
// a coin toss: the catalogs return rows in whatever order they like, so the file has to be
// decided by the encoder. Reversing every slice on the way in must change nothing on the way
// out.
func TestGoldenIsDeterministic(t *testing.T) {
	forward, err := Encode(sampleGolden(MySQL))
	require.NoError(t, err)

	shuffled := sampleSchema()
	reverse(shuffled)
	for i := range shuffled {
		reverse(shuffled[i].Table.Columns)
		reverse(shuffled[i].Table.Indexes)
		reverse(shuffled[i].Table.ForeignKeys)
	}
	backward, err := Encode(Golden{Dialect: MySQL, Migrated: sampleMigrated, Schema: shuffled})
	require.NoError(t, err)

	assert.Equal(t, string(forward), string(backward), "the input order must not reach the file")
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// TestEncodeRefusesAnEmptyDump keeps the failure Dump already refuses from arriving through
// the encoder instead. An empty file compared against an empty file reads as "nothing
// changed" and passes, which is the one outcome that would make the whole check worthless.
func TestEncodeRefusesAnEmptyDump(t *testing.T) {
	_, err := Encode(Golden{Dialect: SQLite, Migrated: sampleMigrated, Schema: Schema{}})
	assert.Error(t, err, "an empty schema is a fault, not a result")

	_, err = Encode(Golden{Dialect: SQLite, Migrated: sampleMigrated, Schema: Schema{{Name: "t"}}})
	assert.Error(t, err, "a table with no columns is a fault, not a result")

	_, err = Encode(Golden{Dialect: Dialect("oracle"), Migrated: sampleMigrated, Schema: sampleSchema()})
	assert.Error(t, err, "an unrecognised dialect must not be encoded")
}

// TestEncodeRefusesAnUnmigratedVersion is the header's half of the rule above. Version 0 is
// what a database that has never been migrated reports and what a struct literal that forgot
// the field carries, and both would encode into a file claiming to record a catalog at
// migration 0. The version rule reads that number, so a zero written here is a false claim
// the lint would then compare against the migrations on disk.
//
// Each case differs from the accepting twin above in the Migrated field alone.
func TestEncodeRefusesAnUnmigratedVersion(t *testing.T) {
	for _, migrated := range []int{0, -1} {
		_, err := Encode(Golden{Dialect: SQLite, Migrated: migrated, Schema: sampleSchema()})
		assert.Errorf(t, err, "migration version %d is not a migrated database", migrated)
	}

	_, err := Encode(Golden{Dialect: SQLite, Migrated: 1, Schema: sampleSchema()})
	assert.NoError(t, err, "the twin differing only in the version is accepted, so the case above tests the version")
}

// TestParseRefusesADamagedFile covers what the per-engine assertion is protected from. Every
// case here is a file that cannot be compared against anything: an older format, a truncated
// write, a hand edit. Reading one leniently would turn a corrupted record into a smaller
// schema that compares equal to another smaller schema.
func TestParseRefusesADamagedFile(t *testing.T) {
	good, err := Encode(sampleGolden(Postgres))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(good), "\n"), "\n")

	// mentions, where it is set, is what the error has to say. Only for the cases where
	// the message is the deliverable rather than the refusal. A field the writer never
	// wrote and a field whose value is corrupt need different repairs, regenerating
	// against a newer binary and restoring a damaged file, so the two are worth telling
	// apart in the words the reader gets.
	for _, tc := range []struct {
		name     string
		file     string
		mentions string
	}{
		{"a format version from after this binary", replaceVersion(string(good), goldenVersion+1), ""},
		{"a format version from before this binary", replaceVersion(string(good), goldenVersion-1), ""},
		{"no version at all", strings.Replace(string(good), fmt.Sprintf("\tversion=%d", goldenVersion), "", 1), ""},
		{"an engine that is not one of the four", strings.Replace(string(good), "engine=postgres", "engine=oracle", 1), ""},
		// migrated= is version 3's addition, and the field most costly to read leniently:
		// its zero value is a number the version rule would happily compare. The two
		// refusals are told apart in the words they use, because a field the writer never
		// wrote is regenerated against a newer binary and a corrupt value is restored.
		// Asserting only that Parse refused would let either branch cover both, which is
		// exactly what strconv.Atoi("") does if nothing pins the difference.
		{"no migrated field at all",
			strings.Replace(string(good), fmt.Sprintf("\tmigrated=%d", sampleMigrated), "", 1),
			"carries no migrated= field"},
		{"a migrated version that is not a number",
			replaceMigrated(string(good), "head"), `records migrated="head"`},
		{"a migrated version of zero", replaceMigrated(string(good), "0"), `records migrated="0"`},
		{"a negative migrated version", replaceMigrated(string(good), "-1"), `records migrated="-1"`},
		{"no header", strings.Join(lines[1:], "\n"), ""},
		{"nothing but a header", lines[0], ""},
		{"a truncated last line", string(good[:len(good)-12]), ""},
		{"an unquoted name", strings.Replace(string(good), "column\t\"clients\"\t\"id\"", "column\t\"clients\"\tid", 1), ""},
		{"a field with no =", strings.Replace(string(good), "\tnullable=false", "\tnullable", 1), ""},
		{"a boolean that is not true or false", strings.Replace(string(good), "nullable=false", "nullable=0", 1), "nullable"},
		{"an unquoted field value", strings.Replace(string(good), `type="json"`, "type=json", 1), ""},
		{"a missing string field", strings.Replace(string(good), "\tcollation=\"\"", "", 1), "no collation field"},
		{"a missing boolean field", strings.Replace(string(good), "\tgenerated=false", "", 1), "no generated field"},
		{"a missing has_default field", strings.Replace(string(good), "\thas_default=false", "", 1), "no has_default field"},
		{"an unknown record kind", strings.Replace(string(good), "column\t", "colunm\t", 1), ""},
		{"an index origin that is none of the three", strings.Replace(string(good), `origin="c"`, `origin="x"`, 1), "origin"},
		{"an index with no key columns", strings.Replace(string(good), `columns="a,b"`, `columns=""`, 1), ""},
		{"a record for a table no table line introduced", strings.Replace(string(good), "table\t\"clients\"\n", "", 1), ""},
		{"a table declared twice", string(good) + "\ntable\t\"clients\"", ""},
	} {
		// A needle that matched nothing would leave the good file behind, and a good
		// file parses, so this would still fail. Saying so here names the fault instead
		// of reporting it as a leniency the parser does not have.
		require.NotEqualf(t, string(good), tc.file, "the fixture for %s must actually damage the file", tc.name)
		_, err := Parse([]byte(tc.file))
		if !assert.Errorf(t, err, "Parse must refuse %s", tc.name) {
			continue
		}
		if tc.mentions != "" {
			assert.Containsf(t, err.Error(), tc.mentions,
				"the refusal of %s must name what is wrong so the file can be fixed", tc.name)
		}
	}
}

// TestGoldenPath names the four files decision 3 places beside each engine's migrations, and
// finds them from a working directory well below the source root, which is where both
// consumers actually run: the generator from src/core and the per-engine assertion from
// src/authserver/tests/data.
func TestGoldenPath(t *testing.T) {
	root, err := SourceRoot()
	require.NoError(t, err, "the test's own working directory is inside the repository")

	for _, d := range []Dialect{SQLite, MySQL, Postgres, MSSQL} {
		path, err := GoldenPath(d)
		require.NoErrorf(t, err, "GoldenPath(%s)", d)
		assert.Equalf(t, filepath.Join(root, "core", "data", string(d)+"db", "schema.golden"), path,
			"the %s golden file sits beside that engine's migrations", d)
		_, statErr := os.Stat(filepath.Dir(path))
		assert.NoErrorf(t, statErr, "the directory holding the %s golden file exists", d)
	}

	_, err = GoldenPath(Dialect("oracle"))
	assert.Error(t, err, "an unrecognised dialect names no golden file")
}

// replaceVersion rewrites the header's version, so the two format-version cases above are
// written against whatever version this binary writes rather than against a literal that
// goes stale the next time the format moves. It went stale once: version 2 added
// has_default, and the case that had been asserting an unknown version began asserting the
// current one and passing for no reason (#284).
func replaceVersion(file string, version int) string {
	return strings.Replace(file,
		fmt.Sprintf("\tversion=%d", goldenVersion),
		fmt.Sprintf("\tversion=%d", version), 1)
}

// replaceMigrated rewrites the header's migration version to an arbitrary string, so the
// cases above can put a value there that no int would encode. Written against
// sampleMigrated for the same reason replaceVersion is written against goldenVersion: a
// literal here goes stale the moment the fixture's number moves.
func replaceMigrated(file, migrated string) string {
	return strings.Replace(file,
		fmt.Sprintf("\tmigrated=%d", sampleMigrated),
		"\tmigrated="+migrated, 1)
}
