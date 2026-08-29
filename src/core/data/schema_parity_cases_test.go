package data

// The cross-engine comparison exercised against synthetic shapes, which is what makes the
// feature testable at all (#284, seam 3): a vocabulary bug is caught here with no database,
// and the real four-engine case is one input to the same function rather than the only one.
//
// The fixture is idealised rather than realistic. Four engines spelling one table in their
// own words, agreeing on every axis, so a case that changes nothing must report nothing and
// every case below is exactly one difference wide. The real SQLite idioms, a missing length
// and no index behind a rowid primary key, are the subject of their own cases.

import (
	"fmt"
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parityFixture is four dumps of one table that agree. Each column is spelled the way that
// engine's catalog reports it, so the baseline is also the test of canonicalisation: it is
// clean only if TEXT-family names, the four datetime spellings, the four collation names and
// the four ways of wrapping a default all map onto one vocabulary.
func parityFixture() map[schemadump.Dialect]schemadump.Schema {
	table := func(columns []schemadump.ColumnShape, indexes []schemadump.IndexShape) schemadump.Schema {
		return schemadump.Schema{{
			Name: "widgets",
			Table: schemadump.TableShape{
				Columns: columns,
				Indexes: indexes,
				ForeignKeys: []schemadump.ForeignKeyShape{
					{Column: "owner_id", RefTable: "owners", RefColumn: "id", OnDelete: "CASCADE"},
				},
			},
		}}
	}
	// Every engine but SQLite names the index behind a primary key for itself, and SQLite
	// produces no index at all for a rowid alias. The fixture gives all four one, so the
	// real SQLite behaviour is a case rather than the baseline.
	primaryKey := schemadump.IndexShape{
		Name: schemadump.EngineNamedPlaceholder, Exists: true, Unique: true,
		Columns: []string{"id"}, Origin: schemadump.OriginPrimaryKey,
	}
	nameIndex := schemadump.IndexShape{
		Name: "idx_widgets_name", Exists: true, Unique: true,
		Columns: []string{"name"}, Origin: schemadump.OriginCreated,
	}

	return map[schemadump.Dialect]schemadump.Schema{
		schemadump.SQLite: table([]schemadump.ColumnShape{
			{Name: "created_at", Type: "DATETIME(6)", Nullable: true, Collation: "BINARY"},
			{Name: "enabled", Type: "BOOLEAN", Default: "0", Collation: "BINARY"},
			{Name: "id", Type: "INTEGER", Collation: "BINARY", Generated: true},
			{Name: "label", Type: "VARCHAR(20)", Default: "'draft'", Collation: "BINARY"},
			{Name: "name", Type: "VARCHAR(40)", Collation: "BINARY"},
			{Name: "owner_id", Type: "INTEGER", Collation: "BINARY"},
			{Name: "payload", Type: "BLOB", Nullable: true, Collation: "BINARY"},
		}, []schemadump.IndexShape{primaryKey, nameIndex}),

		schemadump.MySQL: table([]schemadump.ColumnShape{
			{Name: "created_at", Type: "datetime(6)", Nullable: true},
			{Name: "enabled", Type: "tinyint(1)", Default: "0"},
			{Name: "id", Type: "bigint", Generated: true},
			// MySQL's catalog reports a string default as the value, where the other
			// three report the literal with its quotes.
			{Name: "label", Type: "varchar(20)", Default: "draft", Collation: "utf8mb4_0900_as_cs"},
			{Name: "name", Type: "varchar(40)", Collation: "utf8mb4_0900_as_cs"},
			{Name: "owner_id", Type: "bigint"},
			{Name: "payload", Type: "longblob", Nullable: true},
		}, []schemadump.IndexShape{primaryKey, nameIndex}),

		schemadump.Postgres: table([]schemadump.ColumnShape{
			// An unqualified PostgreSQL timestamp is microsecond precision, which is
			// what the other three write as (6).
			{Name: "created_at", Type: "timestamp without time zone", Nullable: true},
			{Name: "enabled", Type: "boolean", Default: "false"},
			{Name: "id", Type: "bigint", Generated: true},
			{Name: "label", Type: "character varying(20)", Default: "'draft'::character varying", Collation: "default"},
			{Name: "name", Type: "character varying(40)", Collation: "default"},
			{Name: "owner_id", Type: "bigint"},
			{Name: "payload", Type: "bytea", Nullable: true},
		}, []schemadump.IndexShape{primaryKey, nameIndex}),

		schemadump.MSSQL: table([]schemadump.ColumnShape{
			{Name: "created_at", Type: "datetime2(6)", Nullable: true},
			{Name: "enabled", Type: "bit", Default: "((0))"},
			{Name: "id", Type: "bigint", Generated: true},
			{Name: "label", Type: "nvarchar(20)", Default: "('draft')", Collation: mssqlCollation},
			{Name: "name", Type: "nvarchar(40)", Collation: mssqlCollation},
			{Name: "owner_id", Type: "bigint"},
			{Name: "payload", Type: "varbinary(max)", Nullable: true},
		}, []schemadump.IndexShape{primaryKey, nameIndex}),
	}
}

const mssqlCollation = "Latin1_General_100_CS_AS_KS_WS_SC_UTF8"

// widgetsOn returns the fixture's table on one engine so a case can change it in place.
func widgetsOn(dumps map[schemadump.Dialect]schemadump.Schema, d schemadump.Dialect) *schemadump.TableShape {
	for i := range dumps[d] {
		if dumps[d][i].Name == "widgets" {
			return &dumps[d][i].Table
		}
	}
	panic("the parity fixture has no widgets table on " + string(d))
}

// widgetColumnOn returns one column of the fixture's table on one engine, in place.
func widgetColumnOn(dumps map[schemadump.Dialect]schemadump.Schema, d schemadump.Dialect, name string) *schemadump.ColumnShape {
	table := widgetsOn(dumps, d)
	for i := range table.Columns {
		if table.Columns[i].Name == name {
			return &table.Columns[i]
		}
	}
	panic("the parity fixture has no column " + name + " on " + string(d))
}

// excusing builds a rule covering exactly the keys given, with the count and digest they
// produce. Cases that mean to test a rule holding write it this way; cases that mean to test
// a rule that has MOVED write the count and digest by hand.
func excusing(name string, keys []string, matches func(parityDivergence) bool) parityRule {
	return parityRule{
		Name: name, Why: "a synthetic idiom, deliberate for the length of this test",
		Count: len(keys), Digest: parityDigest(keys), Excuses: matches,
	}
}

func onAxis(axis string) func(parityDivergence) bool {
	return func(d parityDivergence) bool { return d.Axis == axis }
}

func TestCheckParity_ReportsEveryDisagreementAndOnlyThose(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(map[schemadump.Dialect]schemadump.Schema)
		rules   []parityRule
		want    []string
	}{
		{
			name: "four engines spelling one schema in four vocabularies agree",
		},
		{
			name: "a column narrowed on one engine is caught",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.MSSQL, "name").Type = "nvarchar(32)"
			},
			want: []string{"widgets.name:type  sqlite=string(40)"},
		},
		{
			name: "SQLite declaring no length is a difference, not a spelling",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "name").Type = "TEXT"
			},
			want: []string{"widgets.name:type  sqlite=string(no declared length)"},
		},
		{
			name: "and the allowlist can excuse it, counted",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "name").Type = "TEXT"
			},
			rules: []parityRule{excusing("sqlite declares no length", []string{"widgets.name:type"}, onAxis(parityAxisType))},
		},
		{
			name: "MySQL's unsigned integers stay comparable and reach the allowlist",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.MySQL, "id").Type = "bigint unsigned"
			},
			want: []string{"widgets.id:type  sqlite=int64  mysql=uint64"},
		},
		{
			name: "a rule that has grown fails on its count",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "name").Type = "TEXT"
				widgetColumnOn(dumps, schemadump.SQLite, "label").Type = "TEXT"
			},
			rules: []parityRule{excusing("sqlite declares no length", []string{"widgets.name:type"}, onAxis(parityAxisType))},
			want:  []string{`"sqlite declares no length" no longer covers what it was written for: recorded 1 place(s), found 2.`},
		},
		{
			name: "a rule whose membership moved at a constant count fails on its digest",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "label").Type = "TEXT"
			},
			rules: []parityRule{excusing("sqlite declares no length", []string{"widgets.name:type"}, onAxis(parityAxisType))},
			want:  []string{"recorded 1 place(s), found 1, and they are not the same places"},
		},
		{
			name: "a table absent on one engine is one finding, not one per column",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				gadgets := schemadump.TableEntry{Name: "gadgets", Table: schemadump.TableShape{
					Columns: []schemadump.ColumnShape{{Name: "id", Type: "bigint", Generated: true}},
				}}
				for _, d := range []schemadump.Dialect{schemadump.SQLite, schemadump.MySQL, schemadump.Postgres} {
					dumps[d] = append(dumps[d], gadgets)
				}
			},
			want: []string{"gadgets:table  sqlite=present  mysql=present  postgres=present  mssql=absent"},
		},
		{
			name: "a column absent on one engine is one finding, not one per axis",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				table := widgetsOn(dumps, schemadump.Postgres)
				table.Columns = table.Columns[1:]
			},
			want: []string{"widgets.created_at:column  sqlite=present  mysql=present  postgres=absent"},
		},
		{
			name: "an index one engine alone builds is caught",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				table := widgetsOn(dumps, schemadump.MySQL)
				table.Indexes = append(table.Indexes, schemadump.IndexShape{
					Name: "fk_widgets_owner", Exists: true, Columns: []string{"owner_id"},
					Origin: schemadump.OriginCreated,
				})
			},
			want: []string{"widgets.index(owner_id):index  sqlite=absent  mysql=present"},
		},
		{
			name: "and the allowlist can excuse that too",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				table := widgetsOn(dumps, schemadump.MySQL)
				table.Indexes = append(table.Indexes, schemadump.IndexShape{
					Name: "fk_widgets_owner", Exists: true, Columns: []string{"owner_id"},
					Origin: schemadump.OriginCreated,
				})
			},
			rules: []parityRule{excusing("innodb indexes every foreign key",
				[]string{"widgets.index(owner_id):index"}, onAxis(parityAxisIndex))},
		},
		{
			name: "SQLite building no index behind a rowid primary key is caught",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				table := widgetsOn(dumps, schemadump.SQLite)
				table.Indexes = table.Indexes[1:]
			},
			want: []string{"widgets.unique index(id):index  sqlite=absent  mysql=present"},
		},
		{
			name: "an index name is compared when every engine's came from a migration",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetsOn(dumps, schemadump.MSSQL).Indexes[1].Name = "idx_widget_name"
			},
			want: []string{"widgets.unique index(name):index-name  sqlite=idx_widgets_name"},
		},
		{
			name: "and not when one engine invented its own",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				index := &widgetsOn(dumps, schemadump.MSSQL).Indexes[1]
				index.Name, index.Origin = schemadump.EngineNamedPlaceholder, schemadump.OriginUnique
			},
		},
		{
			name: "a foreign key's on-delete action is compared",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetsOn(dumps, schemadump.MSSQL).ForeignKeys[0].OnDelete = "NO ACTION"
			},
			want: []string{"widgets.owner_id->owners.id:on-delete  sqlite=CASCADE  mysql=CASCADE  postgres=CASCADE  mssql=NO ACTION"},
		},
		{
			name: "a foreign key absent on one engine is caught",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetsOn(dumps, schemadump.SQLite).ForeignKeys = nil
			},
			want: []string{"widgets.owner_id->owners.id:foreign-key  sqlite=absent"},
		},
		{
			name: "nullability is compared",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "id").Nullable = true
			},
			want: []string{"widgets.id:nullable  sqlite=nullable  mysql=not null"},
		},
		{
			name: "a column the engine stops numbering is caught, which is goal 1 exactly",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.MySQL, "id").Generated = false
			},
			want: []string{"widgets.id:generated  sqlite=generated  mysql=not generated"},
		},
		{
			name: "a collation that decides something is compared",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.MSSQL, "name").Collation = ""
			},
			want: []string{"widgets.name:collation  sqlite=case-sensitive  mysql=case-sensitive  postgres=case-sensitive  mssql=no collation"},
		},
		{
			name: "a type the vocabulary does not carry can never be excused",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "name").Type = "GEOGRAPHY"
			},
			rules: []parityRule{{Name: "excuses everything", Digest: parityDigest(nil),
				Excuses: func(parityDivergence) bool { return true }}},
			want: []string{`widgets.name:vocabulary  sqlite=sqlite spells a type "GEOGRAPHY", which the parity vocabulary does not carry`},
		},
		{
			name: "a collation the vocabulary does not carry is unreadable, not a difference",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "name").Collation = "NOCASE"
			},
			want: []string{`widgets.name:vocabulary  sqlite=sqlite reports collation "NOCASE", which the parity vocabulary does not carry`},
		},
		{
			name: "a divergence two rules both excuse makes neither count mean anything",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				widgetColumnOn(dumps, schemadump.SQLite, "name").Type = "TEXT"
			},
			rules: []parityRule{
				excusing("sqlite declares no length", nil, onAxis(parityAxisType)),
				excusing("something else about types", nil, onAxis(parityAxisType)),
			},
			want: []string{`widgets.name:type is excused by more than one allowlist rule`},
		},
		{
			name: "three engines agreeing is not parity",
			arrange: func(dumps map[schemadump.Dialect]schemadump.Schema) {
				delete(dumps, schemadump.MSSQL)
			},
			want: []string{"no schema to compare for mssql"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dumps := parityFixture()
			if tt.arrange != nil {
				tt.arrange(dumps)
			}
			problems := checkParity(dumps, tt.rules)
			require.Len(t, problems, len(tt.want), "problems reported:\n%s", joinProblems(problems))
			for i, want := range tt.want {
				assert.Contains(t, problems[i], want)
			}
		})
	}
}

func joinProblems(problems []string) string {
	out := ""
	for _, p := range problems {
		out += "  - " + p + "\n"
	}
	return out
}

// TestParityCanonicalType_MapsSpellingAndKeepsFacts pins the boundary the whole comparison
// rests on: what is one type written four ways, and what is four different types.
func TestParityCanonicalType_MapsSpellingAndKeepsFacts(t *testing.T) {
	tests := []struct {
		dialect  schemadump.Dialect
		spelling string
		want     string
		wantErr  string
	}{
		{schemadump.SQLite, "TEXT", "string(no declared length)", ""},
		{schemadump.SQLite, "VARCHAR(40)", "string(40)", ""},
		{schemadump.SQLite, "INT", "int32", ""},
		{schemadump.SQLite, "INTEGER", "int64", ""},
		{schemadump.SQLite, "numeric", "numeric", ""},
		{schemadump.SQLite, "DATETIME", "datetime(no declared precision)", ""},
		{schemadump.MySQL, "varchar(40)", "string(40)", ""},
		{schemadump.MySQL, "tinyint(1)", "bool", ""},
		{schemadump.MySQL, "tinyint(4)", "int8", ""},
		{schemadump.MySQL, "bigint unsigned", "uint64", ""},
		{schemadump.MySQL, "text", "string(65535)", ""},
		{schemadump.MySQL, "longtext", "string(unbounded)", ""},
		{schemadump.MySQL, "datetime(6)", "datetime(6)", ""},
		{schemadump.Postgres, "character varying(40)", "string(40)", ""},
		{schemadump.Postgres, "text", "string(unbounded)", ""},
		{schemadump.Postgres, "timestamp without time zone", "datetime(6)", ""},
		{schemadump.Postgres, "timestamp(3) without time zone", "datetime(3)", ""},
		{schemadump.MSSQL, "nvarchar(40)", "string(40)", ""},
		{schemadump.MSSQL, "nvarchar(max)", "string(unbounded)", ""},
		{schemadump.MSSQL, "varbinary(max)", "bytes(unbounded)", ""},
		{schemadump.MSSQL, "datetime2(6)", "datetime(6)", ""},
		{schemadump.MSSQL, "datetime2", "datetime(7)", ""},
		{schemadump.MySQL, "geometry", "", "does not carry"},
		{schemadump.Postgres, "character varying(wide)", "", "length is not a number"},
	}

	for _, tt := range tests {
		t.Run(string(tt.dialect)+" "+tt.spelling, func(t *testing.T) {
			got, err := canonicalType(tt.dialect, tt.spelling)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

// TestParityCanonicalDefault_StripsWrappingAndNothingElse pins the other half of the same
// boundary. Every engine wraps a default in its own punctuation and one of them reports the
// value where the rest report the literal; none of that is a difference between databases.
// What is left inside the wrapping is untouched, including MySQL's character-set introducer,
// which is a real difference and an allowlist entry of its own.
func TestParityCanonicalDefault_StripsWrappingAndNothingElse(t *testing.T) {
	tests := []struct {
		dialect schemadump.Dialect
		raw     string
		has     bool
		want    parityDefault
	}{
		{schemadump.SQLite, "", false, parityDefault{}},
		{schemadump.MySQL, "", false, parityDefault{}},
		// The pair the has-a-default bit exists for: MySQL reports DEFAULT '' as the
		// empty string, which is what a column with no default reports too, so the
		// expression alone cannot tell these two rows apart.
		{schemadump.MySQL, "", true, parityDefault{Present: true, Value: ""}},
		{schemadump.SQLite, "NULL", true, parityDefault{}},
		{schemadump.MSSQL, "(NULL)", true, parityDefault{}},
		{schemadump.MSSQL, "((0))", true, parityDefault{Present: true, Value: "0"}},
		{schemadump.SQLite, "0", true, parityDefault{Present: true, Value: "0"}},
		{schemadump.Postgres, "false", true, parityDefault{Present: true, Value: "0"}},
		{schemadump.Postgres, "true", true, parityDefault{Present: true, Value: "1"}},
		{schemadump.MSSQL, "('')", true, parityDefault{Present: true, Value: ""}},
		{schemadump.SQLite, "''", true, parityDefault{Present: true, Value: ""}},
		{schemadump.Postgres, "''::character varying", true, parityDefault{Present: true, Value: ""}},
		{schemadump.Postgres, "'default'::character varying", true, parityDefault{Present: true, Value: "default"}},
		{schemadump.MySQL, "default", true, parityDefault{Present: true, Value: "default"}},
		// The cast belongs to the argument, not to the expression, so it stays.
		{schemadump.Postgres, "nextval('widgets_id_seq'::regclass)", true,
			parityDefault{Present: true, Value: "nextval('widgets_id_seq'::regclass)"}},
		// MySQL's character-set introducer is a fact about the default, not a wrapping.
		{schemadump.MySQL, "_utf8mb4'{}'", true, parityDefault{Present: true, Value: "_utf8mb4'{}'"}},
		{schemadump.MSSQL, "(getdate())", true, parityDefault{Present: true, Value: "getdate()"}},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s %q has=%t", tt.dialect, tt.raw, tt.has), func(t *testing.T) {
			assert.Equal(t, tt.want, canonicalDefault(tt.dialect, tt.raw, tt.has))
		})
	}
}
