package schemadump

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The golden file is the checked record of what one engine's migration chain builds, and the
// seam between the generator that writes it and the data tier that compares a freshly
// migrated database against it. It replaced the hand-maintained schema.sql snapshot that used
// to sit beside it, which nothing could hold to being right and which was wrong on SQL Server
// by 27 objects; that snapshot was deleted in the same change (#284).
//
// The format is one tab-separated record per column, index and foreign key. Records carry
// their own table name rather than relying on the table line above them, so a diff hunk in a
// pull request reads without its heading. Every string is written through strconv.Quote,
// which escapes the tab it would otherwise be confused with, and which is why a default
// holding a space survives the round trip: `NO ACTION`, `nextval('clients_id_seq'::regclass)`
// and `_utf8mb4'{}'` are all real values here.
//
// Read it with Parse and never by eye-matching a substring: the two are one pair, and the
// round-trip test is what says the file carries everything the shape holds.

// goldenVersion is the format's version, written into the header and required by Parse. A
// file at an unknown version is refused rather than read as a current one, because the
// failure that would otherwise produce is the worst kind available here: an older file
// missing a field parses into a shape whose zero value is a legitimate reading, and the
// comparison then passes against a record of something else.
//
// Version 2 added has_default to every column record. Version 1 carried the default
// expression alone, which cannot say whether a column with an empty expression has a default
// at all, and read four MySQL columns declaring DEFAULT ” as having none (#284).
//
// Version 3 added migrated= to the header, the migration version of the database the dump
// came from. It is what lets a lint hold a committed file to the highest migration on disk
// for its engine without a database or a git history, so a migration landing without a
// regeneration is caught in the core tier rather than only on the four database jobs (#288).
const goldenVersion = 3

// Golden is everything one golden file records: the engine it describes, the migration
// version of the database it was dumped from, and that database's catalog.
//
// Encode and Parse are its two halves and neither takes the parts separately, which is what
// keeps a field from being dropped on the way through. Parse returning the struct rather
// than a widening list of values is the same argument the format version makes: a reader
// that silently ignores a header field it was not asked for is how an older file gets
// compared against a newer one.
type Golden struct {
	Dialect  Dialect
	Migrated int
	Schema   Schema
}

// EngineNamedPlaceholder stands in for a name the engine invented rather than a migration
// choosing it.
//
// Masking is forced rather than stylistic. SQL Server's generated names carry a random
// per-database suffix, so `UQ__client_l__BF21A42544DF1DA7` differs on every regeneration and
// a file recording it could not be committed at all: the per-engine assertion would fail on
// every run. The distinction that matters, engine-invented against ours, survives the mask.
//
// It is applied uniformly on all four engines and to SQL Server's default constraints too,
// even though those turn out to be stable, so the artifact depends on no undocumented naming
// scheme. Parentheses keep it outside what `identifier` accepts, so it cannot collide with a
// name a migration chose.
const EngineNamedPlaceholder = "(engine-named)"

// maskedIndexName is the name to record for an index, which is the index's own name when a
// migration chose it and the placeholder when the engine did.
//
// The question is answered from IndexOrigin, which every branch of dumpIndexes reads out of
// the catalog, and never from the shape of the name. A name pattern is the one thing that
// cannot be trusted here: SQL Server's generated names are random, and PostgreSQL's
// `<table>_pkey` is a convention a migration is free to spell itself.
func maskedIndexName(ix IndexShape) string {
	if ix.Origin == OriginCreated {
		return ix.Name
	}
	return EngineNamedPlaceholder
}

// maskedDefaultName is the same rule for SQL Server's default constraints, the only named
// defaults any of the four engines have. 42 of the 64 in the chain are the engine's own.
func maskedDefaultName(c ColumnShape) string {
	if c.DefaultName == "" || !c.DefaultIsSystemNamed {
		return c.DefaultName
	}
	return EngineNamedPlaceholder
}

// Encode renders a schema as the bytes of that engine's golden file.
//
// Ordering is total and decided here rather than taken from the input, so the same schema
// read in any order encodes byte-identically: tables by name, columns by name, indexes by key
// columns then uniqueness then name, foreign keys by the tuple DumpTable already sorts on.
//
// Indexes are ordered by key columns BEFORE name, which is what keeps two masked indexes on
// one table apart: client_logos carries a masked primary key and a masked unique constraint
// on three of the four engines, and after masking their names are the same string. Their key
// columns are not.
func Encode(g Golden) ([]byte, error) {
	d, schema := g.Dialect, g.Schema
	if !d.valid() {
		return nil, fmt.Errorf("schemadump: unrecognised database dialect %q", d)
	}
	if len(schema) == 0 {
		return nil, fmt.Errorf("schemadump: refusing to encode an empty schema for %s, which no migrated database can have", d)
	}
	// A migration version of zero is an unmigrated database, and a negative one is a bug in
	// whatever read it. Neither is a record of a catalog anybody chose, and both would encode
	// into a file the version rule then reads as an honest claim.
	if g.Migrated <= 0 {
		return nil, fmt.Errorf("schemadump: refusing to encode the %s dump at migration version %d, which is not a migrated database", d, g.Migrated)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "# goiabada schema dump\tversion=%d\tengine=%s\tmigrated=%d\n", goldenVersion, d, g.Migrated)
	b.WriteString("#\n")
	b.WriteString("# Generated by `go run ./cmd/schemadump` from src/core, which regenerates all four\n")
	b.WriteString("# engines at once. Do not edit by hand: the data tier compares a freshly migrated\n")
	b.WriteString("# database against this file on the engine it was written for, so an edit here is a\n")
	b.WriteString("# claim about a database rather than a record of one.\n")
	b.WriteString("#\n")
	fmt.Fprintf(&b, "# A name reading %s is one the engine invented, not one a migration chose.\n", EngineNamedPlaceholder)

	tables := append(Schema(nil), schema...)
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })

	for _, entry := range tables {
		if len(entry.Table.Columns) == 0 {
			return nil, fmt.Errorf("schemadump: refusing to encode table %q with no columns on %s", entry.Name, d)
		}

		b.WriteString("\n")
		writeRecord(&b, "table", entry.Name)

		columns := append([]ColumnShape(nil), entry.Table.Columns...)
		sort.Slice(columns, func(i, j int) bool { return columns[i].Name < columns[j].Name })
		for _, c := range columns {
			writeRecord(&b, "column", entry.Name, c.Name,
				field("type", c.Type),
				boolField("nullable", c.Nullable),
				field("default", c.Default),
				boolField("has_default", c.HasDefault),
				field("collation", c.Collation),
				field("default_name", maskedDefaultName(c)),
				boolField("generated", c.Generated))
		}

		indexes := append([]IndexShape(nil), entry.Table.Indexes...)
		sort.Slice(indexes, func(i, j int) bool { return lessIndex(indexes[i], indexes[j]) })
		for _, ix := range indexes {
			if len(ix.Columns) == 0 {
				return nil, fmt.Errorf("schemadump: refusing to encode index %q on %q with no key columns on %s", ix.Name, entry.Name, d)
			}
			writeRecord(&b, "index", entry.Name, maskedIndexName(ix),
				field("columns", strings.Join(ix.Columns, ",")),
				boolField("unique", ix.Unique),
				field("origin", string(ix.Origin)))
		}

		foreignKeys := append([]ForeignKeyShape(nil), entry.Table.ForeignKeys...)
		sort.Slice(foreignKeys, func(i, j int) bool { return lessForeignKey(foreignKeys[i], foreignKeys[j]) })
		for _, fk := range foreignKeys {
			writeRecord(&b, "foreign_key", entry.Name, fk.Column,
				field("ref_table", fk.RefTable),
				field("ref_column", fk.RefColumn),
				field("on_delete", fk.OnDelete))
		}
	}

	return b.Bytes(), nil
}

// lessIndex is the golden file's index order: key columns, then uniqueness, then the name as
// recorded. Two indexes agreeing on all three are the same index.
func lessIndex(a, b IndexShape) bool {
	ac, bc := strings.Join(a.Columns, ","), strings.Join(b.Columns, ",")
	if ac != bc {
		return ac < bc
	}
	if a.Unique != b.Unique {
		return b.Unique
	}
	return maskedIndexName(a) < maskedIndexName(b)
}

func lessForeignKey(a, b ForeignKeyShape) bool {
	if a.Column != b.Column {
		return a.Column < b.Column
	}
	if a.RefTable != b.RefTable {
		return a.RefTable < b.RefTable
	}
	return a.RefColumn < b.RefColumn
}

func field(key, value string) string { return key + "=" + strconv.Quote(value) }
func boolField(key string, v bool) string {
	return key + "=" + strconv.FormatBool(v)
}

// writeRecord writes one tab-separated line: the record kind, its quoted positional names,
// then its key=value fields. Positional and keyed parts are told apart by the "=" a field
// carries and a quoted name cannot begin with.
func writeRecord(b *bytes.Buffer, kind string, names ...string) {
	b.WriteString(kind)
	for i, n := range names {
		b.WriteString("\t")
		// The first arguments are names to quote; anything already carrying a key= is a
		// pre-rendered field. field() and boolField() produce those.
		if strings.Contains(n, "=") && i >= positionalCount(kind) {
			b.WriteString(n)
			continue
		}
		b.WriteString(strconv.Quote(n))
	}
	b.WriteString("\n")
}

// positionalCount is how many quoted names precede the key=value fields for each record
// kind. It is what lets a positional name legitimately contain "=" without being read as a
// field, which no identifier here does but which the parser must not depend on.
func positionalCount(kind string) int {
	if kind == "table" {
		return 1
	}
	return 2
}

// Parse reads a golden file back into the schema and the engine it records.
//
// It is deliberately strict. Every failure it reports is a file that cannot be compared
// against anything: a truncated write, a hand edit, or a file from an older format. The
// alternative, tolerating what it does not understand, turns a corrupted record into a
// smaller schema that compares equal to another smaller schema.
func Parse(b []byte) (Golden, error) {
	var (
		g       Golden
		haveHdr bool
		schema  Schema
		byName  = map[string]int{}
	)

	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if strings.HasPrefix(text, "# goiabada schema dump") {
			if haveHdr {
				return Golden{}, fmt.Errorf("schemadump: golden file line %d: a second header", line)
			}
			d, migrated, err := parseHeader(text)
			if err != nil {
				return Golden{}, fmt.Errorf("schemadump: golden file line %d: %w", line, err)
			}
			g.Dialect, g.Migrated, haveHdr = d, migrated, true
			continue
		}
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if !haveHdr {
			return Golden{}, fmt.Errorf("schemadump: golden file line %d: a record before the header", line)
		}
		if err := parseRecord(text, &schema, byName); err != nil {
			return Golden{}, fmt.Errorf("schemadump: golden file line %d: %w", line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Golden{}, fmt.Errorf("schemadump: reading the golden file: %w", err)
	}
	if !haveHdr {
		return Golden{}, fmt.Errorf("schemadump: the golden file carries no header")
	}
	if len(schema) == 0 {
		return Golden{}, fmt.Errorf("schemadump: the %s golden file records no tables at all", g.Dialect)
	}
	for _, e := range schema {
		if len(e.Table.Columns) == 0 {
			return Golden{}, fmt.Errorf("schemadump: the %s golden file records table %q with no columns", g.Dialect, e.Name)
		}
	}
	g.Schema = schema
	return g, nil
}

// parseHeader reads the three things the header carries. Every field is required: a header
// missing one is refused rather than read with a zero in its place, which is the failure
// goldenVersion's own comment describes and which migrated= would be the easiest field to
// suffer it, zero being a value the version rule could otherwise compare.
func parseHeader(text string) (Dialect, int, error) {
	fields := strings.Split(text, "\t")
	var version, engine string
	migrated := ""
	for _, f := range fields[1:] {
		switch {
		case strings.HasPrefix(f, "version="):
			version = strings.TrimPrefix(f, "version=")
		case strings.HasPrefix(f, "engine="):
			engine = strings.TrimPrefix(f, "engine=")
		case strings.HasPrefix(f, "migrated="):
			migrated = strings.TrimPrefix(f, "migrated=")
		}
	}
	if version != strconv.Itoa(goldenVersion) {
		return "", 0, fmt.Errorf("golden file format version %q, but this build writes and reads version %d", version, goldenVersion)
	}
	d := Dialect(engine)
	if !d.valid() {
		return "", 0, fmt.Errorf("golden file names engine %q, which is none of the four dialects", engine)
	}
	if migrated == "" {
		return "", 0, fmt.Errorf("golden file header carries no migrated= field, which version %d requires", goldenVersion)
	}
	n, err := strconv.Atoi(migrated)
	if err != nil || n <= 0 {
		return "", 0, fmt.Errorf("golden file header records migrated=%q, which is not a positive migration version", migrated)
	}
	return d, n, nil
}

// parseRecord appends one record to the schema being built. A record naming a table no
// `table` line introduced is an error rather than an implicit creation: the table line is
// what says the writer got that far.
func parseRecord(text string, schema *Schema, byName map[string]int) error {
	parts := strings.Split(text, "\t")
	kind := parts[0]
	want := positionalCount(kind)
	if len(parts) < 1+want {
		return fmt.Errorf("a %s record with %d fields, which is too few", kind, len(parts)-1)
	}

	names := make([]string, want)
	for i := 0; i < want; i++ {
		n, err := strconv.Unquote(parts[1+i])
		if err != nil {
			return fmt.Errorf("a %s record whose name %q is not a quoted string", kind, parts[1+i])
		}
		names[i] = n
	}
	fields, err := parseFields(parts[1+want:])
	if err != nil {
		return fmt.Errorf("a %s record: %w", kind, err)
	}

	if kind == "table" {
		if _, seen := byName[names[0]]; seen {
			return fmt.Errorf("table %q declared twice", names[0])
		}
		byName[names[0]] = len(*schema)
		*schema = append(*schema, TableEntry{Name: names[0]})
		return nil
	}

	pos, seen := byName[names[0]]
	if !seen {
		return fmt.Errorf("a %s record for table %q, which no table line introduced", kind, names[0])
	}
	shape := &(*schema)[pos].Table

	switch kind {
	case "column":
		nullable, err1 := fields.boolean("nullable")
		generated, err2 := fields.boolean("generated")
		hasDefault, err3 := fields.boolean("has_default")
		if err := firstError(err1, err2, err3); err != nil {
			return err
		}
		defaultName, err := fields.text("default_name")
		if err != nil {
			return err
		}
		typ, err1 := fields.text("type")
		def, err2 := fields.text("default")
		collation, err3 := fields.text("collation")
		if err := firstError(err1, err2, err3); err != nil {
			return err
		}
		shape.Columns = append(shape.Columns, ColumnShape{
			Name: names[1], Type: typ, Nullable: nullable, Default: def,
			HasDefault: hasDefault,
			Collation:  collation, DefaultName: defaultName,
			DefaultIsSystemNamed: defaultName == EngineNamedPlaceholder,
			Generated:            generated,
		})
	case "index":
		columns, err1 := fields.text("columns")
		origin, err2 := fields.text("origin")
		unique, err3 := fields.boolean("unique")
		if err := firstError(err1, err2, err3); err != nil {
			return err
		}
		if columns == "" {
			return fmt.Errorf("index %q on %q records no key columns", names[1], names[0])
		}
		switch IndexOrigin(origin) {
		case OriginCreated, OriginUnique, OriginPrimaryKey:
		default:
			return fmt.Errorf("index %q on %q records origin %q, which is none of c, u or pk", names[1], names[0], origin)
		}
		shape.Indexes = append(shape.Indexes, IndexShape{
			Name: names[1], Exists: true, Unique: unique,
			Columns: strings.Split(columns, ","), Origin: IndexOrigin(origin),
		})
	case "foreign_key":
		refTable, err1 := fields.text("ref_table")
		refColumn, err2 := fields.text("ref_column")
		onDelete, err3 := fields.text("on_delete")
		if err := firstError(err1, err2, err3); err != nil {
			return err
		}
		shape.ForeignKeys = append(shape.ForeignKeys, ForeignKeyShape{
			Column: names[1], RefTable: refTable, RefColumn: refColumn, OnDelete: onDelete,
		})
	default:
		return fmt.Errorf("record kind %q, which is none of table, column, index or foreign_key", kind)
	}
	return nil
}

// recordFields is one record's key=value part. Reading through it rather than positionally
// is what makes a record with a missing or misspelled field an error naming the field,
// instead of a shape silently carrying one value in another's place.
type recordFields map[string]string

func parseFields(parts []string) (recordFields, error) {
	fields := recordFields{}
	for _, p := range parts {
		key, value, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("field %q carries no =", p)
		}
		if _, dup := fields[key]; dup {
			return nil, fmt.Errorf("field %q given twice", key)
		}
		fields[key] = value
	}
	return fields, nil
}

func (f recordFields) text(key string) (string, error) {
	raw, ok := f[key]
	if !ok {
		return "", fmt.Errorf("no %s field", key)
	}
	v, err := strconv.Unquote(raw)
	if err != nil {
		return "", fmt.Errorf("the %s field %q is not a quoted string", key, raw)
	}
	return v, nil
}

func (f recordFields) boolean(key string) (bool, error) {
	raw, ok := f[key]
	if !ok {
		return false, fmt.Errorf("no %s field", key)
	}
	// Only the two spellings Encode writes. ParseBool would also take "1", "T" and "TRUE",
	// which nothing produces here and which would let a hand-edited file read as canonical.
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("the %s field is %q rather than true or false", key, raw)
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// GoldenPath is where one engine's golden file lives: beside that engine's migrations, at
// core/data/<engine>db/schema.golden, taking over the spot the hand-maintained schema.sql
// snapshot held until it was deleted (#284).
//
// The source root is found by ascending from the working directory rather than by counting
// "../" from a caller's package, because the two consumers sit at different depths and in
// different modules: the generator runs from src/core and the per-engine assertion from
// src/authserver/tests/data. A wrong root is not a loud failure, it names a file that is
// simply absent, so the ascent identifies the root by requiring every module to be under it.
// core/testutil.sourceRoot does the same walk for the gofmt guard; it is not shared because
// that one takes a *testing.T and fails a test, and this one has to answer a command.
func GoldenPath(d Dialect) (string, error) {
	if !d.valid() {
		return "", fmt.Errorf("schemadump: unrecognised database dialect %q", d)
	}
	root, err := SourceRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "core", "data", string(d)+"db", "schema.golden"), nil
}

// sourceRootModules are the four go.mod directories that identify the source root, the same
// four the Lint job loops over. Requiring all of them means a module added to the repository
// without being added here is a failure to find the root rather than a walk that lands
// somewhere plausible.
var sourceRootModules = []string{"core", "authserver", "adminconsole", filepath.Join("cmd", "goiabada-setup")}

// SourceRoot is the directory holding every Go module in the repository.
func SourceRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("schemadump: getting the working directory: %w", err)
	}
	for {
		if holdsEveryModule(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("schemadump: no directory above the working directory holds all of %s",
				strings.Join(sourceRootModules, ", "))
		}
		dir = parent
	}
}

func holdsEveryModule(dir string) bool {
	for _, m := range sourceRootModules {
		if _, err := os.Stat(filepath.Join(dir, m, "go.mod")); err != nil {
			return false
		}
	}
	return true
}
