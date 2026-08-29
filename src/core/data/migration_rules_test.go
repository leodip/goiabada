package data

// The four migration directories are written four times by hand, once per engine, and until
// #282 nothing compared the results. Diffing four fully migrated catalogs found five structural
// divergences that had been shipping for months, and #283 then found the same shape in
// collation: `=` over a string meant case-sensitive on two engines and case-insensitive on the
// other two, which RFC 6749 section 1.9 says is wrong. Every one of those was invisible in
// review and cheap to catch at the moment the file was written.
//
// This file is the machinery for catching them: a pure function over an in-memory
// engine -> filename -> contents tree, and the rules that are decidable from source text alone.
// migration_source_lint_test.go is the one place it is pointed at the four committed
// directories. The split is the one parity/golden makes for itself: the machinery has to be
// catchable with no real files at all, so every rule here has a synthetic tree that breaks it.
//
// WHAT THIS CANNOT DO, stated because it decides what a green run is worth. It cannot compare
// catalog SHAPE, whether the four migrated catalogs actually agree on columns, indexes,
// defaults and foreign keys. That needs four live databases and it is #284's, whose golden
// files and cross-engine allowlist are the authority. Green here is a floor (#288).

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/require"
)

// migrationDialects is every engine that must have a migrations directory. It is the same four
// names schemadump and parityDialects carry, so the lint, the dumper and the cross-engine
// comparison share one vocabulary and <dialect>db is always the directory.
var migrationDialects = []schemadump.Dialect{
	schemadump.MySQL, schemadump.Postgres, schemadump.MSSQL, schemadump.SQLite,
}

// migrationTree is a set of migration directories held in memory: one entry per engine, each
// mapping a filename to that file's whole contents. Every rule below reads one of these and
// nothing else, so a case can build the exact tree it wants to test without creating a file.
type migrationTree map[schemadump.Dialect]map[string]string

// migrationFinding is one rule broken in one place. Rule is the name a failure message groups
// by, Where is the file or the number the finding is about, and Say is the sentence a person
// reads.
type migrationFinding struct {
	Rule  string
	Where string
	Say   string
}

func (f migrationFinding) String() string {
	return fmt.Sprintf("%-18s %s: %s", f.Rule, f.Where, f.Say)
}

func joinMigrationFindings(findings []migrationFinding) string {
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, "  "+f.String())
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// The scanner
// ---------------------------------------------------------------------------

// sqlMark is one structural rune the scanner found at the top lexical level: outside a comment,
// outside a single-quoted literal and outside a quoted identifier. Depth is the parenthesis
// depth it sits at, which is what tells a top-level comma in a CREATE TABLE body apart from one
// inside a type's precision argument or inside a VALUES row.
//
// For '(' it is the depth BEFORE the parenthesis and for ')' the depth after it, so the two
// halves of one pair record the same number.
type sqlMark struct {
	Off   int
	Rune  byte
	Depth int
}

// identifierQuotes is how each engine quotes an identifier, measured off the four directories
// rather than assumed: [...] on SQL Server, backticks on MySQL and also on SQLite, which uses
// them 109 times for MySQL compatibility, and nothing at all on PostgreSQL, which quotes no
// identifier anywhere in the tree.
//
// A double quote would be an identifier quote on PostgreSQL and SQLite and a string delimiter on
// MySQL. It appears in no statement on any engine, and scanSQL refuses it rather than picking
// one of the two meanings.
func identifierQuotes(d schemadump.Dialect) (open, close byte) {
	switch d {
	case schemadump.MSSQL:
		return '[', ']'
	case schemadump.MySQL, schemadump.SQLite:
		return '`', '`'
	default:
		return 0, 0
	}
}

// scanSQL walks one migration file once and returns two things: the file with every comment byte
// blanked to a space, the same length as the input so every offset still names its own line, and
// one mark per ';', ',', '(' and ')' that sits at the top lexical level.
//
// WHY A SCANNER RATHER THAN A LINE MATCH. The rules have to be able to say where one statement
// or one column declaration ends, and a rule keyed to lines can refuse correct input: a ';' or a
// '--' inside a string literal would split or truncate a statement that is perfectly legal
// (decision 7). A gate whose failure mode is a false alarm on a legitimate migration is the
// wrong shape.
//
// FOUR FORMS ARE REFUSED rather than guessed at, each with zero occurrences in the tree today:
// a block comment, a '$' at the top level, which is how PostgreSQL opens a dollar-quoted body, a
// '"' anywhere at the top level for the reason identifierQuotes gives, and unbalanced state at
// end of file. A scanner that cannot say where the statements are must not be the reason a file
// reports clean, so it fails loudly and names the line.
func scanSQL(d schemadump.Dialect, text string) (string, []sqlMark, error) {
	idOpen, idClose := identifierQuotes(d)
	backslashEscapes := d == schemadump.MySQL

	clean := []byte(text)
	var marks []sqlMark
	depth := 0
	line := 1

	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == '-' && i+1 < len(text) && text[i+1] == '-':
			for i < len(text) && text[i] != '\n' {
				clean[i] = ' '
				i++
			}
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			return "", nil, fmt.Errorf("line %d: a /* block comment, which this scanner does not model; no migration uses one", line)
		case c == '"':
			return "", nil, fmt.Errorf("line %d: a double quote, which would be an identifier on postgres and sqlite and a string on mysql; no migration uses one", line)
		case c == '$':
			return "", nil, fmt.Errorf("line %d: a $ at the top level, which is how postgres opens a dollar-quoted body; this scanner does not model one and no migration uses one", line)
		case c == '\'':
			end, newlines, ok := skipQuoted(text, i, '\'', backslashEscapes)
			if !ok {
				return "", nil, fmt.Errorf("line %d: a single-quoted literal that is never closed", line)
			}
			line += newlines
			i = end
		case idOpen != 0 && c == idOpen:
			end, newlines, ok := skipQuoted(text, i, idClose, false)
			if !ok {
				return "", nil, fmt.Errorf("line %d: a %c quoted identifier that is never closed", line, idOpen)
			}
			line += newlines
			i = end
		case c == '(':
			marks = append(marks, sqlMark{Off: i, Rune: '(', Depth: depth})
			depth++
			i++
		case c == ')':
			depth--
			if depth < 0 {
				return "", nil, fmt.Errorf("line %d: a closing parenthesis with nothing open", line)
			}
			marks = append(marks, sqlMark{Off: i, Rune: ')', Depth: depth})
			i++
		case c == ';' || c == ',':
			marks = append(marks, sqlMark{Off: i, Rune: c, Depth: depth})
			i++
		default:
			i++
		}
	}
	if depth != 0 {
		return "", nil, fmt.Errorf("the file ends with %d parenthesis(es) still open", depth)
	}
	return string(clean), marks, nil
}

// skipQuoted walks a single-quoted literal or a quoted identifier from its opening delimiter and
// returns the offset just past the closing one, plus the newlines crossed.
//
// A delimiter is escaped by DOUBLING it, which every engine here accepts and which
// mssqldb/000029 spans two lines with: LIKE ”dcr!_%” ESCAPE ”!”'.
//
// A BACKSLASH escapes the next character inside a literal on MySQL alone, and that one is not
// academic. mysqldb/000034 writes a literal backslash as '\\' where mssqldb, postgresdb and
// sqlitedb all write '\'. Reading mssqldb/000034's CHARINDEX('\', [authority]) under MySQL's
// rules leaves the quote open, so the rest of a real file reads as string interior and a content
// rule reports nothing at all rather than reporting a violation.
func skipQuoted(text string, i int, close byte, backslashEscapes bool) (int, int, bool) {
	newlines := 0
	for j := i + 1; j < len(text); j++ {
		switch text[j] {
		case '\n':
			newlines++
		case '\\':
			if backslashEscapes && j+1 < len(text) {
				if text[j+1] == '\n' {
					newlines++
				}
				j++
			}
		case close:
			if j+1 < len(text) && text[j+1] == close {
				j++
				continue
			}
			return j + 1, newlines, true
		}
	}
	return 0, 0, false
}

// sqlStatement is one statement of a migration file, addressable on its own: its text with every
// comment already blanked, and the line it starts on.
type sqlStatement struct {
	Text  string
	Line  int
	clean string
	start int
	end   int
	marks []sqlMark
}

// sqlFragment is one top-level comma-separated unit of a CREATE TABLE or ALTER TABLE body: one
// column declaration, one table constraint, one ADD clause. It is the unit a content rule binds
// to, so a rule reports the column that is wrong rather than the file it is in.
type sqlFragment struct {
	Text string
	Line int
}

// splitStatements cuts the blanked text at every ';' that sits at parenthesis depth 0 outside a
// literal, an identifier and a comment.
//
// A trailing statement with no ';' is emitted rather than refused. golang-migrate sends the file
// to the driver as one batch and does not require the terminator, so refusing would be a false
// alarm on a legitimate migration; every file in the tree happens to end with one today.
func splitStatements(clean string, marks []sqlMark) []sqlStatement {
	var out []sqlStatement
	start, from := 0, 0
	for k, m := range marks {
		if m.Rune != ';' || m.Depth != 0 {
			continue
		}
		out = appendStatement(out, clean, start, m.Off, marks[from:k])
		start, from = m.Off+1, k+1
	}
	return appendStatement(out, clean, start, len(clean), marks[from:])
}

func appendStatement(out []sqlStatement, clean string, start, end int, marks []sqlMark) []sqlStatement {
	first, last := trimRange(clean, start, end)
	if first == last {
		return out
	}
	return append(out, sqlStatement{
		Text:  clean[first:last],
		Line:  lineAt(clean, first),
		clean: clean,
		start: first,
		end:   last,
		marks: marks,
	})
}

var (
	createTableRe = regexp.MustCompile(`(?is)^\s*create\s+table\b`)
	alterTableRe  = regexp.MustCompile(`(?is)^\s*alter\s+table\b`)
)

// declarations splits a CREATE TABLE or ALTER TABLE statement into the units a content rule
// binds to, and returns nil for any other statement.
//
// For a CREATE TABLE that is the first top-level (...) split at its depth-1 commas, so
// `varchar(256) COLLATE x` stays one declaration and a VALUES row inside a CHECK stays inside
// its own. For an ALTER TABLE it is the statement itself split at depth-0 commas, since
// `ALTER TABLE t ADD a INT, b INT` has no wrapping parenthesis.
//
// This is what closes the hole a file-wide match has: a second CREATE TABLE in a file whose
// first one spells its collation would otherwise pass without spelling its own (decision 7).
func (s sqlStatement) declarations() []sqlFragment {
	switch {
	case createTableRe.MatchString(s.Text):
		open, close := -1, -1
		for _, m := range s.marks {
			if m.Off < s.start || m.Off >= s.end {
				continue
			}
			if m.Rune == '(' && m.Depth == 0 && open < 0 {
				open = m.Off
			}
			if m.Rune == ')' && m.Depth == 0 && open >= 0 {
				close = m.Off
				break
			}
		}
		if open < 0 || close < 0 {
			return nil
		}
		return s.splitRange(open+1, close, 1)
	case alterTableRe.MatchString(s.Text):
		return s.splitRange(s.start, s.end, 0)
	}
	return nil
}

func (s sqlStatement) splitRange(from, to, depth int) []sqlFragment {
	var out []sqlFragment
	start := from
	for _, m := range s.marks {
		if m.Rune != ',' || m.Depth != depth || m.Off < from || m.Off >= to {
			continue
		}
		out = appendFragment(out, s.clean, start, m.Off)
		start = m.Off + 1
	}
	return appendFragment(out, s.clean, start, to)
}

func appendFragment(out []sqlFragment, clean string, start, end int) []sqlFragment {
	first, last := trimRange(clean, start, end)
	if first == last {
		return out
	}
	return append(out, sqlFragment{Text: clean[first:last], Line: lineAt(clean, first)})
}

func trimRange(s string, start, end int) (int, int) {
	for start < end && isSQLSpace(s[start]) {
		start++
	}
	for end > start && isSQLSpace(s[end-1]) {
		end--
	}
	return start, end
}

func isSQLSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func lineAt(s string, off int) int {
	return 1 + strings.Count(s[:off], "\n")
}

// ---------------------------------------------------------------------------
// Filenames
// ---------------------------------------------------------------------------

var (
	// migrationFileRe reads a filename the way golang-migrate's file source reads it. The
	// number is the LEADING INTEGER, not six digits, which is what keeps
	// sqlitedb/00001_initial_create counted as number 1. Dropping it instead makes number 1
	// read as absent on sqlite and appear as a phantom partial migration.
	migrationFileRe = regexp.MustCompile(`^(\d+)_(.+)\.(up|down)\.sql$`)

	// migrationNameRe is what a NEW file has to look like, which is stricter: six digits and a
	// lower_snake slug.
	migrationNameRe = regexp.MustCompile(`^\d{6}_[a-z0-9_]+\.(up|down)\.sql$`)
)

// migrationNameExempt is the one pair of files the naming rule excuses. SQLite's initial
// migration is five digits where every other engine's is six; golang-migrate parses the leading
// integer so it has always worked, and renaming it now would change a version already recorded
// in every deployment. Naming it here rather than relaxing the rule is what stops a new
// five-digit file landing beside it.
func migrationNameExempt(d schemadump.Dialect, name string) bool {
	return d == schemadump.SQLite &&
		(name == "00001_initial_create.up.sql" || name == "00001_initial_create.down.sql")
}

func parseMigrationFilename(name string) (num int, slug, half string, ok bool) {
	m := migrationFileRe.FindStringSubmatch(name)
	if m == nil {
		return 0, "", "", false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, "", "", false
	}
	return n, m[2], m[3], true
}

// ---------------------------------------------------------------------------
// One file, read
// ---------------------------------------------------------------------------

// migrationFile is one migration read and scanned once, so no rule re-parses what another rule
// already parsed and every rule sees the same statements.
type migrationFile struct {
	Dialect    schemadump.Dialect
	Name       string
	Number     int
	Slug       string
	Half       string
	Text       string
	Clean      string
	Statements []sqlStatement
	ScanErr    error
}

func (f migrationFile) Where() string { return string(f.Dialect) + "db/" + f.Name }

func readMigrationFiles(tree migrationTree) []migrationFile {
	var files []migrationFile
	for _, d := range sortedDialects(tree) {
		for _, name := range sortedFilenames(tree[d]) {
			f := migrationFile{Dialect: d, Name: name, Text: tree[d][name]}
			f.Number, f.Slug, f.Half, _ = parseMigrationFilename(name)
			clean, marks, err := scanSQL(d, f.Text)
			if err != nil {
				f.ScanErr = err
			} else {
				f.Clean = clean
				f.Statements = splitStatements(clean, marks)
			}
			files = append(files, f)
		}
	}
	return files
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

// migrationCutoffs is one grandfathering number per content rule, never a shared baseline
// (decision 3). A rule applies to every number STRICTLY ABOVE its cutoff; everything at or below
// is exempt, deliberately, because a shipped migration's DDL cannot be edited: golang-migrate
// records only (version, dirty) and no checksum, so changing an old file would make a fresh
// database differ from every existing one. Divergences are fixed by a NEW migration.
//
// One cutoff per rule rather than one for the tree. A shared number couples the rules: a rule
// added later whose violations reach higher forces it up, and every rule already there silently
// stops checking the migrations below. Per-rule, bare VARCHAR is checked from 000015 rather than
// from 000040.
//
// A CUTOFF NEVER ADVANCES WITH THE TREE. It moves only when a new rule is added that already
// shipped migrations would fail. Raising one to step over the migration being written right now
// exempts exactly the file the rule exists to check, which is the one way to use this that is
// worse than not running it, and TestMigrationCutoffs_AreTight is what refuses it: each number
// below is asserted to be a migration that really does break its rule.
type migrationCutoffs struct {
	MSSQLNVarchar     int
	MSSQLNamedDefault int
	MSSQLCollate      int
	MySQLCollation    int
}

// migrationCutoffsDefault is measured rather than chosen: the highest number each rule is
// actually violated at today (probe/rule_facts.out, #288 decision 3).
var migrationCutoffsDefault = migrationCutoffs{
	MSSQLNVarchar:     14,
	MSSQLNamedDefault: 18,
	MSSQLCollate:      38,
	MySQLCollation:    35,
}

// checkMigrationSource holds a migration tree to every rule decidable from its source text and
// returns what it finds, in a stable order. An empty result is the whole of a pass.
//
// The golden-version rule is not here, because it is the one rule that reads something other
// than the migrations: see checkGoldenVersion.
func checkMigrationSource(tree migrationTree) []migrationFinding {
	return checkMigrationSourceWith(tree, migrationCutoffsDefault)
}

// checkMigrationSourceWith is the same thing with the cutoffs supplied, which is what lets
// TestMigrationCutoffs_AreTight lower one by a single number and require the migration it names
// to break the rule.
func checkMigrationSourceWith(tree migrationTree, cutoffs migrationCutoffs) []migrationFinding {
	files := readMigrationFiles(tree)
	var findings []migrationFinding

	findings = append(findings, checkScannable(files)...)
	findings = append(findings, checkNaming(files)...)
	findings = append(findings, checkPairing(tree)...)
	findings = append(findings, checkNumberIdentity(files)...)
	findings = append(findings, checkCoverage(files)...)
	findings = append(findings, checkReversibility(files)...)
	findings = append(findings, checkMSSQLContent(files, cutoffs)...)
	findings = append(findings, checkMySQLContent(files, cutoffs)...)
	return findings
}

// checkScannable reports every file the scanner refused. It is a finding rather than a silent
// skip because the rules below all read the scanner's output, so a file it could not read is a
// file no rule has judged.
func checkScannable(files []migrationFile) []migrationFinding {
	var out []migrationFinding
	for _, f := range files {
		if f.ScanErr != nil {
			out = append(out, migrationFinding{"scanner", f.Where(), f.ScanErr.Error()})
		}
	}
	return out
}

func checkNaming(files []migrationFile) []migrationFinding {
	var out []migrationFinding
	for _, f := range files {
		if migrationNameExempt(f.Dialect, f.Name) || migrationNameRe.MatchString(f.Name) {
			continue
		}
		out = append(out, migrationFinding{"naming", f.Where(),
			"is not NNNNNN_lower_snake.{up,down}.sql, six digits and a lower_snake slug"})
	}
	return out
}

// checkPairing works off the filename stem rather than the parsed number and slug, so a number
// whose up and down disagree about the slug is reported as two unpaired halves rather than
// silently matched.
func checkPairing(tree migrationTree) []migrationFinding {
	var out []migrationFinding
	for _, d := range sortedDialects(tree) {
		ups, downs := map[string]bool{}, map[string]bool{}
		for _, name := range sortedFilenames(tree[d]) {
			switch {
			case strings.HasSuffix(name, ".up.sql"):
				ups[strings.TrimSuffix(name, ".up.sql")] = true
			case strings.HasSuffix(name, ".down.sql"):
				downs[strings.TrimSuffix(name, ".down.sql")] = true
			}
		}
		for _, stem := range sortedKeys(ups) {
			if !downs[stem] {
				out = append(out, migrationFinding{"pairing", string(d) + "db/" + stem + ".up.sql",
					"has no .down.sql"})
			}
		}
		for _, stem := range sortedKeys(downs) {
			if !ups[stem] {
				out = append(out, migrationFinding{"pairing", string(d) + "db/" + stem + ".down.sql",
					"has no .up.sql"})
			}
		}
	}
	return out
}

// migrationNumbers is the number index every cross-engine rule reads: number -> engine -> slug,
// built from the up migrations, which are the ones that define what a number means.
func migrationNumbers(files []migrationFile) map[int]map[schemadump.Dialect]string {
	numbers := map[int]map[schemadump.Dialect]string{}
	for _, f := range files {
		if f.Half != "up" {
			continue
		}
		if numbers[f.Number] == nil {
			numbers[f.Number] = map[schemadump.Dialect]string{}
		}
		numbers[f.Number][f.Dialect] = f.Slug
	}
	return numbers
}

// checkNumberIdentity refuses a number that names a different change per engine. A number is a
// version, recorded in schema_migrations and shared by the four engines, so one number meaning
// two changes is how an engine silently skips the one it did not get.
func checkNumberIdentity(files []migrationFile) []migrationFinding {
	numbers := migrationNumbers(files)
	var out []migrationFinding
	for _, num := range sortedNumbers(numbers) {
		slugs := map[string]bool{}
		for _, slug := range numbers[num] {
			slugs[slug] = true
		}
		if len(slugs) < 2 {
			continue
		}
		named := make([]string, 0, len(numbers[num]))
		for _, d := range migrationDialects {
			if slug, ok := numbers[num][d]; ok {
				named = append(named, string(d)+"="+slug)
			}
		}
		out = append(out, migrationFinding{"number identity", fmt.Sprintf("%06d", num),
			"names a different change per engine: " + strings.Join(named, ", ")})
	}
	return out
}

var (
	// parityDeclRe is the declaration a partial migration carries, per decision 5. It is read
	// from the raw text and then confirmed against the scanner's blanked output, because a rule
	// that matched the same words inside a string literal would accept a declaration that is
	// not a comment at all.
	parityDeclRe = regexp.MustCompile(`(?i)^[ \t]*--[ \t]*parity:[ \t]*(.*)$`)

	// parityGrammarRe is `<engines> only. <prose>`, the form all fourteen declarations in the
	// tree already spell. Prose is required: the engine list says which engines, and only the
	// prose says why.
	parityGrammarRe = regexp.MustCompile(`(?is)^(.+?)\s+only\.\s+(\S.*)$`)
)

// migrationParityDeclaration finds the `-- parity:` line in a migration and returns everything
// after the colon.
//
// The line is confirmed to be a real comment by checking that the scanner blanked it: comments
// are the only thing scanSQL replaces with spaces, so a line that is entirely whitespace in the
// clean text and not in the raw text is one.
func migrationParityDeclaration(f migrationFile) (rest string, line int, found bool) {
	off := 0
	for n, raw := range strings.Split(f.Text, "\n") {
		end := off + len(raw)
		m := parityDeclRe.FindStringSubmatch(raw)
		if m != nil && f.ScanErr == nil && strings.TrimSpace(f.Clean[off:end]) == "" {
			return strings.TrimSpace(m[1]), n + 1, true
		}
		off = end + 1
	}
	return "", 0, false
}

// parseParityEngines reads the engine list a declaration names: the names before the word
// `only`, separated by commas and by the word `and`. The vocabulary is the four dialect names
// and nothing else.
func parseParityEngines(list string) ([]schemadump.Dialect, string, bool) {
	var out []schemadump.Dialect
	for _, part := range strings.Split(strings.ReplaceAll(list, " and ", ","), ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			return nil, part, false
		}
		d := schemadump.Dialect(name)
		if !slicesContains(migrationDialects, d) {
			return nil, name, false
		}
		out = append(out, d)
	}
	return out, "", true
}

// checkCoverage is the rule that tells a deliberate levelling-up apart from three forgotten
// files. A migration landing on fewer than four engines is either correct, as #282's 000036 on
// sqlite alone was, or it is a mistake, and from the outside the two are the same thing. So a
// partial migration says which it is, in each carrying engine's own up.sql, and a complete one
// carries no such claim.
//
// The engine set is read rather than merely required to be present (decision 5), because these
// files are written by copying the neighbouring migration, whose declaration then names the
// engines THAT one landed on.
//
// It reads the up migrations only. A down migration restores what the up built, and where it
// carries a declaration of its own it is a courtesy to the reader rather than the claim this
// rule checks.
func checkCoverage(files []migrationFile) []migrationFinding {
	numbers := migrationNumbers(files)
	byKey := map[string]migrationFile{}
	for _, f := range files {
		if f.Half == "up" {
			byKey[fmt.Sprintf("%s/%d", f.Dialect, f.Number)] = f
		}
	}

	var out []migrationFinding
	for _, num := range sortedNumbers(numbers) {
		carrying := make([]schemadump.Dialect, 0, len(migrationDialects))
		absent := make([]string, 0, len(migrationDialects))
		for _, d := range migrationDialects {
			if _, ok := numbers[num][d]; ok {
				carrying = append(carrying, d)
			} else {
				absent = append(absent, string(d))
			}
		}
		complete := len(absent) == 0

		for _, d := range carrying {
			f := byKey[fmt.Sprintf("%s/%d", d, num)]
			rest, _, found := migrationParityDeclaration(f)

			if complete {
				if found {
					out = append(out, migrationFinding{"coverage", f.Where(),
						"declares a parity exception, but this number landed on all four engines"})
				}
				continue
			}
			if !found {
				out = append(out, migrationFinding{"coverage", f.Where(), fmt.Sprintf(
					"does not say why it is partial (absent on: %s); add a line reading "+
						"`-- parity: <engines> only. <why the others do not need it>`",
					strings.Join(absent, ", "))})
				continue
			}
			m := parityGrammarRe.FindStringSubmatch(rest)
			if m == nil {
				out = append(out, migrationFinding{"coverage", f.Where(),
					"declares `-- parity: " + rest + "`, which is not `<engines> only. <prose>`"})
				continue
			}
			declared, bad, ok := parseParityEngines(m[1])
			if !ok {
				out = append(out, migrationFinding{"coverage", f.Where(),
					"declares engine " + strconv.Quote(strings.TrimSpace(bad)) + ", which is none of the four"})
				continue
			}
			if !sameDialectSet(declared, carrying) {
				out = append(out, migrationFinding{"coverage", f.Where(), fmt.Sprintf(
					"declares %s, but %06d is carried by %s",
					joinDialects(declared), num, joinDialects(carrying))})
			}
		}
	}
	return out
}

// noopDownRe is the declaration a statement-free down migration carries. All twelve in the tree
// spell it exactly, and it names its own number so the line cannot be copied unchanged from a
// neighbour.
var noopDownRe = regexp.MustCompile(`(?im)^[ \t]*--[ \t]*migration\s+(\d+)\s+down:\s*intentional no-op\.`)

// checkReversibility refuses a down migration holding no statement that does not say it means
// it. A .down.sql with nothing in it is either deliberately irreversible, as the three one-way
// data migrations are, or a file somebody left empty, and only the author can tell you which.
func checkReversibility(files []migrationFile) []migrationFinding {
	var out []migrationFinding
	for _, f := range files {
		if f.Half != "down" || f.ScanErr != nil || len(f.Statements) > 0 {
			continue
		}
		declared := false
		for _, m := range noopDownRe.FindAllStringSubmatch(f.Text, -1) {
			if n, err := strconv.Atoi(m[1]); err == nil && n == f.Number {
				declared = true
			}
		}
		if !declared {
			out = append(out, migrationFinding{"reversibility", f.Where(), fmt.Sprintf(
				"holds no statement and does not declare itself one; write "+
					"`-- Migration %06d down: intentional no-op.` and say why the change is one-way",
				f.Number)})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The content rules
// ---------------------------------------------------------------------------
//
// WHAT THE CONTENT RULES CANNOT SEE, stated the way lint/credential states its own boundary,
// because it decides what a green run is worth. DDL inside a string literal is invisible: the
// scanner treats a literal's interior as opaque, so a column type built up inside an EXEC('...')
// is never read by any rule below. Measured, which is why the limit costs nothing today: all six
// EXEC literals in the tree wrap a DROP CONSTRAINT or an UPDATE and not one carries a column
// type. A migration that hides a column declaration in a literal defeats these rules, and the
// answer to that is #284's golden files, which read the catalog the DDL actually produced.
//
// They read .up.sql ONLY, and that is not an oversight. A down migration restores the shape that
// was there before, which is by definition the shape these rules reject: mssqldb/000038's down
// puts five VARCHAR columns back, correctly. Holding a down to the forward rules would make
// every reversible migration unwritable.

// The two collation pins. Both are decisions with reasoning attached rather than preferences:
// the MySQL one is #283 goal item 1, and the SQL Server one is its migration 000040, which
// explains why the KS_WS variant rather than the plain CS_AS form.
//
// TestMigrationPins_AreTheParityVocabulary holds both to being members of parityCollations with
// the value case-sensitive, so this lint and the cross-engine comparison in schema_parity_test.go
// share one vocabulary in one package: a typo in either place fails rather than quietly excusing
// a column.
const (
	migrationMySQLCollation = "utf8mb4_0900_as_cs"
	migrationMSSQLCollation = "Latin1_General_100_CS_AS_KS_WS_SC_UTF8"
)

var (
	// bareVarcharRe is VARCHAR( with no N in front of it. The leading class is what keeps
	// NVARCHAR( and [varchar] out: an identifier character or an opening bracket before the
	// word means it is not a bare declaration.
	bareVarcharRe = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_@#\[])varchar\s*\(`)

	// mssqlStringColumnRe is a string column being declared: a name, then a char type. The
	// three openings are the three places a declaration starts, once a statement has been split
	// into its top-level units: the head of a CREATE TABLE column, an ALTER COLUMN, and an ADD.
	mssqlStringColumnRe = regexp.MustCompile(`(?i)(?:^|\balter\s+column\s+|\badd\s+)\[?\w+\]?\s+n?(?:var)?char\s*\(`)

	// mssqlNotAColumnRe are the words that make a char( somewhere other than a declaration: a
	// cast inside a CHECK constraint, a variable, a computed column's expression.
	mssqlNotAColumnRe = regexp.MustCompile(`(?i)\b(declare|cast|convert|exec|sysname|select|where)\b`)

	// collateClauseRe reads a spelled collation. The optional = is MySQL's table-level form,
	// COLLATE=utf8mb4_0900_as_cs, which SQL Server never writes.
	collateClauseRe = regexp.MustCompile(`(?i)\bcollate\s*=?\s*(\w+)`)

	// addDefaultRe is a column or constraint being added with a default attached.
	addDefaultRe = regexp.MustCompile(`(?is)\badd\b.*\bdefault\b`)

	constraintWordRe = regexp.MustCompile(`(?i)\bconstraint\b`)
	alterColumnRe    = regexp.MustCompile(`(?i)\balter\s+column\b`)
	nullWordRe       = regexp.MustCompile(`(?i)\bnull\b`)
)

// contentFiles is the .up.sql files of one engine that the scanner could read, in filename
// order. A file the scanner refused is already a finding of its own (checkScannable), so
// skipping it here reports one problem rather than a cascade of nonsense from a mis-split file.
func contentFiles(files []migrationFile, d schemadump.Dialect) []migrationFile {
	var out []migrationFile
	for _, f := range files {
		if f.Dialect == d && f.Half == "up" && f.ScanErr == nil {
			out = append(out, f)
		}
	}
	return out
}

func at(f migrationFile, line int) string { return fmt.Sprintf("%s:%d", f.Where(), line) }

// checkMSSQLContent is the four SQL Server rules, each bound to ONE DECLARATION rather than to
// the statement or the file. That is the whole point of splitting a CREATE TABLE body: a rule
// asking whether the pin appears anywhere in the statement passes a table whose second string
// column spells no collation at all, because the first one did (decision 7).
func checkMSSQLContent(files []migrationFile, cutoffs migrationCutoffs) []migrationFinding {
	var out []migrationFinding
	for _, f := range contentFiles(files, schemadump.MSSQL) {
		for _, s := range f.Statements {
			for _, decl := range s.declarations() {
				// Every string column on SQL Server is NVARCHAR. Under a non-UTF-8 server
				// collation VARCHAR replaces anything outside the code page with '?', and
				// that loss is irreversible (#282 D4).
				if f.Number > cutoffs.MSSQLNVarchar && bareVarcharRe.MatchString(decl.Text) {
					out = append(out, migrationFinding{"mssql/nvarchar", at(f, decl.Line),
						"declares a bare VARCHAR, which loses anything outside the code page " +
							"under a non-UTF-8 server collation; every string column here is NVARCHAR: " +
							shorten(decl.Text)})
				}

				// NewMsSQLDatabase creates the database at the pinned collation, but creates
				// it IF NOT EXISTS, so a database an operator pre-created keeps their own
				// default and an unpinned column silently lands case-insensitive there. RFC
				// 6749 section 1.9 makes every protocol parameter value case-sensitive (#283).
				if f.Number > cutoffs.MSSQLCollate && isMSSQLStringColumn(decl.Text) {
					if m := collateClauseRe.FindStringSubmatch(decl.Text); m == nil {
						out = append(out, migrationFinding{"mssql/collate", at(f, decl.Line),
							"declares a string column that spells no COLLATE, so it inherits " +
								"whatever the database was created at; write COLLATE " +
								migrationMSSQLCollation + ": " + shorten(decl.Text)})
					} else if m[1] != migrationMSSQLCollation {
						out = append(out, migrationFinding{"mssql/collate", at(f, decl.Line),
							"declares COLLATE " + m[1] + ", but every string column here is " +
								migrationMSSQLCollation})
					}
				}

				// SQL Server generates a per-database name for an unnamed default, so a later
				// ALTER COLUMN cannot drop it by name and has to go looking in
				// sys.default_constraints, which is what mssqldb/000038 and 000040 both had to
				// do (#282 D4).
				if f.Number > cutoffs.MSSQLNamedDefault &&
					addDefaultRe.MatchString(decl.Text) && !constraintWordRe.MatchString(decl.Text) {
					out = append(out, migrationFinding{"mssql/named-default", at(f, decl.Line),
						"adds a DEFAULT with no CONSTRAINT name, so SQL Server invents a " +
							"per-database one that nothing can later drop by name; write " +
							"CONSTRAINT [df_<table>_<column>] DEFAULT: " + shorten(decl.Text)})
				}

				// ALTER COLUMN c <type> with no NULL keyword makes the column NULLABLE
				// whatever it was before, so a restated type silently drops NOT NULL. No
				// cutoff: the tree has never done it, including all 92 in 000040.
				if alterColumnRe.MatchString(decl.Text) && !nullWordRe.MatchString(decl.Text) {
					out = append(out, migrationFinding{"mssql/nullability", at(f, decl.Line),
						"restates a column's type without NULL or NOT NULL, which makes it " +
							"nullable whatever it was before: " + shorten(decl.Text)})
				}
			}
		}
	}
	return out
}

func isMSSQLStringColumn(text string) bool {
	return mssqlStringColumnRe.MatchString(text) && !mssqlNotAColumnRe.MatchString(text)
}

// checkMySQLContent is the one MySQL rule in its two forms, and the second form is why it binds
// to the statement rather than the file. MySQL runs at utf8mb4_0900_as_cs, case- and
// accent-SENSITIVE; the _ci and _ai forms fold, which makes `=` over a client_id or a scope
// answer the wrong question (RFC 6749 section 1.9). #283 found three tables at
// utf8mb4_unicode_ci and one at utf8mb4_0900_ai_ci, the last added in the most recent migration.
func checkMySQLContent(files []migrationFile, cutoffs migrationCutoffs) []migrationFinding {
	var out []migrationFinding
	for _, f := range contentFiles(files, schemadump.MySQL) {
		if f.Number <= cutoffs.MySQLCollation {
			continue
		}
		for _, s := range f.Statements {
			// Spelled, and spelled wrong. Read off the statement rather than the declaration
			// because MySQL's table-level clause sits after the closing parenthesis, outside
			// every declaration in the body.
			for _, m := range collateClauseRe.FindAllStringSubmatchIndex(s.Text, -1) {
				if name := s.Text[m[2]:m[3]]; name != migrationMySQLCollation {
					out = append(out, migrationFinding{"mysql/collation",
						at(f, lineAt(s.clean, s.start+m[0])),
						"names COLLATE " + name + ", which folds where " + migrationMySQLCollation +
							" does not; `=` over a client_id or a scope then answers the wrong question"})
				}
			}

			// Not spelled at all. ONE STATEMENT, not one file: a rule asking whether the pin
			// appears anywhere in the file passes a second CREATE TABLE that inherits the
			// database default, which is right today and silently wrong on any deployment
			// whose database was created before 000040 moved it.
			if createTableRe.MatchString(s.Text) &&
				!strings.Contains(strings.ToLower(s.Text), strings.ToLower(migrationMySQLCollation)) {
				out = append(out, migrationFinding{"mysql/collation", at(f, s.Line),
					"creates a table without spelling its collation, so it inherits the database " +
						"default; write ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=" +
						migrationMySQLCollation})
			}
		}
	}
	return out
}

// shorten keeps a finding's quoted fragment to one readable line. A declaration can span several
// lines and the point of quoting it is recognition, not reproduction.
func shorten(text string) string {
	flat := strings.Join(strings.Fields(text), " ")
	if len(flat) > 88 {
		return flat[:88] + "..."
	}
	return flat
}

// ---------------------------------------------------------------------------
// The golden file's migration version
// ---------------------------------------------------------------------------

// checkGoldenVersion holds each engine's committed schema.golden to the highest migration number
// on disk for that engine, which is #288's replacement for the git-diff rule the issue proposed
// (decision 2). It reads no git and no database, so it gives the same answer in CI, on the host,
// in a tarball and in a worktree, where a merge-base against main gives no answer at all on a
// shallow clone.
//
// It takes the recorded numbers rather than reading the files, so the rule is testable with no
// golden file anywhere; migration_source_lint_test.go parses the four committed ones and hands
// them over.
//
// ITS HONEST LIMIT: it catches a migration added without a regeneration, not a shipped migration
// edited in place, which would leave the version unmoved. That edit is forbidden anyway, and
// TestSchemaGolden_MatchesTheCommittedFile catches it on all four engines against a real database.
func checkGoldenVersion(tree migrationTree, recorded map[schemadump.Dialect]int) []migrationFinding {
	files := readMigrationFiles(tree)
	highest := map[schemadump.Dialect]int{}
	for _, f := range files {
		if f.Half == "up" && f.Number > highest[f.Dialect] {
			highest[f.Dialect] = f.Number
		}
	}

	var out []migrationFinding
	for _, d := range migrationDialects {
		where := string(d) + "db/schema.golden"
		got, ok := recorded[d]
		if !ok {
			out = append(out, migrationFinding{"golden version", where,
				"records no migration version, so nothing says which chain it was dumped from"})
			continue
		}
		if got != highest[d] {
			out = append(out, migrationFinding{"golden version", where, fmt.Sprintf(
				"was dumped at migration %d, but %sdb's highest migration is %06d; "+
					"regenerate all four with `cd src/core && go run ./cmd/schemadump` in the dev container",
				got, d, highest[d])})
		}
	}
	return out
}

// checkMigrationDirectories compares the migration directories that were discovered against the
// four dialects, IN BOTH DIRECTIONS.
//
// Both halves are load-bearing and they catch opposite mistakes. Requiring each of the four
// catches a directory that went missing, which is an engine whose migrations silently stopped
// being checked. Refusing a name that is not one of the four catches a directory that was ADDED,
// which iterating the four constants cannot see at all: a fifth engine would be skipped in
// silence, and skipping an engine in silence is the exact failure this rule exists to prevent.
func checkMigrationDirectories(found []string) []migrationFinding {
	want := map[string]bool{}
	for _, d := range migrationDialects {
		want[string(d)+"db"] = true
	}
	have := map[string]bool{}
	for _, name := range found {
		have[name] = true
	}

	var out []migrationFinding
	for _, name := range sortedKeys(have) {
		if !want[name] {
			out = append(out, migrationFinding{"directories", name,
				"holds migrations but is no engine schemadump names; add the dialect, or the rules will never read this directory"})
		}
	}
	for _, d := range migrationDialects {
		if !have[string(d)+"db"] {
			out = append(out, migrationFinding{"directories", string(d) + "db",
				"has no migrations directory, so nothing checks that engine's migrations at all"})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func sortedDialects(tree migrationTree) []schemadump.Dialect {
	out := make([]schemadump.Dialect, 0, len(tree))
	for d := range tree {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedFilenames(files map[string]string) []string {
	out := make([]string, 0, len(files))
	for name := range files {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func sortedNumbers(numbers map[int]map[schemadump.Dialect]string) []int {
	out := make([]int, 0, len(numbers))
	for n := range numbers {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func slicesContains(haystack []schemadump.Dialect, needle schemadump.Dialect) bool {
	for _, d := range haystack {
		if d == needle {
			return true
		}
	}
	return false
}

func sameDialectSet(a, b []schemadump.Dialect) bool {
	seen := map[schemadump.Dialect]bool{}
	for _, d := range a {
		seen[d] = true
	}
	if len(seen) != len(b) {
		return false
	}
	for _, d := range b {
		if !seen[d] {
			return false
		}
	}
	return true
}

func joinDialects(ds []schemadump.Dialect) string {
	names := make([]string, 0, len(ds))
	for _, d := range migrationDialects {
		if slicesContains(ds, d) {
			names = append(names, string(d))
		}
	}
	return strings.Join(names, ", ")
}

// ---------------------------------------------------------------------------
// The scanner's cases
// ---------------------------------------------------------------------------

// TestMigrationScanner_ReadsTheLexicalFormsTheTreeUses is the machinery's own table. Every case
// is a form measured off the four committed directories, and every refusal is a form none of
// them carries, so a case that stops matching is a real change in how migrations are written.
func TestMigrationScanner_ReadsTheLexicalFormsTheTreeUses(t *testing.T) {
	tests := []struct {
		name     string
		dialect  schemadump.Dialect
		text     string
		want     []string
		refuseOn string
	}{
		{
			name:    "a semicolon inside a literal does not split",
			dialect: schemadump.SQLite,
			text:    "UPDATE t SET a = 'x;y';\nUPDATE t SET b = 1;",
			want:    []string{"UPDATE t SET a = 'x;y'", "UPDATE t SET b = 1"},
		},
		{
			name:    "a double dash inside a literal does not strip",
			dialect: schemadump.SQLite,
			text:    "UPDATE t SET a = 'x--y';",
			want:    []string{"UPDATE t SET a = 'x--y'"},
		},
		{
			name:    "a semicolon inside a quoted identifier does not split",
			dialect: schemadump.MSSQL,
			text:    "ALTER TABLE [we;ird] ADD [a] INT;\nALTER TABLE [b] ADD [c] INT;",
			want:    []string{"ALTER TABLE [we;ird] ADD [a] INT", "ALTER TABLE [b] ADD [c] INT"},
		},
		{
			name:    "a double dash inside a quoted identifier does not strip",
			dialect: schemadump.MySQL,
			text:    "ALTER TABLE `we--ird` ADD `a` INT;",
			want:    []string{"ALTER TABLE `we--ird` ADD `a` INT"},
		},
		{
			name:    "a comment is blanked and the statement around it survives",
			dialect: schemadump.Postgres,
			text:    "-- a leading comment\nALTER TABLE t ADD a INT; -- trailing\nALTER TABLE t ADD b INT;",
			want:    []string{"ALTER TABLE t ADD a INT", "ALTER TABLE t ADD b INT"},
		},
		{
			// mssqldb/000029 spells this over two lines.
			name:    "a doubled quote escapes and the literal spans two lines",
			dialect: schemadump.MSSQL,
			text:    "EXEC('UPDATE [c] SET [x] = 1\n WHERE [i] LIKE ''dcr!_%'' ESCAPE ''!''');\nALTER TABLE [t] ADD [a] INT;",
			want: []string{
				"EXEC('UPDATE [c] SET [x] = 1\n WHERE [i] LIKE ''dcr!_%'' ESCAPE ''!''')",
				"ALTER TABLE [t] ADD [a] INT",
			},
		},
		{
			// mssqldb/000034 line 114. A backslash is an ordinary character here.
			name:    "a lone backslash in a literal closes normally off mysql",
			dialect: schemadump.MSSQL,
			text:    "UPDATE [w] SET [x] = 1 WHERE CHARINDEX('\\', [authority]) > 0;\nALTER TABLE [t] ADD [a] INT;",
			want: []string{
				"UPDATE [w] SET [x] = 1 WHERE CHARINDEX('\\', [authority]) > 0",
				"ALTER TABLE [t] ADD [a] INT",
			},
		},
		{
			// mysqldb/000034 line 89, which has to double it for exactly this reason.
			name:    "a doubled backslash in a literal closes normally on mysql",
			dialect: schemadump.MySQL,
			text:    "UPDATE `w` SET `x` = 1 WHERE INSTR(`authority`, '\\\\') > 0;\nALTER TABLE `t` ADD `a` INT;",
			want: []string{
				"UPDATE `w` SET `x` = 1 WHERE INSTR(`authority`, '\\\\') > 0",
				"ALTER TABLE `t` ADD `a` INT",
			},
		},
		{
			// The same bytes mssql writes, read under mysql's rules: the backslash escapes the
			// closing quote, the literal never ends, and the file is refused rather than read
			// as a statement whose tail is string interior.
			name:     "mysql refuses the lone backslash form, which is why 000034 doubles it",
			dialect:  schemadump.MySQL,
			text:     "UPDATE `w` SET `x` = 1 WHERE INSTR(`authority`, '\\') > 0;\n",
			refuseOn: "never closed",
		},
		{
			name:     "a block comment is refused",
			dialect:  schemadump.Postgres,
			text:     "ALTER TABLE t ADD a INT;\n/* not modelled */\n",
			refuseOn: "block comment",
		},
		{
			name:     "a double quote is refused",
			dialect:  schemadump.Postgres,
			text:     "ALTER TABLE \"users\" ADD a INT;\n",
			refuseOn: "double quote",
		},
		{
			name:     "a dollar sign at the top level is refused",
			dialect:  schemadump.Postgres,
			text:     "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END $$;\n",
			refuseOn: "dollar-quoted",
		},
		{
			name:     "an unterminated literal is refused",
			dialect:  schemadump.SQLite,
			text:     "UPDATE t SET a = 'never closed;\n",
			refuseOn: "never closed",
		},
		{
			name:     "an unterminated quoted identifier is refused",
			dialect:  schemadump.MSSQL,
			text:     "ALTER TABLE [never closed ADD a INT;\n",
			refuseOn: "never closed",
		},
		{
			name:     "an unbalanced parenthesis is refused",
			dialect:  schemadump.SQLite,
			text:     "CREATE TABLE t (\n  id integer\n;\n",
			refuseOn: "still open",
		},
		{
			name:     "a closing parenthesis with nothing open is refused",
			dialect:  schemadump.SQLite,
			text:     "CREATE TABLE t id integer);\n",
			refuseOn: "nothing open",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clean, marks, err := scanSQL(tt.dialect, tt.text)
			if tt.refuseOn != "" {
				require.Error(t, err, "this form has to be refused, not guessed at")
				require.Contains(t, err.Error(), tt.refuseOn)
				return
			}
			require.NoError(t, err)
			require.Len(t, clean, len(tt.text), "the blanked text keeps every offset")

			got := make([]string, 0, len(tt.want))
			for _, s := range splitStatements(clean, marks) {
				got = append(got, s.Text)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// TestMigrationScanner_SplitsDeclarationsAtTheTopLevelOnly is the unit a stage-4 content rule
// binds to: one column rather than one file. The nested cases are the ones a naive comma split
// gets wrong, and both shapes are in the tree.
func TestMigrationScanner_SplitsDeclarationsAtTheTopLevelOnly(t *testing.T) {
	tests := []struct {
		name    string
		dialect schemadump.Dialect
		text    string
		want    []string
	}{
		{
			name:    "a create table body splits at its top-level commas",
			dialect: schemadump.MSSQL,
			text:    "CREATE TABLE [t] (\n  [id] BIGINT NOT NULL,\n  [a] NVARCHAR(64) COLLATE X NOT NULL,\n  PRIMARY KEY ([id])\n);",
			want: []string{
				"[id] BIGINT NOT NULL",
				"[a] NVARCHAR(64) COLLATE X NOT NULL",
				"PRIMARY KEY ([id])",
			},
		},
		{
			name:    "a comma inside a precision argument does not split",
			dialect: schemadump.MySQL,
			text:    "CREATE TABLE `t` (\n  `id` bigint NOT NULL,\n  `amount` decimal(10,2) NOT NULL\n) ENGINE=InnoDB;",
			want:    []string{"`id` bigint NOT NULL", "`amount` decimal(10,2) NOT NULL"},
		},
		{
			name:    "a comma inside a literal does not split",
			dialect: schemadump.SQLite,
			text:    "CREATE TABLE t (\n  a text NOT NULL DEFAULT 'x,y',\n  b text\n);",
			want:    []string{"a text NOT NULL DEFAULT 'x,y'", "b text"},
		},
		{
			name:    "an alter table splits at depth zero",
			dialect: schemadump.MySQL,
			text:    "ALTER TABLE `t` ADD `a` int NOT NULL, ADD `b` decimal(10,2) NULL;",
			want:    []string{"ALTER TABLE `t` ADD `a` int NOT NULL", "ADD `b` decimal(10,2) NULL"},
		},
		{
			name:    "anything else has no declarations",
			dialect: schemadump.SQLite,
			text:    "UPDATE t SET a = 1, b = 2;",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clean, marks, err := scanSQL(tt.dialect, tt.text)
			require.NoError(t, err)

			statements := splitStatements(clean, marks)
			require.Len(t, statements, 1)

			var got []string
			for _, f := range statements[0].declarations() {
				got = append(got, f.Text)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// The rules' cases
// ---------------------------------------------------------------------------

// migrationTreeFixture is a four-engine tree that every rule passes. Each case below changes
// exactly one thing in it, so a case cannot pass with the rule it names deleted: it differs from
// a green tree in the thing under test and in nothing else.
func migrationTreeFixture() migrationTree {
	create := func(d schemadump.Dialect) string {
		switch d {
		case schemadump.MSSQL:
			return "CREATE TABLE [widgets] (\n  [id] BIGINT NOT NULL\n);\n"
		case schemadump.MySQL:
			return "CREATE TABLE `widgets` (\n  `id` bigint NOT NULL\n);\n"
		default:
			return "CREATE TABLE widgets (\n  id bigint NOT NULL\n);\n"
		}
	}
	tree := migrationTree{}
	for _, d := range migrationDialects {
		tree[d] = map[string]string{
			"000001_initial_create.up.sql":   create(d),
			"000001_initial_create.down.sql": "DROP TABLE widgets;\n",
		}
	}
	return tree
}

func TestMigrationRules_AcceptAGreenTreeAndRefuseOneBrokenThing(t *testing.T) {
	tests := []struct {
		name string
		// break mutates the fixture in exactly one way. A nil break is the accepting twin.
		breaks   func(migrationTree)
		wantRule string
		wantSay  string
	}{
		{
			name: "the fixture itself passes every rule",
		},

		// naming
		{
			// Both halves, so the only thing that differs from the fixture is the digit
			// count: renaming one half alone would break pairing too and the case would pass
			// with the naming rule deleted.
			name: "a five-digit name is refused",
			breaks: func(tr migrationTree) {
				rename(tr, schemadump.Postgres, "000001_initial_create.up.sql", "00001_initial_create.up.sql")
				rename(tr, schemadump.Postgres, "000001_initial_create.down.sql", "00001_initial_create.down.sql")
			},
			wantRule: "naming",
			wantSay:  "six digits",
		},
		{
			name: "sqlite's own five-digit pair is the one exemption",
			breaks: func(tr migrationTree) {
				rename(tr, schemadump.SQLite, "000001_initial_create.up.sql", "00001_initial_create.up.sql")
				rename(tr, schemadump.SQLite, "000001_initial_create.down.sql", "00001_initial_create.down.sql")
			},
		},
		{
			// On all four engines, so the slug still agrees across them: renaming one
			// engine's pair would break number identity too.
			name: "an upper-case slug is refused",
			breaks: func(tr migrationTree) {
				for _, d := range migrationDialects {
					rename(tr, d, "000001_initial_create.up.sql", "000001_Initial_Create.up.sql")
					rename(tr, d, "000001_initial_create.down.sql", "000001_Initial_Create.down.sql")
				}
			},
			wantRule: "naming",
			wantSay:  "lower_snake",
		},

		// pairing
		{
			name: "an up with no down is refused",
			breaks: func(tr migrationTree) {
				delete(tr[schemadump.MySQL], "000001_initial_create.down.sql")
			},
			wantRule: "pairing",
			wantSay:  "has no .down.sql",
		},
		{
			name: "a down with no up is refused",
			breaks: func(tr migrationTree) {
				tr[schemadump.MySQL]["000002_orphan.down.sql"] = "-- Migration 000002 down: intentional no-op.\n"
			},
			wantRule: "pairing",
			wantSay:  "has no .up.sql",
		},

		// number identity
		{
			name: "one number naming two changes is refused",
			breaks: func(tr migrationTree) {
				rename(tr, schemadump.MSSQL, "000001_initial_create.up.sql", "000001_initial_setup.up.sql")
				rename(tr, schemadump.MSSQL, "000001_initial_create.down.sql", "000001_initial_setup.down.sql")
			},
			wantRule: "number identity",
			wantSay:  "names a different change per engine",
		},

		// coverage
		{
			name: "a partial migration with no declaration is refused",
			breaks: func(tr migrationTree) {
				addMigration(tr, schemadump.SQLite, "000002_add_gadgets", "ALTER TABLE widgets ADD gadgets int;\n")
			},
			wantRule: "coverage",
			wantSay:  "does not say why it is partial",
		},
		{
			name: "a partial migration that declares itself passes",
			breaks: func(tr migrationTree) {
				addMigration(tr, schemadump.SQLite, "000002_add_gadgets",
					"-- parity: sqlite only. The other three already carry the column.\n"+
						"ALTER TABLE widgets ADD gadgets int;\n")
			},
		},
		{
			name: "a declaration naming the wrong engine set is refused",
			breaks: func(tr migrationTree) {
				addMigration(tr, schemadump.SQLite, "000002_add_gadgets",
					"-- parity: mysql only. The other three already carry the column.\n"+
						"ALTER TABLE widgets ADD gadgets int;\n")
			},
			wantRule: "coverage",
			wantSay:  "declares mysql, but 000002 is carried by sqlite",
		},
		{
			name: "a two-engine declaration reads `and` as a separator",
			breaks: func(tr migrationTree) {
				body := "-- parity: mysql and sqlite only. Postgres and SQL Server were written later.\n" +
					"ALTER TABLE widgets ADD gadgets int;\n"
				addMigration(tr, schemadump.SQLite, "000002_add_gadgets", body)
				addMigration(tr, schemadump.MySQL, "000002_add_gadgets", body)
			},
		},
		{
			name: "a declaration with no prose is refused",
			breaks: func(tr migrationTree) {
				addMigration(tr, schemadump.SQLite, "000002_add_gadgets",
					"-- parity: sqlite only.\nALTER TABLE widgets ADD gadgets int;\n")
			},
			wantRule: "coverage",
			wantSay:  "is not `<engines> only. <prose>`",
		},
		{
			name: "a declaration naming an engine that does not exist is refused",
			breaks: func(tr migrationTree) {
				addMigration(tr, schemadump.SQLite, "000002_add_gadgets",
					"-- parity: oracle only. Nothing else needs it.\nALTER TABLE widgets ADD gadgets int;\n")
			},
			wantRule: "coverage",
			wantSay:  "which is none of the four",
		},
		{
			name: "a declaration on a complete migration is refused",
			breaks: func(tr migrationTree) {
				for _, d := range migrationDialects {
					body := tr[d]["000001_initial_create.up.sql"]
					tr[d]["000001_initial_create.up.sql"] =
						"-- parity: sqlite only. Copied from the neighbour by mistake.\n" + body
				}
			},
			wantRule: "coverage",
			wantSay:  "landed on all four engines",
		},
		{
			name: "the same words inside a literal are not a declaration",
			breaks: func(tr migrationTree) {
				addMigration(tr, schemadump.SQLite, "000002_add_gadgets",
					"UPDATE widgets SET note = '-- parity: sqlite only. Not a comment.';\n")
			},
			wantRule: "coverage",
			wantSay:  "does not say why it is partial",
		},

		// reversibility
		{
			name: "a statement-free down with no declaration is refused",
			breaks: func(tr migrationTree) {
				tr[schemadump.Postgres]["000001_initial_create.down.sql"] = "-- nothing to do here\n"
			},
			wantRule: "reversibility",
			wantSay:  "holds no statement and does not declare itself one",
		},
		{
			name: "a statement-free down that declares itself passes",
			breaks: func(tr migrationTree) {
				tr[schemadump.Postgres]["000001_initial_create.down.sql"] =
					"-- Migration 000001 down: intentional no-op.\n--\n-- The change is one-way.\n"
			},
		},
		{
			name: "a declaration naming another migration's number is refused",
			breaks: func(tr migrationTree) {
				tr[schemadump.Postgres]["000001_initial_create.down.sql"] =
					"-- Migration 000033 down: intentional no-op.\n"
			},
			wantRule: "reversibility",
			wantSay:  "holds no statement and does not declare itself one",
		},

		// the scanner, reached through the rules
		{
			name: "a file the scanner refuses is a finding rather than a silent pass",
			breaks: func(tr migrationTree) {
				tr[schemadump.Postgres]["000001_initial_create.up.sql"] = "CREATE TABLE \"widgets\" (id bigint);\n"
			},
			wantRule: "scanner",
			wantSay:  "double quote",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := migrationTreeFixture()
			if tt.breaks != nil {
				tt.breaks(tree)
			}
			findings := checkMigrationSource(tree)

			if tt.wantRule == "" {
				require.Emptyf(t, findings, "this tree is meant to pass every rule:\n%s",
					joinMigrationFindings(findings))
				return
			}
			require.NotEmpty(t, findings, "this tree breaks %s and nothing reported it", tt.wantRule)
			for _, f := range findings {
				require.Equalf(t, tt.wantRule, f.Rule,
					"only %s should fire here, but:\n%s", tt.wantRule, joinMigrationFindings(findings))
			}
			require.Containsf(t, findings[0].Say, tt.wantSay,
				"reported:\n%s", joinMigrationFindings(findings))
		})
	}
}

func rename(tr migrationTree, d schemadump.Dialect, from, to string) {
	tr[d][to] = tr[d][from]
	delete(tr[d], from)
}

func addMigration(tr migrationTree, d schemadump.Dialect, stem, up string) {
	tr[d][stem+".up.sql"] = up
	num, _, _, _ := parseMigrationFilename(stem + ".up.sql")
	tr[d][stem+".down.sql"] = fmt.Sprintf("-- Migration %06d down: intentional no-op.\n-- One-way.\n", num)
}

// TestMigrationDirectories_ComparedInBothDirections is the half of §4's promise that iterating
// four constants cannot buy. The added directory is the case that matters: a rule written as a
// loop over the four dialects passes it while never reading a line of the fifth engine.
func TestMigrationDirectories_ComparedInBothDirections(t *testing.T) {
	all := []string{"mssqldb", "mysqldb", "postgresdb", "sqlitedb"}

	tests := []struct {
		name    string
		found   []string
		wantSay string
	}{
		{
			name:  "the four directories the tree has",
			found: all,
		},
		{
			name:    "a fifth engine's directory is refused by name",
			found:   append(append([]string{}, all...), "oracledb"),
			wantSay: "is no engine schemadump names",
		},
		{
			name:    "a missing directory is refused",
			found:   []string{"mssqldb", "mysqldb", "sqlitedb"},
			wantSay: "has no migrations directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := checkMigrationDirectories(tt.found)
			if tt.wantSay == "" {
				require.Emptyf(t, findings, "reported:\n%s", joinMigrationFindings(findings))
				return
			}
			require.Len(t, findings, 1, "reported:\n%s", joinMigrationFindings(findings))
			require.Contains(t, findings[0].Say, tt.wantSay)
		})
	}
}

// ---------------------------------------------------------------------------
// The content rules' cases
// ---------------------------------------------------------------------------

// TestMigrationPins_AreTheParityVocabulary is the join between this lint and the cross-engine
// comparison in schema_parity_test.go. They are one package on purpose: the lint says a column
// must SPELL these two names, the comparison says what those names DECIDE, and a typo in either
// place would otherwise pass, the lint excusing a column and the comparison never seeing it.
func TestMigrationPins_AreTheParityVocabulary(t *testing.T) {
	for _, pin := range []string{migrationMySQLCollation, migrationMSSQLCollation} {
		decides, ok := parityCollations[pin]
		require.Truef(t, ok, "the lint pins %q, which the parity vocabulary does not carry: "+
			"one of the two has been changed without the other", pin)
		require.Equalf(t, "case-sensitive", decides,
			"the lint pins %q, but parity says it decides %q. RFC 6749 section 1.9 makes every "+
				"protocol parameter value case-sensitive and OIDC Core section 2 says the same of "+
				"sub, so a folding collation is the defect #283 fixed.", pin, decides)
	}
}

// The green bodies every content case starts from. They are built out of the pin constants
// rather than spelling the names again, so moving a pin moves the fixture with it instead of
// turning every accepting case into a silent violation.
func greenMSSQLGadgets() string {
	return "CREATE TABLE [gadgets] (\n" +
		"  [id] BIGINT NOT NULL,\n" +
		"  [name] NVARCHAR(64) COLLATE " + migrationMSSQLCollation + " NOT NULL,\n" +
		"  [label] NVARCHAR(32) COLLATE " + migrationMSSQLCollation + " NULL\n" +
		");\n" +
		"ALTER TABLE [widgets] ADD [note] NVARCHAR(16) COLLATE " + migrationMSSQLCollation +
		" NOT NULL CONSTRAINT [df_widgets_note] DEFAULT '';\n" +
		"ALTER TABLE [widgets] ALTER COLUMN [id] BIGINT NOT NULL;\n"
}

// Two tables, so a rule that reads the file rather than the statement can be caught: the mixed
// case below leaves the first one spelling the pin and takes it off the second.
func greenMySQLGadgets() string {
	return "CREATE TABLE gadgets (\n" +
		"  id bigint NOT NULL,\n" +
		"  name varchar(64) NOT NULL\n" +
		") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=" + migrationMySQLCollation + ";\n" +
		"CREATE TABLE doodads (\n" +
		"  id bigint NOT NULL\n" +
		") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=" + migrationMySQLCollation + ";\n"
}

// migrationContentFixture is the green tree plus one migration at `num` on all four engines, so
// the number is complete and coverage stays quiet whatever a content case does to the text.
// PostgreSQL and SQLite carry no content rule and get the plain body.
func migrationContentFixture(num int) migrationTree {
	tree := migrationTreeFixture()
	stem := fmt.Sprintf("%06d_add_gadgets", num)
	for _, d := range migrationDialects {
		body := "CREATE TABLE gadgets (\n  id bigint NOT NULL\n);\n"
		switch d {
		case schemadump.MSSQL:
			body = greenMSSQLGadgets()
		case schemadump.MySQL:
			body = greenMySQLGadgets()
		}
		tree[d][stem+".up.sql"] = body
		tree[d][stem+".down.sql"] = "DROP TABLE gadgets;\n"
	}
	return tree
}

// editUp rewrites one span of one up migration. It panics when the span is gone, because a case
// whose anchor no longer matches would otherwise stop testing anything and keep passing: it
// would be running the green fixture under a name that claims a violation.
func editUp(tr migrationTree, d schemadump.Dialect, num int, from, to string) {
	name := fmt.Sprintf("%06d_add_gadgets.up.sql", num)
	body, ok := tr[d][name]
	if !ok {
		panic("migration content fixture has no " + string(d) + "db/" + name)
	}
	if !strings.Contains(body, from) {
		panic("migration content fixture no longer holds " + strconv.Quote(from) + " in " +
			string(d) + "db/" + name + "; the case that edits it is testing nothing")
	}
	tr[d][name] = strings.Replace(body, from, to, 1)
}

// TestMigrationContentRules_BindToOneColumnOrOneTable is seam 1's half of the content rules:
// every rule against a synthetic tree that breaks it, and every case differing from the green
// fixture in exactly the thing under test, so none of them can pass with its rule deleted.
//
// The two MIXED cases are the ones a wider check passes, and they are the reason the rules bind
// to a declaration and a statement rather than to a file (decision 7): one leaves the first
// string column of a CREATE TABLE spelling the pin and takes it off the second, and one leaves
// the first of two CREATE TABLEs spelling it and takes it off the second.
func TestMigrationContentRules_BindToOneColumnOrOneTable(t *testing.T) {
	const wrongMSSQL = "Latin1_General_CI_AS"
	const wrongMySQL = "utf8mb4_0900_ai_ci"

	tests := []struct {
		name     string
		breaks   func(migrationTree)
		wantRule string
		wantSay  string
	}{
		{
			name: "the content fixture itself passes every rule",
		},

		// mssql/nvarchar
		{
			name: "a bare VARCHAR is refused",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50, "[name] NVARCHAR(64)", "[name] VARCHAR(64)")
			},
			wantRule: "mssql/nvarchar",
			wantSay:  "declares a bare VARCHAR",
		},
		{
			name: "NVARCHAR is not read as a bare VARCHAR",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50, "[name] NVARCHAR(64)", "[name] NVARCHAR(128)")
			},
		},

		// mssql/collate
		{
			name: "the second string column of a table cannot ride on the first one's COLLATE",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50,
					"[label] NVARCHAR(32) COLLATE "+migrationMSSQLCollation+" NULL",
					"[label] NVARCHAR(32) NULL")
			},
			wantRule: "mssql/collate",
			wantSay:  "spells no COLLATE",
		},
		{
			name: "a string column pinned to a folding collation is refused",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50,
					"[label] NVARCHAR(32) COLLATE "+migrationMSSQLCollation,
					"[label] NVARCHAR(32) COLLATE "+wrongMSSQL)
			},
			wantRule: "mssql/collate",
			wantSay:  "declares COLLATE " + wrongMSSQL,
		},
		{
			name: "a non-string column is not asked for a collation",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50, "[id] BIGINT NOT NULL,", "[id] INT NOT NULL,")
			},
		},

		// mssql/named-default
		{
			name: "an unnamed default constraint is refused",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50, "CONSTRAINT [df_widgets_note] DEFAULT", "DEFAULT")
			},
			wantRule: "mssql/named-default",
			wantSay:  "no CONSTRAINT name",
		},

		// mssql/nullability
		{
			name: "an ALTER COLUMN that restates the type and drops NOT NULL is refused",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50,
					"ALTER COLUMN [id] BIGINT NOT NULL", "ALTER COLUMN [id] BIGINT")
			},
			wantRule: "mssql/nullability",
			wantSay:  "without NULL or NOT NULL",
		},
		{
			name: "an ALTER COLUMN that says NULL out loud passes",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MSSQL, 50,
					"ALTER COLUMN [id] BIGINT NOT NULL", "ALTER COLUMN [id] BIGINT NULL")
			},
		},

		// mysql/collation
		{
			name: "the second CREATE TABLE in a file cannot ride on the first one's collation",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MySQL, 50,
					"  id bigint NOT NULL\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE="+
						migrationMySQLCollation+";",
					"  id bigint NOT NULL\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;")
			},
			wantRule: "mysql/collation",
			wantSay:  "creates a table without spelling its collation",
		},
		{
			name: "a column pinned to a folding collation is refused even where the table is right",
			breaks: func(tr migrationTree) {
				editUp(tr, schemadump.MySQL, 50, "name varchar(64) NOT NULL",
					"name varchar(64) COLLATE "+wrongMySQL+" NOT NULL")
			},
			wantRule: "mysql/collation",
			wantSay:  "names COLLATE " + wrongMySQL,
		},

		// engines with no content rule
		{
			name: "postgres and sqlite carry no content rule",
			breaks: func(tr migrationTree) {
				for _, d := range []schemadump.Dialect{schemadump.Postgres, schemadump.SQLite} {
					editUp(tr, d, 50, "id bigint NOT NULL", "id bigint NOT NULL,\n  name varchar(64) NOT NULL")
				}
			},
		},

		// the down halves are never judged by a content rule
		{
			name: "a down migration restoring the rejected shape is not a violation",
			breaks: func(tr migrationTree) {
				tr[schemadump.MSSQL]["000050_add_gadgets.down.sql"] =
					"ALTER TABLE [widgets] ALTER COLUMN [note] VARCHAR(16);\nDROP TABLE [gadgets];\n"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := migrationContentFixture(50)
			if tt.breaks != nil {
				tt.breaks(tree)
			}
			findings := checkMigrationSource(tree)

			if tt.wantRule == "" {
				require.Emptyf(t, findings, "this tree is meant to pass every rule:\n%s",
					joinMigrationFindings(findings))
				return
			}
			require.NotEmpty(t, findings, "this tree breaks %s and nothing reported it", tt.wantRule)
			for _, f := range findings {
				require.Equalf(t, tt.wantRule, f.Rule,
					"only %s should fire here, but:\n%s", tt.wantRule, joinMigrationFindings(findings))
			}
			require.Containsf(t, findings[0].Say, tt.wantSay,
				"reported:\n%s", joinMigrationFindings(findings))
		})
	}
}

// TestMigrationContentRules_ApplyOnlyAboveTheirCutoff runs one broken migration at its rule's
// cutoff and again one number above it. Both sides matter: below is the grandfathering that
// makes the rules landable at all, since a shipped migration's DDL cannot be edited, and above
// is the rule doing its job.
//
// TestMigrationCutoffs_AreTight is the other half, over the real tree: this says the cutoff is
// obeyed, that one says the number is where the violations actually stop.
func TestMigrationContentRules_ApplyOnlyAboveTheirCutoff(t *testing.T) {
	tests := []struct {
		rule   string
		cutoff int
		breaks func(migrationTree, int)
	}{
		{
			rule:   "mssql/nvarchar",
			cutoff: migrationCutoffsDefault.MSSQLNVarchar,
			breaks: func(tr migrationTree, num int) {
				editUp(tr, schemadump.MSSQL, num, "[name] NVARCHAR(64)", "[name] VARCHAR(64)")
			},
		},
		{
			rule:   "mssql/named-default",
			cutoff: migrationCutoffsDefault.MSSQLNamedDefault,
			breaks: func(tr migrationTree, num int) {
				editUp(tr, schemadump.MSSQL, num, "CONSTRAINT [df_widgets_note] DEFAULT", "DEFAULT")
			},
		},
		{
			rule:   "mssql/collate",
			cutoff: migrationCutoffsDefault.MSSQLCollate,
			breaks: func(tr migrationTree, num int) {
				editUp(tr, schemadump.MSSQL, num,
					"[label] NVARCHAR(32) COLLATE "+migrationMSSQLCollation+" NULL",
					"[label] NVARCHAR(32) NULL")
			},
		},
		{
			rule:   "mysql/collation",
			cutoff: migrationCutoffsDefault.MySQLCollation,
			breaks: func(tr migrationTree, num int) {
				editUp(tr, schemadump.MySQL, num,
					"  id bigint NOT NULL\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE="+
						migrationMySQLCollation+";",
					"  id bigint NOT NULL\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			at := migrationContentFixture(tt.cutoff)
			tt.breaks(at, tt.cutoff)
			require.Emptyf(t, checkMigrationSource(at),
				"%06d is the %s cutoff, so it is grandfathered: a shipped migration's DDL cannot "+
					"be edited, which is the whole reason the content rules are not retroactive",
				tt.cutoff, tt.rule)

			above := migrationContentFixture(tt.cutoff + 1)
			tt.breaks(above, tt.cutoff+1)
			findings := checkMigrationSource(above)
			require.NotEmptyf(t, findings, "%06d is one above the %s cutoff and nothing reported it",
				tt.cutoff+1, tt.rule)
			require.Equal(t, tt.rule, findings[0].Rule, joinMigrationFindings(findings))
		})
	}
}

// TestMigrationNullabilityRule_HasNoCutoff is the one content rule that reads every number,
// including the oldest. It costs nothing: no ALTER COLUMN in the tree has ever omitted the
// keyword, so pinning it now is free and pinning it later would mean another issue.
func TestMigrationNullabilityRule_HasNoCutoff(t *testing.T) {
	tree := migrationContentFixture(2)
	editUp(tree, schemadump.MSSQL, 2, "ALTER COLUMN [id] BIGINT NOT NULL", "ALTER COLUMN [id] BIGINT")

	findings := checkMigrationSource(tree)
	require.NotEmpty(t, findings, "000002 is below every cutoff, but nullability has none")
	require.Equal(t, "mssql/nullability", findings[0].Rule, joinMigrationFindings(findings))
}

// TestMigrationGoldenVersion_HoldsEachGoldenToItsOwnHighestNumber is decision 2's replacement
// for the git-diff rule the issue proposed. Reading a recorded number rather than a diff is what
// makes it fire in CI at all: check.yml checks out at depth 1, where `git merge-base HEAD main`
// has no answer and the proposed rule was silently inert.
//
// The number is PER ENGINE and never compared across engines. They legitimately differ.
func TestMigrationGoldenVersion_HoldsEachGoldenToItsOwnHighestNumber(t *testing.T) {
	// A fresh tree and a fresh map per case: they are independent claims, and a case that
	// mutated a shared one would silently change what the next case is testing.
	fixture := func() (migrationTree, map[schemadump.Dialect]int) {
		recorded := map[schemadump.Dialect]int{}
		for _, d := range migrationDialects {
			recorded[d] = 50
		}
		return migrationContentFixture(50), recorded
	}

	t.Run("four goldens at their engine's highest number", func(t *testing.T) {
		tree, recorded := fixture()
		require.Empty(t, checkGoldenVersion(tree, recorded))
	})

	t.Run("a golden left behind by a new migration is refused", func(t *testing.T) {
		tree, stale := fixture()
		stale[schemadump.MSSQL] = 49

		findings := checkGoldenVersion(tree, stale)
		require.Len(t, findings, 1, joinMigrationFindings(findings))
		require.Equal(t, "mssqldb/schema.golden", findings[0].Where)
		require.Contains(t, findings[0].Say, "was dumped at migration 49")
	})

	t.Run("engines that differ from one another are not compared", func(t *testing.T) {
		// The real tree is like this: postgres 39, mssql 40, mysql 42, sqlite 43. Only sqlite
		// carries 000051 here, so only sqlite's golden owes that number.
		tree, moved := fixture()
		tree[schemadump.SQLite]["000051_sqlite_only.up.sql"] =
			"-- parity: sqlite only. The other three already carry the index.\n" +
				"CREATE INDEX idx_gadgets_id ON gadgets (id);\n"
		tree[schemadump.SQLite]["000051_sqlite_only.down.sql"] = "DROP INDEX idx_gadgets_id;\n"
		moved[schemadump.SQLite] = 51

		require.Empty(t, checkMigrationSource(tree), "the added migration is green on its own")
		require.Empty(t, checkGoldenVersion(tree, moved))
	})

	t.Run("a golden recording no version at all is refused", func(t *testing.T) {
		tree, none := fixture()
		delete(none, schemadump.Postgres)

		findings := checkGoldenVersion(tree, none)
		require.Len(t, findings, 1, joinMigrationFindings(findings))
		require.Contains(t, findings[0].Say, "records no migration version")
	})
}
