package commondb

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every statement and column list in this package carries all four engines' versions (#644
// decision 2).
//
// A statement value missing a version compiles, and runs on the three engines that have one: the
// fourth receives the empty string and refuses it, which only that engine's data tier would show.
// So every composite literal of statement or columnList in production code must key all four
// engines, by name, and none of them with the empty string. Keyed, because a positional literal
// whose engines are swapped also compiles and sends MySQL's text to PostgreSQL.
//
// It reads and parses files and nothing else, so it runs in the internal tier on every CI job.

// fourVersionTypes are the types whose literals must carry a version per engine.
var fourVersionTypes = map[string]bool{"statement": true, "columnList": true}

// engineVersions are the fields every such literal keys, one per engine.
var engineVersions = []string{"sqlite", "mysql", "postgres", "mssql"}

// missingVersion is one literal short of an engine's version.
type missingVersion struct {
	file   string
	line   int
	reason string
}

// findMissingVersions walks root's non-test Go files and reports every statement or columnList
// literal that does not key each engine exactly once with a non-empty value. It answers the
// number of such literals it read, so an empty walk is told from a clean one.
func findMissingVersions(root string) ([]missingVersion, int, error) {
	var findings []missingVersion
	literals := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns.
			return nil
		}

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := lit.Type.(*ast.Ident)
			if !ok || !fourVersionTypes[typ.Name] {
				return true
			}
			literals++
			line := fset.Position(lit.Pos()).Line
			report := func(reason string) {
				findings = append(findings, missingVersion{file: rel, line: line, reason: reason})
			}

			keyed := map[string]int{}
			for _, elt := range lit.Elts {
				kv, isKV := elt.(*ast.KeyValueExpr)
				if !isKV {
					report("a " + typ.Name + " literal names its engines positionally")
					return true
				}
				key, isIdent := kv.Key.(*ast.Ident)
				if !isIdent {
					continue
				}
				keyed[key.Name]++
				if basic, isBasic := kv.Value.(*ast.BasicLit); isBasic && basic.Kind == token.STRING {
					if value, err := strconv.Unquote(basic.Value); err == nil && strings.TrimSpace(value) == "" {
						report(key.Name + "'s version is empty")
					}
				}
			}
			for _, engine := range engineVersions {
				switch keyed[engine] {
				case 0:
					report("no " + engine + " version")
				case 1:
				default:
					report(engine + " is keyed more than once")
				}
			}
			return true
		})
		return nil
	})

	return findings, literals, err
}

// TestStatements_EveryEngineHasItsVersion holds the real package to the rule.
func TestStatements_EveryEngineHasItsVersion(t *testing.T) {
	assertEveryEngineHasItsVersion(t, filepath.Join(guard.SourceRoot(t), "authserver", "internal", "data", "commondb"))
}

// assertEveryEngineHasItsVersion is the reporting half, over a root a rule test can point at a
// fixture tree.
func assertEveryEngineHasItsVersion(r guard.Reporter, root string) {
	r.Helper()

	findings, literals, err := findMissingVersions(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	if literals == 0 {
		r.Fatalf("found no statement or columnList literals under %s; the type names or the package layout have moved", root)
	}
	if len(findings) == 0 {
		return
	}
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.reason)
	}
	sort.Strings(lines)
	r.Errorf("%d problem(s) in %d statement and column list literal(s):\n\t%s\n\n"+
		"Key every engine by name, sqlite, mysql, postgres and mssql, each with its own text, spelled "+
		"as that engine runs it. A missing version sends the empty string to that engine, which only "+
		"its own data tier would show (#644).",
		len(findings), literals, strings.Join(lines, "\n\t"))
}

func writeStatementFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}

const fixtureTypes = "package commondb\n\n" +
	"type statement struct{ sqlite, mysql, postgres, mssql string }\n" +
	"type columnList struct{ sqlite, mysql, postgres, mssql string }\n"

func TestStatements_TheCheckerTellsAWholeLiteralFromAShortOne(t *testing.T) {
	root := t.TempDir()
	writeStatementFixture(t, root, "types.go", fixtureTypes)
	writeStatementFixture(t, root, "whole.go", "package commondb\n\n"+
		"var whole = statement{\n"+
		"\tsqlite: \"SELECT 1\",\n"+
		"\tmysql: \"SELECT 1\",\n"+
		"\tpostgres: \"SELECT \" + \"1\",\n"+
		"\tmssql: \"SELECT 1\",\n"+
		"}\n")
	writeStatementFixture(t, root, "short.go", "package commondb\n\n"+
		"var noMSSQL = statement{sqlite: \"a\", mysql: \"a\", postgres: \"a\"}\n"+
		"var emptyMySQL = columnList{sqlite: \"a\", mysql: \"\", postgres: \"a\", mssql: \"a\"}\n"+
		"var positional = statement{\"a\", \"a\", \"a\", \"a\"}\n"+
		"var twice = statement{sqlite: \"a\", sqlite: \"b\", mysql: \"a\", postgres: \"a\", mssql: \"a\"}\n")
	writeStatementFixture(t, root, "short_test.go", "package commondb\n\n"+
		"var inATest = statement{sqlite: \"a\"}\n")

	findings, literals, err := findMissingVersions(root)
	require.NoError(t, err)
	assert.Equal(t, 5, literals, "every production literal is counted, and a test file's is not")
	assert.Equal(t, []missingVersion{
		{file: "short.go", line: 3, reason: "no mssql version"},
		{file: "short.go", line: 4, reason: "mysql's version is empty"},
		{file: "short.go", line: 5, reason: "a statement literal names its engines positionally"},
		{file: "short.go", line: 6, reason: "sqlite is keyed more than once"},
	}, findings)
}

func TestStatements_TheGuardFailsOnAMissingVersion(t *testing.T) {
	root := t.TempDir()
	writeStatementFixture(t, root, "types.go", fixtureTypes)
	writeStatementFixture(t, root, "short.go", "package commondb\n\n"+
		"var noPostgres = statement{sqlite: \"a\", mysql: \"a\", mssql: \"a\"}\n")

	report := guard.Run(func(r guard.Reporter) {
		assertEveryEngineHasItsVersion(r, root)
	})

	require.True(t, report.Failed(), "a statement with no PostgreSQL version passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "short.go:3: no postgres version")
}

func TestStatements_TheGuardPassesAWholeStatement(t *testing.T) {
	root := t.TempDir()
	writeStatementFixture(t, root, "types.go", fixtureTypes)
	writeStatementFixture(t, root, "whole.go", "package commondb\n\n"+
		"var whole = statement{sqlite: \"?\", mysql: \"?\", postgres: \"$1\", mssql: \"@p1\"}\n")

	report := guard.Run(func(r guard.Reporter) {
		assertEveryEngineHasItsVersion(r, root)
	})

	assert.False(t, report.Failed(), "a whole statement failed the guard: %s", report.Text())
}

func TestStatements_TheGuardIsFatalOnAWalkThatFoundNoLiteral(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) {
		assertEveryEngineHasItsVersion(r, t.TempDir())
	})

	require.True(t, report.Stopped, "a walk that found no literal must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "found no statement or columnList literals")
}

// TestStatement_TextIsTheDialectsOwnVersion pins which field each dialect reads, so a swap in the
// switch is caught here rather than by the one engine it sends the wrong text to.
func TestStatement_TextIsTheDialectsOwnVersion(t *testing.T) {
	s := statement{sqlite: "on sqlite", mysql: "on mysql", postgres: "on postgres", mssql: "on mssql"}
	assert.Equal(t, "on sqlite", s.text(data.SQLite))
	assert.Equal(t, "on mysql", s.text(data.MySQL))
	assert.Equal(t, "on postgres", s.text(data.Postgres))
	assert.Equal(t, "on mssql", s.text(data.MSSQL))
	assert.Empty(t, s.text(data.Dialect("oracle")), "an unknown engine is sent nothing it could run")

	l := columnList{sqlite: "a", mysql: "`b`", postgres: `"c"`, mssql: `"d"`}
	assert.Equal(t, "`b`", l.text(data.MySQL))
	assert.Equal(t, `"d"`, l.text(data.MSSQL))
}

// TestInList_WritesEachEnginesPlaceholders is the IN-list helper against each engine's style,
// written out here rather than computed: `?` on SQLite and MySQL, `$n` on PostgreSQL and `@pn` on
// SQL Server, numbered from the first argument the list binds.
func TestInList_WritesEachEnginesPlaceholders(t *testing.T) {
	assert.Equal(t, "id IN (?, ?, ?)", inList(data.SQLite, "id", 1, 3))
	assert.Equal(t, "id IN (?, ?, ?)", inList(data.MySQL, "id", 1, 3))
	assert.Equal(t, "id IN ($1, $2, $3)", inList(data.Postgres, "id", 1, 3))
	assert.Equal(t, "id IN (@p1, @p2, @p3)", inList(data.MSSQL, "id", 1, 3))

	assert.Equal(t, "user_id IN ($3, $4)", inList(data.Postgres, "user_id", 3, 2),
		"a list after two other arguments numbers from the third")
	assert.Equal(t, "user_id IN (@p3, @p4)", inList(data.MSSQL, "user_id", 3, 2))
	assert.Equal(t, "user_id IN (?, ?)", inList(data.MySQL, "user_id", 3, 2),
		"an unnumbered placeholder is the same wherever it sits")
	assert.Equal(t, "id IN ($1)", inList(data.Postgres, "id", 1, 1))
}

// TestInList_AnEmptyListMatchesNothing: `IN ()` is a syntax error on every engine, so an empty
// list is a predicate no row satisfies.
func TestInList_AnEmptyListMatchesNothing(t *testing.T) {
	for _, dialect := range allDialects {
		assert.Equal(t, "0 = 1", inList(dialect, "id", 1, 0), string(dialect))
	}
}
