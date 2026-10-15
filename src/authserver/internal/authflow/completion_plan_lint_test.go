package authflow

// The one place a completion plan mode is held to "built only by its constructor". A mode written as
// a literal anywhere else could carry attributes no decision chose, and Completion.Run acts on every
// attribute it finds: a stray rotation, termination or replacement is a session write (#580).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// completionPlanConstructors names each mode's type and the one function that may write it as a
// literal.
var completionPlanConstructors = map[string]string{
	"reuseSessionPlan":  "reuseSession",
	"createSessionPlan": "createSession",
	"restartPlan":       "restartAtLevel1",
}

// modeLiteralFound is one literal of a mode outside its constructor.
type modeLiteralFound struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	mode string
	// in is the function holding the literal, empty at package level.
	in string
}

// findModeLiterals parses every production Go file directly in dir under root and reports each
// composite literal of a type constructors names that sits anywhere but in that type's constructor,
// a plain function of that name, with the number of files it parsed. Test files are left out: the
// reference and the constructors' own tests read modes the code built.
func findModeLiterals(root, dir string, constructors map[string]string) ([]modeLiteralFound, int, error) {
	start := filepath.Join(root, filepath.FromSlash(dir))
	entries, err := os.ReadDir(start)
	if err != nil {
		return nil, 0, err
	}

	var found []modeLiteralFound
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, filepath.Join(start, name), nil, 0)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns.
			continue
		}
		files++
		for _, decl := range file.Decls {
			in := ""
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				in = fn.Name.Name
			} else if ok {
				in = "method " + fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				ident, ok := lit.Type.(*ast.Ident)
				if !ok {
					return true
				}
				constructor, isMode := constructors[ident.Name]
				if isMode && in != constructor {
					found = append(found, modeLiteralFound{
						file: dir + "/" + name,
						line: fset.Position(lit.Pos()).Line,
						mode: ident.Name,
						in:   in,
					})
				}
				return true
			})
		}
	}
	return found, files, nil
}

// TestCompletionPlanModes_BuiltOnlyByTheirConstructors holds the real package to the rule.
func TestCompletionPlanModes_BuiltOnlyByTheirConstructors(t *testing.T) {
	assertModesBuiltByConstructors(t, guard.SourceRoot(t), authflowDir)
}

// assertModesBuiltByConstructors is the reporting half, taking the root as a parameter and failing
// through a guard.Reporter so a rule test can drive it against a fixture tree.
func assertModesBuiltByConstructors(r guard.Reporter, root, dir string) {
	r.Helper()

	found, files, err := findModeLiterals(root, dir, completionPlanConstructors)
	if err != nil {
		r.Fatalf("reading %s: %v", dir, err)
	}
	// A directory holding no production file reads nothing and would otherwise pass.
	if files == 0 {
		r.Fatalf("read no production Go files under %s", dir)
	}
	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		where := "at package level"
		if f.in != "" {
			where = "in " + f.in
		}
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.mode+" "+where+
			", built by "+completionPlanConstructors[f.mode]+" alone")
	}
	r.Errorf("%d completion plan mode literal(s) outside their constructor under %s:\n\t%s\n\n"+
		"Build each mode through its constructor, so every attribute Completion acts on is one a "+
		"decision chose (#580).",
		len(found), dir, strings.Join(lines, "\n\t"))
}

// A fixture holding a literal of each mode in its constructor, and one in each place it may not sit.
func TestCompletionPlanModes_TheFinderTellsAConstructorFromAnyOtherSite(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/plan.go", `package authflow

type reuseSessionPlan struct{ rotateIdentifier bool }
type createSessionPlan struct{}
type restartPlan struct{}
type otherPlan struct{}

func reuseSession(rotate bool) reuseSessionPlan { return reuseSessionPlan{rotateIdentifier: rotate} }
func createSession() createSessionPlan         { return createSessionPlan{} }
func restartAtLevel1() restartPlan             { return restartPlan{} }

var stray = restartPlan{}

func decide() any {
	_ = otherPlan{}
	_ = &createSessionPlan{}
	return reuseSessionPlan{rotateIdentifier: true}
}

type operation struct{}

func (operation) restartAtLevel1() restartPlan { return restartPlan{} }
`)
	writeImportFixture(t, root, authflowDir+"/plan_test.go", `package authflow

var fromATest = reuseSessionPlan{}
`)

	found, files, err := findModeLiterals(root, authflowDir, completionPlanConstructors)
	require.NoError(t, err)
	assert.Equal(t, 1, files, "the one production file")

	var got []string
	for _, f := range found {
		got = append(got, f.file+":"+strconv.Itoa(f.line)+": "+f.mode+" in "+f.in)
	}
	assert.Equal(t, []string{
		authflowDir + "/plan.go:12: restartPlan in ",
		authflowDir + "/plan.go:16: createSessionPlan in decide",
		authflowDir + "/plan.go:17: reuseSessionPlan in decide",
		authflowDir + "/plan.go:22: restartPlan in method restartAtLevel1",
	}, got, "a constructor's own literal, another type's and a test file's are not reported")
}

func TestCompletionPlanModes_TheGuardFailsOnALiteralOutsideItsConstructor(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/plan.go", `package authflow

type restartPlan struct{}

func decide() restartPlan { return restartPlan{} }
`)

	report := guard.Run(func(r guard.Reporter) {
		assertModesBuiltByConstructors(r, root, authflowDir)
	})

	require.True(t, report.Failed(), "a mode built outside its constructor passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), authflowDir+"/plan.go:5: restartPlan in decide, built by restartAtLevel1 alone")
}

func TestCompletionPlanModes_TheGuardPassesModesBuiltByTheirConstructors(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/plan.go", `package authflow

type restartPlan struct{}

func restartAtLevel1() restartPlan { return restartPlan{} }

func decide() restartPlan { return restartAtLevel1() }
`)

	report := guard.Run(func(r guard.Reporter) {
		assertModesBuiltByConstructors(r, root, authflowDir)
	})

	assert.False(t, report.Failed(), "modes built by their constructors failed the guard: %s", report.Text())
}

func TestCompletionPlanModes_TheGuardIsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/only_test.go", `package authflow

var p = restartPlan{}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertModesBuiltByConstructors(r, root, authflowDir)
	})

	require.True(t, report.Stopped, "a package with no production file must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under "+authflowDir)
}
