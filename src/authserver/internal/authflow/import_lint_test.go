package authflow

// The one place authflow is held to "an operation cannot reach HTTP". Its operations decide a
// ceremony step and make its writes, and the handler writes the response after the operation
// returns, so the clear before the answer (#141), the rotation before the bind and the commit before
// the clear hold because nothing of the response exists while an operation runs. An operation that
// took the response writer, or read the request through reqctx, could write part of a response
// partway through and undo that; so could one that called back into handlers or middleware. The
// rule is about the import list, because the import list names every way back in (#580).

import (
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

// authflowDir is this package, relative to the source root, forward slashes.
const authflowDir = "authserver/internal/authflow"

// refusedImport is one import path, and every path under it, that authflow's production files may
// not name, with why.
type refusedImport struct {
	path string
	why  string
}

// authflowRefusedImports are the ways an operation could reach the HTTP exchange it serves.
var authflowRefusedImports = []refusedImport{
	{"net/http", "the request and the response writer; the browser session is reached through the handler's per-request adapter"},
	{"github.com/go-chi", "the router and its middleware"},
	{"github.com/leodip/goiabada/authserver/internal/handlers", "the handlers, which import authflow and write the response"},
	{"github.com/leodip/goiabada/authserver/internal/middleware", "the request middleware"},
	{"github.com/leodip/goiabada/authserver/internal/reqctx", "the request-scoped values, which the handler reads and hands over as plain values"},
}

// refusedImportFound is one import of a refused path from a production file of the package.
type refusedImportFound struct {
	// file is relative to the root the walk started from, forward slashes.
	file    string
	line    int
	path    string
	refused refusedImport
}

// isUnder reports whether imported is path or a package under it. A path that merely shares the
// prefix, net/httpx beside net/http, is not under it.
func isUnder(imported, path string) bool {
	return imported == path || strings.HasPrefix(imported, path+"/")
}

// findRefusedImports parses every production Go file directly in dir under root and reports each
// import of a refused path, with the number of files it parsed, so the reporting half can tell
// "nothing to report" from "nothing was read".
//
// Imports are parsed rather than matched as text: an alias binds another name to the same path and
// still counts, and a path written in a comment or a string is no import. The directory itself is
// read and not its subtree, and test files are left out, since a _test.go compiles into nothing the
// route table builds.
func findRefusedImports(root, dir string, refused []refusedImport) ([]refusedImportFound, int, error) {
	start := filepath.Join(root, filepath.FromSlash(dir))
	entries, err := os.ReadDir(start)
	if err != nil {
		return nil, 0, err
	}

	var found []refusedImportFound
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, filepath.Join(start, name), nil, parser.ImportsOnly)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns.
			continue
		}
		files++
		for _, spec := range file.Imports {
			imported, uErr := strconv.Unquote(spec.Path.Value)
			if uErr != nil {
				continue
			}
			for _, r := range refused {
				if isUnder(imported, r.path) {
					found = append(found, refusedImportFound{
						file:    dir + "/" + name,
						line:    fset.Position(spec.Pos()).Line,
						path:    imported,
						refused: r,
					})
				}
			}
		}
	}
	return found, files, nil
}

// TestAuthflow_ReachesNoHTTP holds the real package to the rule.
func TestAuthflow_ReachesNoHTTP(t *testing.T) {
	assertAuthflowReachesNoHTTP(t, guard.SourceRoot(t), authflowDir)
}

// assertAuthflowReachesNoHTTP is the reporting half, taking the root as a parameter and failing
// through a guard.Reporter so a rule test can drive it against a fixture tree.
func assertAuthflowReachesNoHTTP(r guard.Reporter, root, dir string) {
	r.Helper()

	found, files, err := findRefusedImports(root, dir, authflowRefusedImports)
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
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.path+" ("+f.refused.why+")")
	}
	r.Errorf("%d import(s) under %s that reach the HTTP exchange:\n\t%s\n\n"+
		"An authflow operation decides a step and makes its writes, and the handler writes the "+
		"response after it returns. Take what the request carries as a plain value, and reach the "+
		"browser session through the port the handler's adapter satisfies (#580).",
		len(found), dir, strings.Join(lines, "\n\t"))
}

func writeImportFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}

// A fixture holding every refused shape, each beside one that passes.
func TestAuthflow_ReachesNoHTTP_TheFinderTellsARefusedImportFromALookAlike(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/refused.go", `package authflow

import (
	"net/http"
	stdhttp "net/http/httptest"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)
`)
	writeImportFixture(t, root, authflowDir+"/allowed.go", `package authflow

// net/http in a comment is no import.
import (
	"context"
	"net/httpx"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/handlersx"
)

const s = "net/http"
`)
	writeImportFixture(t, root, authflowDir+"/allowed_test.go", `package authflow

import "net/http"
`)
	writeImportFixture(t, root, authflowDir+"/sub/nested.go", `package sub

import "net/http"
`)

	found, files, err := findRefusedImports(root, authflowDir, authflowRefusedImports)
	require.NoError(t, err)
	assert.Equal(t, 2, files, "the two production files directly in the package")

	var got []string
	for _, f := range found {
		got = append(got, f.file+":"+strconv.Itoa(f.line)+": "+f.path)
	}
	assert.Equal(t, []string{
		authflowDir + "/refused.go:4: net/http",
		authflowDir + "/refused.go:5: net/http/httptest",
		authflowDir + "/refused.go:7: github.com/go-chi/chi/v5",
		authflowDir + "/refused.go:8: github.com/leodip/goiabada/authserver/internal/handlers",
		authflowDir + "/refused.go:9: github.com/leodip/goiabada/authserver/internal/handlers/apihandlers",
		authflowDir + "/refused.go:10: github.com/leodip/goiabada/authserver/internal/middleware",
		authflowDir + "/refused.go:11: github.com/leodip/goiabada/authserver/internal/reqctx",
	}, got)
}

func TestAuthflow_ReachesNoHTTP_TheGuardFailsOnARefusedImport(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/operation.go", `package authflow

import "github.com/leodip/goiabada/authserver/internal/reqctx"
`)

	report := guard.Run(func(r guard.Reporter) {
		assertAuthflowReachesNoHTTP(r, root, authflowDir)
	})

	require.True(t, report.Failed(), "a reqctx import passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), authflowDir+"/operation.go:3: github.com/leodip/goiabada/authserver/internal/reqctx")
	assert.Contains(t, report.Text(), "plain value")
}

func TestAuthflow_ReachesNoHTTP_TheGuardPassesAPackageOffHTTP(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/operation.go", `package authflow

import (
	"context"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
)
`)

	report := guard.Run(func(r guard.Reporter) {
		assertAuthflowReachesNoHTTP(r, root, authflowDir)
	})

	assert.False(t, report.Failed(), "a package off HTTP failed the guard: %s", report.Text())
}

func TestAuthflow_ReachesNoHTTP_TheGuardIsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, authflowDir+"/only_test.go", `package authflow

import "net/http"
`)

	report := guard.Run(func(r guard.Reporter) {
		assertAuthflowReachesNoHTTP(r, root, authflowDir)
	})

	require.True(t, report.Stopped, "a package with no production file must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under "+authflowDir)
}
