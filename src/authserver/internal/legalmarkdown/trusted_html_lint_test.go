package legalmarkdown

// The one place the auth server is held to "markup built from data comes from Render".
//
// html/template escapes every value a page prints, unless the value is one of its trusted types,
// template.HTML above all, which it prints as markup. Every such value is therefore a sink: the
// day it carries text a person wrote, that text runs in the page. Before #622 the auth server built
// exactly one, a build-stamp comment from constants; #622 adds the second, a legal document's
// Markdown rendered by Render, whose rules (raw HTML out, dangerous addresses dropped, images as
// links) are what make it safe to print (decision 4). A third written anywhere else would bypass
// them, so this refuses any use of html/template's trusted types in the module's production code
// outside the two files named below.
//
// It reads and parses files and nothing else, so it runs in the internal tier on every CI job.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustedHTMLOwners are the files allowed to name html/template's trusted types, relative to the
// source root with forward slashes. Not the place for a new owner: markup a page shows is written in
// a template, and a document's text goes through Render.
var trustedHTMLOwners = map[string]string{
	"authserver/internal/legalmarkdown/render.go":  "a legal document's Markdown, rendered under this package's rules",
	"authserver/internal/render/template_funcs.go": "versionComment, the build stamp as an HTML comment, built from constants",
}

// trustedTypes are html/template's types whose values a template prints unescaped.
var trustedTypes = map[string]bool{
	"HTML": true, "HTMLAttr": true, "JS": true, "JSStr": true, "CSS": true, "URL": true, "Srcset": true,
}

// trustedHTMLUse is one use of a trusted type, or a dot import of html/template, outside the owners.
type trustedHTMLUse struct {
	file string
	line int
	name string
}

// findTrustedHTMLUses walks moduleDir under root for non-test Go files and reports every reference
// to one of html/template's trusted types outside the owners, under whatever name the file imports
// the package, and every dot import of it, which would let the types be named bare. It also returns
// how many files it parsed.
func findTrustedHTMLUses(root, moduleDir string, owners map[string]string) ([]trustedHTMLUse, int, error) {
	var uses []trustedHTMLUse
	files := 0
	err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(moduleDir)), func(path string, d fs.DirEntry, err error) error {
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
		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			// A file that does not parse is the build's to report.
			return nil
		}
		files++
		if _, owned := owners[rel]; owned {
			return nil
		}
		names := map[string]bool{}
		for _, spec := range file.Imports {
			importPath, _ := strconv.Unquote(spec.Path.Value)
			if importPath != "html/template" {
				continue
			}
			switch {
			case spec.Name == nil:
				names["template"] = true
			case spec.Name.Name == ".":
				uses = append(uses, trustedHTMLUse{file: rel, line: fset.Position(spec.Pos()).Line, name: `. "html/template"`})
			case spec.Name.Name != "_":
				names[spec.Name.Name] = true
			}
		}
		if len(names) == 0 {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if ok && names[pkg.Name] && trustedTypes[sel.Sel.Name] {
				uses = append(uses, trustedHTMLUse{file: rel, line: fset.Position(sel.Pos()).Line, name: pkg.Name + "." + sel.Sel.Name})
			}
			return true
		})
		return nil
	})
	return uses, files, err
}

func TestTrustedHTML_OnlyTheRendererAndTheBuildStamp(t *testing.T) {
	root := guard.SourceRoot(t)
	for file := range trustedHTMLOwners {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(file)))
		require.NoErrorf(t, err, "the owner %s is gone; a file that no longer exists leaves the list", file)
	}
	assertNoTrustedHTML(t, root, "authserver", trustedHTMLOwners)
}

// assertNoTrustedHTML is the reporting half, failing through a guard.Reporter so the rule tests
// below can drive it against a fixture tree.
func assertNoTrustedHTML(r guard.Reporter, root, moduleDir string, owners map[string]string) {
	r.Helper()

	uses, files, err := findTrustedHTMLUses(root, moduleDir, owners)
	if err != nil {
		r.Fatalf("walking %s: %v", moduleDir, err)
	}
	if files == 0 {
		r.Fatalf("walked no Go files under %s; this guard is checking nothing", moduleDir)
	}
	for _, use := range uses {
		r.Errorf("%s:%d: %s is printed by html/template as markup, unescaped. Write markup in a "+
			"template, and render a legal document's Markdown with legalmarkdown.Render, the one "+
			"guarded HTML sink (#622 decision 4)", use.file, use.line, use.name)
	}
}

// writeFixture writes one file under root.
func writeFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}

// TestTrustedHTML_TheFinderReadsEveryShape is the finder over a fixture tree holding each shape:
// a conversion, a type in a signature, an aliased import, a dot import, an owner, a test file, and
// the names that are not uses (text/template's, a comment, a string).
func TestTrustedHTML_TheFinderReadsEveryShape(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "authserver/internal/page/conversion.go", `package page

import "html/template"

func Banner(s string) template.HTML {
	return template.HTML("<b>" + s + "</b>")
}
`)
	writeFixture(t, root, "authserver/internal/page/alias.go", `package page

import ht "html/template"

var unsafeURL = ht.URL("javascript:alert(1)")
`)
	writeFixture(t, root, "authserver/internal/page/dot.go", `package page

import . "html/template"

var _ = New
`)
	writeFixture(t, root, "authserver/internal/page/clean.go", `package page

import (
	"html/template"
	text "text/template"
)

// template.HTML in a comment is not a use.
const note = "template.HTML"

var pages = template.New("pages")
var mails = text.New("mails")
`)
	writeFixture(t, root, "authserver/internal/legalmarkdown/render.go", `package legalmarkdown

import "html/template"

func Render(s string) template.HTML { return template.HTML(s) }
`)
	writeFixture(t, root, "authserver/internal/page/page_test.go", `package page

import "html/template"

var expected = template.HTML("<p>x</p>")
`)

	uses, files, err := findTrustedHTMLUses(root, "authserver", map[string]string{
		"authserver/internal/legalmarkdown/render.go": "the renderer",
	})
	require.NoError(t, err)
	assert.Equal(t, 5, files, "every non-test file is parsed, the owner included")
	assert.ElementsMatch(t, []trustedHTMLUse{
		{file: "authserver/internal/page/conversion.go", line: 5, name: "template.HTML"},
		{file: "authserver/internal/page/conversion.go", line: 6, name: "template.HTML"},
		{file: "authserver/internal/page/alias.go", line: 5, name: "ht.URL"},
		{file: "authserver/internal/page/dot.go", line: 3, name: `. "html/template"`},
	}, uses)
}

// TestTrustedHTML_TheGuardFailsOnAUse drives the reporting half, the lines the real tree, clean
// since the guard was written, never reaches.
func TestTrustedHTML_TheGuardFailsOnAUse(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "authserver/internal/page/conversion.go", `package page

import "html/template"

var banner = template.HTML("<b>hi</b>")
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoTrustedHTML(r, root, "authserver", trustedHTMLOwners)
	})

	require.True(t, report.Failed(), "a template.HTML conversion passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/page/conversion.go:5: template.HTML")
	assert.Contains(t, report.Text(), "legalmarkdown.Render")
}

func TestTrustedHTML_TheGuardPassesACleanTree(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "authserver/internal/page/clean.go", `package page

import "html/template"

var pages = template.New("pages")
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoTrustedHTML(r, root, "authserver", trustedHTMLOwners)
	})

	assert.False(t, report.Failed(), report.Text())
}

func TestTrustedHTML_TheGuardIsFatalWhenItWalksNothing(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "authserver/README.md", "no Go here\n")

	report := guard.Run(func(r guard.Reporter) {
		assertNoTrustedHTML(r, root, "authserver", trustedHTMLOwners)
	})

	require.True(t, report.Stopped, "a walk that read no Go file must stop the guard")
	assert.Contains(t, report.Text(), "checking nothing")
}
