package guard

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AssertGeneratedSourceTypeChecks type-checks a generator's rendered output together with the
// hand-written files of the package it is written into. pkgDir is that package's directory,
// generatedFile the base name the generator writes (data_generated.go), and src the rendered bytes.
//
// Formatting the output is not compiling it. The timezones generator's template kept an fmt import
// its body no longer used after b4ade52c edited the committed output and the template by hand, so
// its next run would have written a file that does not build; go/format accepts that, and nothing
// else checked the generator (#432). Every non-test Go file in pkgDir except generatedFile is
// parsed, src is added under generatedFile's name, and the whole package is checked with go/types,
// so the rendered table has to agree with the type it fills. The copy of generatedFile on disk is
// skipped: it is what the generator is about to replace, and a stale or broken one must neither
// hide a defect in src nor report one src does not have.
//
// Each type error is an Errorf. A directory holding no other Go file is a Fatalf, since checking
// the output alone would pass whatever type it names.
func AssertGeneratedSourceTypeChecks(r Reporter, pkgDir, generatedFile string, src []byte) {
	r.Helper()

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		r.Fatalf("read %s: %v", pkgDir, err)
		return
	}
	var handWritten []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == generatedFile {
			continue
		}
		handWritten = append(handWritten, name)
	}
	sort.Strings(handWritten)
	if len(handWritten) == 0 {
		r.Fatalf("%s holds no Go file besides %s, so there is nothing to check the output against", pkgDir, generatedFile)
		return
	}

	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(handWritten)+1)
	for _, name := range handWritten {
		path := filepath.Join(pkgDir, name)
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			r.Errorf("parse %s: %v", path, parseErr)
			return
		}
		files = append(files, f)
	}
	generated, err := parser.ParseFile(fset, filepath.Join(pkgDir, generatedFile), src, parser.ParseComments)
	if err != nil {
		r.Errorf("the rendered %s does not parse: %v", generatedFile, err)
		return
	}
	files = append(files, generated)

	conf := types.Config{
		// The source importer resolves imports from source, as the compiler would, so the check
		// needs no compiled export data for the packages the output imports.
		Importer: importer.ForCompiler(fset, "source", nil),
		Error: func(err error) {
			r.Errorf("the rendered %s does not type-check: %v", generatedFile, err)
		},
	}
	// Every error has already reached the Error callback; the returned one is the first of them.
	_, _ = conf.Check(files[0].Name.Name, fset, files, nil)
}
