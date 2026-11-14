package errcode

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
)

// Every key here names a sentence of the English catalog, so a refusal never shows its key: a key
// missing from the catalog renders as itself. core/i18n's catalog tests hold every other built-in
// catalog to the English one's keys, and its error_codes.md to its sentences.
func TestKeys_EachNamesASentenceOfTheEnglishCatalog(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "errcode.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				key, unquoteErr := strconv.Unquote(value.Values[i].(*ast.BasicLit).Value)
				if unquoteErr != nil {
					t.Fatalf("%s: %v", name.Name, unquoteErr)
				}
				keys[name.Name] = key
			}
		}
	}
	if len(keys) == 0 {
		t.Fatal("errcode.go declares no keys, so this test would pass on nothing")
	}
	for name, key := range keys {
		if got := i18n.T(context.Background(), key); got == key {
			t.Errorf("%s = %q, which the English catalog has no sentence for", name, key)
		}
	}
}
