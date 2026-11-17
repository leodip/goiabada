package web

// Readers of what the pages ship to a browser: the static lint and the scripts the unit tier runs
// through Node both use them, so they live outside the lint file, which builds only without the race
// detector.

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// servedFiles returns every embedded file under dir whose name ends in ext, keyed by its path.
func servedFiles(t *testing.T, fsys fs.FS, dir, ext string) map[string]string {
	t.Helper()

	out := map[string]string{}
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ext) {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for %s files: %v", dir, ext, err)
	}
	return out
}

// jsDeclRe matches a top-level declaration in a served script, in either of the two forms this
// file uses: `function name(` and `const name = (`, or a top-level statement, code in column zero
// that runs when the script loads, such as `document.querySelectorAll(...)` registering a listener.
// All three start in column zero, which is what keeps a nested helper out of the set: a function
// declared inside another is not something a template can call, so it is part of its parent's body
// rather than a declaration of its own.
var jsDeclRe = regexp.MustCompile(`(?m)^(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=|[A-Za-z_$][\w$]*\s*[.(])`)

// callRe matches a call to name that is not a property access, so `props.t(` and a comment's
// `t()` are treated alike: a bare identifier followed by an open parenthesis.
func callRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_.$])` + regexp.QuoteMeta(name) + `\s*\(`)
}

// jsDecl is one top-level declaration, or one top-level statement, whose name is empty: the code
// the script runs on its own when it loads.
type jsDecl struct {
	name string
	body string
}

// jsDecls splits a served script into its top-level declarations and statements. A declaration's
// body runs to the start of the next one, which needs no brace matching and is exact for a file
// written this way.
func jsDecls(src string) []jsDecl {
	locs := jsDeclRe.FindAllStringSubmatchIndex(src, -1)
	decls := make([]jsDecl, 0, len(locs))
	for i, loc := range locs {
		name := ""
		for _, g := range [][2]int{{2, 3}, {4, 5}} {
			if loc[g[0]] >= 0 {
				name = src[loc[g[0]]:loc[g[1]]]
			}
		}
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		decls = append(decls, jsDecl{name: name, body: src[loc[0]:end]})
	}
	return decls
}
