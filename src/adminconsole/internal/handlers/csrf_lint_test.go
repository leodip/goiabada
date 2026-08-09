package handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHandlers_NoCsrfFieldBind is the bind-side half of the guard whose template-side half lives in
// web/template_lint_test.go as TestTemplates_NoCsrfField. #155 replaced the CSRF token with an
// origin check, deleting 100 csrfField binds from the 59 handler files under internal/handlers and
// four more from internal/rendertest, and nothing else in this module can tell if one comes back.
//
// The admin console has no handler tests: its seven test_main_test.go files are stubs, and the four
// render tests in internal/rendertest supply their own bind maps rather than a handler's. So the
// authserver's instrument does not exist here. There, a reintroduced bind fails a deliberately
// brittle len(bind) assertion; here, reintroducing "csrfField": "" left the entire module tier
// green when it was tried, from a handler's bind map and from a render test's alike.
//
// A stray bind is inert rather than broken, which is exactly why it needs a lint: it binds a value
// no template reads, it cannot fail anything, and it reads to the next person as though that
// handler still emitted a CSRF token. #155 deleted the plumbing rather than repointing it at a
// local helper for that precise reason.
//
// The boundary is every Go source under internal/, not this package's tree alone, because a bind
// map reaching the real renderer from a test fixture reads exactly like one reaching it from a
// handler and is just as invisible. Every RenderTemplate caller in this module lives under
// internal/, in one of two trees: internal/handlers and internal/rendertest. Both must be walked or
// the guard covers less than it claims, which is what the per-tree check below enforces.
//
// It walks source text rather than go/ast, and the claim it makes is exactly that: no Go source
// under internal/ contains the string csrfField. That is the shape a regression actually takes,
// because a bind comes back by copy-paste, by a revert, or by a new handler written from an old
// one, and every one of those carries the spelling.
//
// It is not a guard on the runtime map key, and the difference is demonstrable rather than
// theoretical: the constant expression "csrf" + "Field" builds the same key and this test does not
// see it. Closing that would take go/ast with constant folding, and a key assembled at run time
// would still be out of reach, so the boundary is lexical on purpose rather than by oversight.
// Anything that reaches it has been written deliberately to evade this file, which is a different
// problem from the one #155 left behind.
func TestHandlers_NoCsrfFieldBind(t *testing.T) {
	// go test runs with the package directory as the working directory, so ".." is
	// src/adminconsole/internal.
	const self = "../handlers/csrf_lint_test.go"

	perTree := map[string]int{}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel := filepath.ToSlash(path)
		if rel == self {
			return nil
		}
		b, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		perTree[strings.SplitN(strings.TrimPrefix(rel, "../"), "/", 2)[0]]++
		if strings.Contains(string(b), "csrfField") {
			// Lexical, like the scan: this says the spelling is present, not that the
			// occurrence is a bind. A comment naming it matches too, and should also go.
			t.Errorf("%s: names csrfField, the bind spelling #155 deleted when it replaced the "+
				"CSRF token with an origin check; no template reads it, so remove the occurrence "+
				"or update this guard", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal sources: %v", err)
	}

	// A walk that misses one of these passes while guarding only half the bind suppliers.
	for _, tree := range []string{"handlers", "rendertest"} {
		if perTree[tree] == 0 {
			t.Errorf("walked no Go files under internal/%s; the guard is not checking the bind "+
				"maps that live there", tree)
		}
	}
}
