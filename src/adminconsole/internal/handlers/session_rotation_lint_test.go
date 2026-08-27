package handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHandlers_SignInRotatesTheSessionIdentifier guards the admin console's one privilege
// transition against losing its identifier rotation again.
//
// The session used to be the cookie itself, which made this module structurally immune to
// session fixation: the cookie WAS the state, so an attacker's planted copy stayed the
// attacker's own stale state and never became anyone else's session. Session state now
// lives in a row and the cookie carries only a handle to it, and that immunity is not
// inherited. A planted handle names the row that the administrator's sign-in then fills
// in with their access, id and refresh tokens, so whoever planted it is signed in as them.
// Rotating the handle at the moment the session becomes authenticated is what puts the
// immunity back (#266).
//
// Why a source lint rather than a test that drives the handler. The missing call was
// invisible to every other instrument: nothing failed, nothing was red, and the module's
// sign-in worked perfectly, because a rotation that never happens is inert rather than
// broken. That is the same reason csrf_lint_test.go in this package exists. This module
// has no handler test harness at all (#237) and building one is a different change, so
// there is no mock store to observe the call on either.
//
// What it proves and what it does not. It proves that the file which writes the token set
// into a session also reaches the store's rotation, which is what a copy-paste, a revert
// or a rewritten handler would drop. It does not prove the two are on the same path, and
// nothing lexical could. The store's own half, that rotation issues a different identifier
// and removes the old row, is real behaviour and is covered at
// core/sessionstore.TestServerSideStore_RegenerateRotatesAnAdminConsoleSession; the auth
// server's equivalent site is observed end to end, through a real cookie jar, at
// TestBrowserSession_IdentifierRotatesAtSignIn.
func TestHandlers_SignInRotatesTheSessionIdentifier(t *testing.T) {
	// The write that makes a session authenticated in this module. It is the store's own
	// AuthenticatedKey for the adminconsole owner, so this string is the definition of
	// the transition rather than one example of it.
	const authenticatedWrite = "constants.SessionKeyJwt] ="

	// The rotation, named by the interface rather than the method, since a caller has to
	// assert to it before it can call anything.
	const rotation = "sessionstore.Regenerator"

	// go test runs with the package directory as the working directory, so ".." is
	// src/adminconsole/internal.
	const self = "../handlers/session_rotation_lint_test.go"

	found := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.ToSlash(path) == self {
			return nil
		}

		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(source)
		if !strings.Contains(text, authenticatedWrite) {
			return nil
		}

		found++
		if !strings.Contains(text, rotation) {
			t.Errorf("%s writes the authenticated session key but never reaches %s. "+
				"A handle that existed before sign-in must not name the session sign-in "+
				"produces, and nothing else in this module would notice it does (#266)", path, rotation)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module's sources: %v", err)
	}

	// Without this the lint passes by finding nothing, which is how a guard quietly stops
	// guarding after the code it watches is renamed or moved.
	if found == 0 {
		t.Fatalf("no source under internal/ writes %q, so this guard is watching nothing", authenticatedWrite)
	}
}
