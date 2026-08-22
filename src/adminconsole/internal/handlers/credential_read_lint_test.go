package handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHandlers_NoCredentialQueryFallback is the admin console half of the guard #202 asked for. Its
// authserver twin lives at src/authserver/internal/handlers/credential_read_lint_test.go with a
// deliberately different name list, for the reason spelled out below.
//
// r.FormValue calls ParseForm, which merges the URL query into r.Form behind the request body. So a
// handler reading a credential with r.FormValue accepts it from the request target: POST
// /account/change-password?newPassword=... changed the password, with the password then sitting in
// the browser's history, in the Referer of anything the page loads, and in the access log of every
// proxy, gateway and CDN in front of the deployment. r.PostFormValue reads the body alone and
// returns "" for such a request, so the handler's existing required-field or validation path runs
// instead.
//
// Every credential-bearing form in this module is served by a POST-only route whose GET counterpart
// is a separate handler that renders the form, so no legitimate caller ever supplies one of these
// names in a query. The two accessors therefore return the same value for every request a real
// client makes, and they diverge only where the value arrived somewhere it should not have.
//
// This module carries the whole weight of the guard, which is why it exists at all. The admin
// console has no handler tests: its seven test_main_test.go files are stubs and the only real
// handler test is adminclienthandlers/handler_admin_client_redirect_uris_test.go, so the sixteen
// reads this file covers have no behavioural instrument available. That is the same gap #155 left
// behind and csrf_lint_test.go was written to cover, in the same module, for the same reason.
//
// The instrument's honest limit, stated because it decides what this file is worth: it asserts a
// spelling is absent, not that the replacement is right. In the authserver, four behavioural cases
// cover the replacement as well. Here nothing does, because there is no harness to write one in.
// Building this module's first handler harness would outlive this change and is drafted as a
// follow-up rather than done here.
//
// The list below is this module's, not a shared one, and it is the longer of the two. It carries
// "code", "state", "error" and "error_description" on top of the ten credential names because this
// module has no authorization endpoint: those four reach it only at /auth/callback, which
// auth_helper.go arranges by asking for response_mode=form_post precisely so they arrive in a body,
// and which is registered POST-only. The authserver's list must not carry them, because
// handler_authorize.go reads .FormValue("state") legitimately: OIDC Core 3.1.2.1 requires the
// authorization endpoint to accept both GET and POST, so there those names have a lawful query
// source.
//
// Two boundaries, both chosen rather than overlooked:
//
// The scan is lexical, exactly as csrf_lint_test.go in this package states for itself. A key
// assembled from a constant expression, "pass" + "word", is not seen, and one built at run time
// never could be. That is the right trade because the way this regression actually happens is
// copy-paste, a revert, or a new handler written from an old one, and every one of those carries the
// spelling.
//
// The walk is this module's internal/ tree, so a credential read that appeared in src/core would be
// seen by neither this file nor its authserver twin. No such read exists today: the only .FormValue
// reads in core are the rate limiter's own "email" and "username" account keys, which are
// deliberately absent from the list below because they are not credentials and because the limiter
// and the handler it protects must keep reading the account name the same way (#219).
func TestHandlers_NoCredentialQueryFallback(t *testing.T) {
	// The ten credential-bearing names, as quoted literals. A value under any of them
	// authenticates, authorizes or configures on its own.
	forbidden := []string{
		`"password"`,
		`"passwordConfirmation"`,
		`"currentPassword"`,
		`"newPassword"`,
		`"newPasswordConfirmation"`,
		`"otp"`,
		`"secretKey"`,
		`"base64Image"`,
		`"verificationCode"`,
		`"clientSecret"`,
		// The four form_post arrivals at /auth/callback. The authorization code is a
		// credential on the same terms as the rest; state, error and error_description travel
		// with it and are read in the same function, so splitting them would leave four reads
		// in one place divided two ways with nothing saying why.
		`"code"`,
		`"state"`,
		`"error"`,
		`"error_description"`,
	}

	// go test runs with the package directory as the working directory, so ".." is
	// src/adminconsole/internal. It is a variable rather than an inline argument so a mutation
	// can point the walk at a tree holding no handler sources and show the per-tree floor
	// below is live.
	root := ".."

	perTree := map[string]int{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Non-test sources only: a test legitimately spells these names when it builds a
		// submission, and it is production code that decides where a credential may come
		// from. Skipping them also skips this file, whose patterns are assembled below rather
		// than written out, so it never matches itself either way.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		rel := filepath.ToSlash(path)
		perTree[strings.SplitN(strings.TrimPrefix(rel, "../"), "/", 2)[0]]++
		src := string(b)
		for _, name := range forbidden {
			// The leading dot and no receiver: this matches a read under any receiver
			// name, r., req. or request., and it does not match .PostFormValue(<name>),
			// because the character before FormValue there is a t rather than a dot. A
			// pattern spelled r.FormValue( would miss the first property, and one spelled
			// FormValue(" would fail on the fix itself. The closing paren is part of the
			// pattern, so .FormValue("passwordPolicy") and .FormValue("username"), both
			// live reads in this module, are not matched by "password" or by a prefix of
			// any other name on the list.
			if strings.Contains(src, ".FormValue("+name+")") {
				t.Errorf("%s: reads %s with .FormValue, which merges the URL query behind "+
					"the request body, so the value is accepted from the request target and "+
					"leaks into history, Referer and every proxy log in front of the "+
					"deployment; use .PostFormValue (#202)", rel, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal sources: %v", err)
	}

	// A walk that covers nothing passes while guarding nothing, which is how this kind of
	// instrument dies quietly. These are the two trees in this module whose code is handed an
	// *http.Request: handlers holds every credential read there is, and middleware is where a
	// form read would be just as invisible and just as unguarded by anything else.
	for _, tree := range []string{"handlers", "middleware"} {
		if perTree[tree] == 0 {
			t.Errorf("walked no non-test Go files under internal/%s; the guard is not checking "+
				"the credential reads that live there", tree)
		}
	}
}
