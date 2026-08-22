package handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHandlers_NoCredentialQueryFallback is the authserver half of the guard #202 asked for. Its
// admin console twin lives at src/adminconsole/internal/handlers/credential_read_lint_test.go with
// a deliberately different name list, for the reason spelled out below.
//
// r.FormValue calls ParseForm, which merges the URL query into r.Form behind the request body. So
// a handler reading a credential with r.FormValue accepts it from the request target: POST
// /auth/pwd?password=... authenticates, with the password then sitting in the browser's history,
// in the Referer of anything the page loads, and in the access log of every proxy, gateway and CDN
// in front of the deployment. r.PostFormValue reads the body alone and returns "" for such a
// request, so the handler's existing required-field path renders instead.
//
// Every credential-bearing form in this module is served by a POST-only route whose GET
// counterpart is a separate handler that renders the form, so no legitimate caller ever supplies
// one of these names in a query. The two accessors therefore return the same value for every
// request a real client makes, and they diverge only where the value arrived somewhere it should
// not have.
//
// The list below is this module's, not a shared one. It must not carry "state" or "code":
// handler_authorize.go reads .FormValue("state") at two sites, and OIDC Core 3.1.2.1 requires the
// authorization endpoint to accept both GET and POST, so those names have a lawful query source
// here. The admin console has no such endpoint, which is why its list is the longer one.
//
// The instrument's honest limit, stated because it decides what this file is worth: it asserts a
// spelling is absent, not that the replacement is right. In this module the four behavioural cases
// in handler_auth_pwd_test.go, handler_auth_otp_test.go, handler_reset_password_test.go and
// accounthandlers/handler_account_register_test.go cover the replacement; the lint covers the
// spelling coming back.
//
// The boundary is lexical, exactly as csrf_lint_test.go in the admin console states for itself: a
// key assembled from a constant expression, "pass" + "word", is not seen, and one built at run
// time never could be. That is chosen rather than overlooked, because the way this regression
// actually happens is copy-paste, a revert, or a new handler written from an old one, and every
// one of those carries the spelling.
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
		// The form-binding markers, read through their constants rather than a literal.
		// They authorize nothing alone, but a marker supplied by a URL is not a submission,
		// and reading one from a URL reintroduces the shape #201 removed from the reset
		// link one indirection later.
		"ceremonyIdField",
		"continuationIdField",
	}

	// go test runs with the package directory as the working directory, so ".." is
	// src/authserver/internal. It is a variable rather than an inline argument so a mutation
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
		// from. Skipping them also skips this file, whose patterns are assembled below
		// rather than written out, so it never matches itself either way.
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
			// because the character before FormValue there is a t rather than a dot.
			// A pattern spelled r.FormValue( would miss the first property, and one
			// spelled FormValue(" would fail on the fix itself.
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
	// instrument dies quietly. handlers holds every credential read; middleware holds the
	// rate limiter, whose own .FormValue("email") reads are deliberately absent from the list
	// above and must stay visible to anyone widening it.
	for _, tree := range []string{"handlers", "middleware"} {
		if perTree[tree] == 0 {
			t.Errorf("walked no non-test Go files under internal/%s; the guard is not checking "+
				"the credential reads that live there", tree)
		}
	}
}
