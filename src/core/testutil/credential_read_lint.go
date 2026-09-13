package testutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// AssertNoCredentialQueryFallback holds production code under dirs to reading each of names from
// the request body alone, never from the merged form.
//
// http.Request.ParseForm merges the URL query into r.Form behind the request body, and r.FormValue
// reads that merged map. So a handler reading a credential with r.FormValue accepts it from the
// request target: POST /auth/pwd?password=... authenticates, and POST
// /account/change-password?newPassword=... changes the password, with the value then sitting in the
// browser's history, in the Referer of anything the page loads, and in the access log of every
// proxy, gateway and CDN in front of the deployment. r.PostFormValue reads the body alone and
// returns "" for such a request, so the handler's existing required-field or validation path runs
// instead.
//
// Every credential-bearing form in this tree is served by a POST-only route whose GET counterpart is
// a separate handler that renders the form, so no legitimate caller ever supplies one of these names
// in a query. The two accessors therefore return the same value for every request a real client
// makes, and they diverge only where the value arrived somewhere it should not have.
//
// The accessor is what is refused, not the policy name, and mergedFormAccessors carries all four
// shapes. Matching .FormValue alone was the guard's blind spot until #333 lifted it: the two copies
// this replaces named merged r.Form as the unsafe source in their own rationale and then checked
// only one of the four ways to read it, so a protected read moved from r.PostForm.Get to r.Form.Get
// passed the whole tier. handler_token.go calls ParseForm before it reads anything, which is exactly
// the precondition that makes r.Form the merged map rather than the body.
//
// names are argument texts rather than bare words, because that is what the walk matches against:
// `"password"` with its quotes for a literal read, ceremonyIdField without them for one read through
// a constant. Each is wrapped in its accessor's opening and closing delimiters before the search, so
// the match is anchored on both sides and a listed name cannot swallow a longer one beginning the
// same way. Which delimiter does that work depends on how the name was spelled: a quoted literal
// carries its own closing quote inside the name text, which is what keeps `"code"` off
// .FormValue("code_challenge") and `"otp"` off .Form["otpSecret"]; a constant has no such quote, and
// there the accessor's closing ")" or "]" is the only thing keeping ceremonyIdField off
// .FormValue(ceremonyIdFieldLegacy).
//
// The list is the caller's, never a shared one, and the two call sites deliberately differ. The auth
// server's must not carry "state", because handler_authorize.go reads .FormValue("state") at two
// sites and OIDC Core 3.1.2.1 requires the authorization endpoint to accept GET as well as POST, so
// there the name has a lawful query source; the admin console's carries it because it has no such
// endpoint and those names reach it only at /auth/callback, which is registered POST-only and
// arranged with response_mode=form_post precisely so they arrive in a body (#202).
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes and
// relative to it ("authserver/internal"). Every directory named is also a coverage floor: it must
// yield at least one non-test Go file, or the walk is reported as guarding nothing. Overlapping
// entries are deduped by path, so a caller names the tree it walks and, beneath it, each subtree it
// insists is actually covered -- a walk that quietly reaches nothing is how an instrument like this
// dies without anything going red.
//
// Two boundaries, both chosen rather than overlooked.
//
// The scan is lexical, exactly as csrf_lint_test.go in the admin console states for itself. A key
// assembled from a constant expression, "pass" + "word", is not seen, and one built at run time
// never could be. That is the right trade because the way this regression actually happens is
// copy-paste, a revert, or a new handler written from an old one, and every one of those carries the
// spelling.
//
// ceiling: being lexical, the walk also cannot follow the merged map through a name. A handler that
// wrote form := r.Form and then read form.Get("password") reads the query and matches nothing here,
// because the receiver is no longer spelled Form. No site in the tree binds r.Form or r.PostForm to
// a local today, and resolving one would mean type-checking every package under dirs, which is the
// cost AssertNoDeadInterfaces pays and this guard does not. Revisit when a handler binds either map
// to a variable, or when a finding shows a read reaching the query through one (#333).
//
// It asserts a spelling is absent, not that the replacement is right. In the auth server four
// behavioural cases cover the replacement, in handler_auth_pwd_test.go, handler_auth_otp_test.go,
// handler_reset_password_test.go and accounthandlers/handler_account_register_test.go. In the admin
// console nothing does, because that module has no handler harness to write one in, which is the
// same gap #155 left behind and csrf_lint_test.go was written to cover.
//
// Scope and shape follow AssertNoLegacyErrors and AssertGofmted, which carry the reasoning for
// walking the source root rather than the calling module.
func AssertNoCredentialQueryFallback(t *testing.T, names []string, dirs ...string) {
	t.Helper()

	root := SourceRoot(t)

	reads, perDir, err := findCredentialQueryReads(root, names, dirs)
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	for _, r := range reads {
		t.Errorf("%s:%d: reads %s with %s, which merges the URL query behind the request body, so "+
			"the value is accepted from the request target and leaks into history, Referer and "+
			"every proxy log in front of the deployment; use %s (#202)",
			r.file, r.line, r.name, r.accessor, r.use)
	}

	// A walk that covers nothing passes while guarding nothing. Each directory the caller named is
	// held to having been reached, so narrowing one of them by renaming a tree fails here rather
	// than shrinking the guard in silence.
	for _, dir := range dirs {
		if perDir[dir] == 0 {
			t.Errorf("walked no non-test Go files under %s; the guard is not checking the "+
				"credential reads that live there", dir)
		}
	}
	if len(dirs) == 0 && perDir[""] == 0 {
		t.Fatalf("walked no non-test Go files under %s", root)
	}
}

// credentialQueryRead is one merged-form read of a protected name, located.
type credentialQueryRead struct {
	// file is relative to the source root, forward slashes.
	file string
	line int
	// name is the argument text as the caller spelled it, quotes and all.
	name string
	// accessor is the shape that was found, and use is what should have been written instead.
	accessor string
	use      string
}

// formAccessor is one way to read a named form value, as the text that brackets the name.
type formAccessor struct {
	// open and close bracket the name, so a match is anchored on both sides.
	open  string
	close string
	// label is how the shape is named in a finding, and use is its body-only counterpart.
	label string
	use   string
}

// mergedFormAccessors is every way to read a name out of the merged map, each paired with the
// body-only accessor that should have been written instead.
//
// The leading dot and no receiver is what makes these four safe to match as text. A pattern matches
// a read under any receiver name -- r., req. or request. -- while the dot keeps it off the body-only
// twin of each shape: in .PostFormValue( the character before FormValue is a t rather than a dot,
// and in .PostForm.Get(, .PostForm.Has( and .PostForm[ the character before Form is a t. A pattern
// spelled r.FormValue( would miss the first property and one spelled FormValue(" would fail on the
// fix itself.
var mergedFormAccessors = []formAccessor{
	{open: ".FormValue(", close: ")", label: ".FormValue", use: ".PostFormValue"},
	{open: ".Form.Get(", close: ")", label: ".Form.Get", use: ".PostForm.Get"},
	{open: ".Form.Has(", close: ")", label: ".Form.Has", use: ".PostForm.Has"},
	{open: ".Form[", close: "]", label: ".Form[...]", use: ".PostForm[...]"},
}

// findCredentialQueryReads scans the non-test Go sources under the named subdirectories of root for
// any of names read through a merged-form accessor. It returns the reads it found and, per named
// directory, how many non-test Go files it walked there.
func findCredentialQueryReads(root string, names, dirs []string) ([]credentialQueryRead, map[string]int, error) {
	starts := map[string]string{}
	if len(dirs) == 0 {
		starts[""] = root
	}
	for _, dir := range dirs {
		starts[dir] = filepath.Join(root, filepath.FromSlash(dir))
	}

	var found []credentialQueryRead
	perDir := map[string]int{}
	// Overlapping directories are ordinary here -- a caller names the tree it walks and the
	// subtrees it insists are covered -- so a file reached twice is counted twice against the
	// floors and scanned once for findings.
	scanned := map[string]bool{}
	for dir, start := range starts {
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skippedDir(d.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			// Non-test sources only: a test legitimately spells these names when it builds a
			// submission, and it is production code that decides where a credential may come from.
			// Skipping them also skips the two callers, whose lists would otherwise match
			// themselves.
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			perDir[dir]++
			if scanned[path] {
				return nil
			}
			scanned[path] = true

			b, rErr := os.ReadFile(path)
			if rErr != nil {
				return rErr
			}
			rel, rErr := filepath.Rel(root, path)
			if rErr != nil {
				return rErr
			}
			found = append(found, readsIn(filepath.ToSlash(rel), string(b), names)...)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}

	sort.Slice(found, func(i, j int) bool {
		if found[i].file != found[j].file {
			return found[i].file < found[j].file
		}
		if found[i].line != found[j].line {
			return found[i].line < found[j].line
		}
		return found[i].name < found[j].name
	})
	return found, perDir, nil
}

// readsIn collects every merged-form read of one of names in one file's source.
func readsIn(rel, src string, names []string) []credentialQueryRead {
	var found []credentialQueryRead
	for _, name := range names {
		for _, acc := range mergedFormAccessors {
			pattern := acc.open + name + acc.close
			for off := 0; ; {
				i := strings.Index(src[off:], pattern)
				if i < 0 {
					break
				}
				at := off + i
				found = append(found, credentialQueryRead{
					file:     rel,
					line:     1 + strings.Count(src[:at], "\n"),
					name:     name,
					accessor: acc.label,
					use:      acc.use,
				})
				off = at + len(pattern)
			}
		}
	}
	return found
}
