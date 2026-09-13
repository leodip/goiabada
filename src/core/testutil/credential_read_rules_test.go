package testutil

// Seam 2: the rule table AssertNoCredentialQueryFallback enforces, over fixture trees written into a
// temp directory and walked through the same function the two real callers use.
//
// The synthetic half exists because the real half cannot fail informatively. Both call sites are
// green on arrival and have been since #202, so they would pass identically whether the rule still
// fires or has quietly stopped matching anything. Every "rejected" row below is a read that reaches
// the URL query; every "admitted" row is a read that does not and must survive untouched.

import (
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderReads renders findings as "<file>:<line> <accessor>(<name>)" so a failure names what was
// missed or over-matched rather than printing a struct.
func renderReads(reads []credentialQueryRead) []string {
	out := make([]string, 0, len(reads))
	for _, r := range reads {
		out = append(out, r.file+":"+strconv.Itoa(r.line)+" "+r.accessor+"("+r.name+")")
	}
	sort.Strings(out)
	return out
}

// TestNoCredentialQueryFallback_TheAccessorTable holds the four rejected shapes against the four
// admitted ones, in one file, under three receiver names.
//
// One file rather than one per row: the property that keeps the admitted half admitted is textual --
// the dot before Form, which .PostFormValue and .PostForm.Get do not have -- so a row that cannot
// see its neighbours is not exercising the thing that could break.
func TestNoCredentialQueryFallback_TheAccessorTable(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/reads.go", `package handlers

func rejected(r *request, req *request, request2 *request) {
	_ = r.FormValue("password")
	_ = r.Form.Get("password")
	_ = r.Form.Has("password")
	_ = r.Form["password"]
	_ = req.FormValue("password")
	_ = request2.Form.Get("password")
}

func admitted(r *request) {
	_ = r.PostFormValue("password")
	_ = r.PostForm.Get("password")
	_ = r.PostForm.Has("password")
	_ = r.PostForm["password"]
}
`)

	reads, perDir, err := findCredentialQueryReads(root, []string{`"password"`}, []string{"handlers"})
	require.NoError(t, err)
	assert.Equal(t, []string{
		`handlers/reads.go:4 .FormValue("password")`,
		`handlers/reads.go:5 .Form.Get("password")`,
		`handlers/reads.go:6 .Form.Has("password")`,
		`handlers/reads.go:7 .Form[...]("password")`,
		`handlers/reads.go:8 .FormValue("password")`,
		`handlers/reads.go:9 .Form.Get("password")`,
	}, renderReads(reads))
	assert.Equal(t, 1, perDir["handlers"])
}

// TestNoCredentialQueryFallback_TheReplacementIsNamed checks that a finding says what to write
// instead, per shape. A finding naming only the defect leaves the reader to guess which of the four
// body-only accessors is the counterpart of the one they wrote.
func TestNoCredentialQueryFallback_TheReplacementIsNamed(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/reads.go", `package handlers

func f(r *request) {
	_ = r.FormValue("otp")
	_ = r.Form.Get("otp")
	_ = r.Form.Has("otp")
	_ = r.Form["otp"]
}
`)

	reads, _, err := findCredentialQueryReads(root, []string{`"otp"`}, []string{"handlers"})
	require.NoError(t, err)
	require.Len(t, reads, 4)
	uses := map[string]string{}
	for _, r := range reads {
		uses[r.accessor] = r.use
	}
	assert.Equal(t, map[string]string{
		".FormValue": ".PostFormValue",
		".Form.Get":  ".PostForm.Get",
		".Form.Has":  ".PostForm.Has",
		".Form[...]": ".PostForm[...]",
	}, uses)
}

// TestNoCredentialQueryFallback_TheNameIsAnchoredOnBothSides is the property that lets "code" and
// "otp" be listed at all. Both are prefixes of names this tree reads legitimately from the query --
// code_challenge and code_challenge_method at /auth/authorize, otpSecret and otpEnabled elsewhere --
// so a pattern that stopped at the name would fail the tier on reads that are correct.
//
// Two things anchor the right-hand side and the second half of this case exists because a mutation
// showed the first was covering for it. A quoted literal carries its own closing quote inside the
// name text, so "code" cannot match code_challenge whatever the accessor appends; a constant name
// has no such quote, and there only the accessor's closing delimiter keeps ceremonyIdField off
// ceremonyIdFieldLegacy.
func TestNoCredentialQueryFallback_TheNameIsAnchoredOnBothSides(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/authorize.go", `package handlers

func f(r *request) {
	_ = r.FormValue("code_challenge")
	_ = r.FormValue("code_challenge_method")
	_ = r.Form.Get("code_verifier_hint")
	_ = r.Form["otpSecret"]
	_ = r.FormValue("precode")
}
`)

	reads, _, err := findCredentialQueryReads(root,
		[]string{`"code"`, `"otp"`, `"code_verifier"`}, []string{"handlers"})
	require.NoError(t, err)
	assert.Empty(t, renderReads(reads))

	// And the anchored name is still found when it is the whole argument.
	writeFixture(t, root, "handlers/token.go", `package handlers

func g(r *request) {
	_ = r.FormValue("code")
}
`)
	reads, _, err = findCredentialQueryReads(root,
		[]string{`"code"`, `"otp"`, `"code_verifier"`}, []string{"handlers"})
	require.NoError(t, err)
	assert.Equal(t, []string{`handlers/token.go:4 .FormValue("code")`}, renderReads(reads))

	// A constant name has no closing quote of its own, so the accessor's closing delimiter is the
	// only thing keeping it off a longer identifier that starts the same way.
	writeFixture(t, root, "handlers/ceremony.go", `package handlers

func h(r *request) {
	_ = r.FormValue(ceremonyIdFieldLegacy)
	_ = r.Form[continuationIdFieldV2]
	_ = r.Form.Get(ceremonyIdField2)
}
`)
	reads, _, err = findCredentialQueryReads(root,
		[]string{"ceremonyIdField", "continuationIdField"}, []string{"handlers"})
	require.NoError(t, err)
	assert.Empty(t, renderReads(reads))
}

// TestNoCredentialQueryFallback_AConstantNameIsMatchedAsWritten covers the auth server's two
// form-binding markers, which are read through constants rather than literals. The caller passes the
// argument text, so an identifier works exactly as a quoted literal does and nothing in the walk has
// to know which it was given.
func TestNoCredentialQueryFallback_AConstantNameIsMatchedAsWritten(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/ceremony.go", `package handlers

func f(r *request) {
	_ = r.FormValue(ceremonyIdField)
	_ = r.PostFormValue(continuationIdField)
}
`)

	reads, _, err := findCredentialQueryReads(root,
		[]string{"ceremonyIdField", "continuationIdField"}, []string{"handlers"})
	require.NoError(t, err)
	assert.Equal(t, []string{"handlers/ceremony.go:4 .FormValue(ceremonyIdField)"}, renderReads(reads))
}

// TestNoCredentialQueryFallback_TestSourcesAreNotWalked pins the exclusion the two callers depend
// on. A test legitimately spells these names when it builds a submission, and both call sites are
// themselves _test.go files whose lists would otherwise match themselves on every run.
func TestNoCredentialQueryFallback_TestSourcesAreNotWalked(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/handler_test.go", `package handlers

func f(r *request) {
	_ = r.FormValue("password")
}
`)
	writeFixture(t, root, "handlers/handler.go", `package handlers

func g(r *request) {
	_ = r.PostFormValue("password")
}
`)

	reads, perDir, err := findCredentialQueryReads(root, []string{`"password"`}, []string{"handlers"})
	require.NoError(t, err)
	assert.Empty(t, renderReads(reads))
	// The production file was still walked, so the floor below is not satisfied by the test file.
	assert.Equal(t, 1, perDir["handlers"])
}

// TestNoCredentialQueryFallback_EveryNamedDirectoryIsAFloor is what stops the guard dying quietly. A
// walk that reaches nothing reports nothing, which is indistinguishable from a clean tree, so each
// directory the caller named is counted separately and a zero is the finding.
func TestNoCredentialQueryFallback_EveryNamedDirectoryIsAFloor(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "internal/handlers/handler.go", "package handlers\n")
	writeFixture(t, root, "internal/middleware/notes.md", "no Go here\n")
	writeFixture(t, root, "internal/middleware/mw_test.go", "package middleware\n")

	_, perDir, err := findCredentialQueryReads(root, []string{`"password"`},
		[]string{"internal", "internal/handlers", "internal/middleware"})
	require.NoError(t, err)

	assert.Equal(t, 1, perDir["internal"], "the parent tree holds one non-test Go file")
	assert.Equal(t, 1, perDir["internal/handlers"])
	assert.Equal(t, 0, perDir["internal/middleware"],
		"a directory holding only a test file and a markdown file guards nothing")
}

// TestNoCredentialQueryFallback_OverlappingDirectoriesReportOnce is the other half of naming a tree
// and its subtrees at once: the floors have to count a file under each directory that reaches it,
// and the findings must not.
func TestNoCredentialQueryFallback_OverlappingDirectoriesReportOnce(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "internal/handlers/handler.go", `package handlers

func f(r *request) {
	_ = r.FormValue("password")
}
`)

	reads, perDir, err := findCredentialQueryReads(root, []string{`"password"`},
		[]string{"internal", "internal/handlers"})
	require.NoError(t, err)
	assert.Equal(t, []string{`internal/handlers/handler.go:4 .FormValue("password")`}, renderReads(reads))
	assert.Equal(t, 1, perDir["internal"])
	assert.Equal(t, 1, perDir["internal/handlers"])
}

// TestNoCredentialQueryFallback_TheListIsThePolicy is the case that keeps the two call sites honest.
// The whole reason this guard takes its names as a parameter is that the two modules must disagree:
// "state" is a finding in the admin console and a lawful query read in the auth server, because only
// the auth server has an authorization endpoint that OIDC Core 3.1.2.1 requires to accept GET. A
// shared list would have to drop it, and the admin console's /auth/callback reads would go unguarded.
func TestNoCredentialQueryFallback_TheListIsThePolicy(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/authorize.go", `package handlers

func f(r *request) {
	_ = r.FormValue("state")
	_ = r.FormValue("password")
}
`)

	adminConsole := []string{`"password"`, `"state"`}
	authServer := []string{`"password"`}

	acReads, _, err := findCredentialQueryReads(root, adminConsole, []string{"handlers"})
	require.NoError(t, err)
	assert.Equal(t, []string{
		`handlers/authorize.go:4 .FormValue("state")`,
		`handlers/authorize.go:5 .FormValue("password")`,
	}, renderReads(acReads))

	asReads, _, err := findCredentialQueryReads(root, authServer, []string{"handlers"})
	require.NoError(t, err)
	assert.Equal(t, []string{`handlers/authorize.go:5 .FormValue("password")`}, renderReads(asReads))
}
