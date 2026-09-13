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

// Seam 3: the reporting half. Everything above asserts on what findCredentialQueryReads returned,
// which leaves the lines that turn those reads into a failure untested. This is the guard where
// that matters most: it is the sole enforcement of CLAUDE.md pattern 5, which exists to stop a
// bearer token or a password reaching a proxy log, and blinding its report loop (ranging over
// reads[:0]) survived its own rule test.

// TestNoCredentialQueryFallback_TheGuardFailsOnAMergedRead drives the reporting half and holds the
// message to naming the file, the line, the shape found, the replacement, and why it matters. The
// message is the whole remedy here -- a reader who is told only "line 4 is wrong" reaches for the
// nearest edit rather than the right one.
func TestNoCredentialQueryFallback_TheGuardFailsOnAMergedRead(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/login.go", `package handlers

func f(r *request) {
	_ = r.FormValue("password")
}
`)

	report := RunGuard(func(rep Reporter) {
		assertNoCredentialQueryFallback(rep, root, []string{`"password"`}, []string{"handlers"})
	})

	require.True(t, report.Failed(), "a merged-form credential read passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "handlers/login.go:4")
	assert.Contains(t, report.Text(), `"password"`)
	assert.Contains(t, report.Text(), ".FormValue")
	assert.Contains(t, report.Text(), "use .PostFormValue")
	assert.Contains(t, report.Text(), "#202")
}

// TestNoCredentialQueryFallback_TheGuardPassesABodyOnlyRead is the other direction: the admitted
// shape must survive the reporting half untouched.
func TestNoCredentialQueryFallback_TheGuardPassesABodyOnlyRead(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/login.go", `package handlers

func f(r *request) {
	_ = r.PostFormValue("password")
}
`)

	report := RunGuard(func(rep Reporter) {
		assertNoCredentialQueryFallback(rep, root, []string{`"password"`}, []string{"handlers"})
	})

	assert.False(t, report.Failed(), "a body-only read failed the guard: %s", report.Text())
}

// TestNoCredentialQueryFallback_ADirectoryThatCoveredNothingIsAnError is this guard's own answer to
// the empty walk, and it is deliberately not the one the other twelve give. Each named directory is
// a floor reported separately, so a tree renamed out from under one of three call sites fails here
// naming that directory, rather than shrinking the guard to the two that still resolve.
func TestNoCredentialQueryFallback_ADirectoryThatCoveredNothingIsAnError(t *testing.T) {
	root := t.TempDir()

	writeFixture(t, root, "handlers/login.go", "package handlers\n")
	writeFixture(t, root, "middleware/mw_test.go", "package middleware\n")

	report := RunGuard(func(rep Reporter) {
		assertNoCredentialQueryFallback(rep, root, []string{`"password"`},
			[]string{"handlers", "middleware"})
	})

	require.True(t, report.Failed())
	assert.False(t, report.Stopped,
		"a named directory that covered nothing is an Errorf, so every other directory is still reported")
	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Text(), "walked no non-test Go files under middleware")
	assert.NotContains(t, report.Text(), "under handlers")
}

// TestNoCredentialQueryFallback_NoDirectoriesAndAnEmptyRootIsFatal is the other arm of the same
// decision. With no directory named there is no floor to report against, so the only honest answer
// is to stop.
func TestNoCredentialQueryFallback_NoDirectoriesAndAnEmptyRootIsFatal(t *testing.T) {
	root := t.TempDir()

	report := RunGuard(func(rep Reporter) {
		assertNoCredentialQueryFallback(rep, root, []string{`"password"`}, nil)
	})

	require.True(t, report.Stopped, "an unnamed walk that covered nothing must be fatal")
	assert.Contains(t, report.Fatal, "walked no non-test Go files under")
}
