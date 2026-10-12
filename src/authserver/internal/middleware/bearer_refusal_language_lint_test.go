package middleware

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/guard"
)

// The bearer guards' refusals on /api/v1/* are English, always, and this file is what keeps that
// true. #559 translated the 400 and 409 refusals a person reaches through the admin console, and
// TestAPIRefusals_EnglishOnlyForTheMachineOnlyClasses in internal/handlers/apihandlers holds the
// handlers to it. The guards here answer before any handler runs, so that scan never reads them.
// They stay English for two reasons:
//
//   - No person reads them. The console sends one well-formed Authorization header on every call,
//     and shows its own page for a 401 or a 403, so these sentences reach an integrator debugging a
//     request, for whom English is the documented default.
//   - Each sentence is written twice, once as the JSON body's error_description and once as the
//     WWW-Authenticate challenge's, which RFC 6750 section 3 restricts to printable ASCII and which
//     BearerChallenge passes through oauth.ConformErrorDescription. A Portuguese sentence there
//     would come back with a '?' for every accented letter, so translating one would mean splitting
//     the body from the challenge rather than translating the one string both read.
//
// What is checked, in both directions:
//
//   - Every description a guard hands invalidRequest, invalidToken or forbidden is a string literal,
//     or a package string constant, whose value is in bearerEnglishRefusals. A sentence read from a
//     catalog, built at run time or new to the table fails. Those calls go through the
//     bearerRefusals interface, so /userinfo's answers are held to the same sentences.
//   - Inside apiBearerRefusals, the writer of the API envelope, every WriteError message and every
//     BearerChallenge description is the method's own description parameter, the empty string, or a
//     literal in the table. That is what keeps the body and the challenge one English string.
//   - A table entry nothing writes fails, so the table cannot rot into a list that excuses whatever
//     comes back under that spelling.

// bearerEnglishRefusals is every sentence a bearer guard may answer an /api/v1/* refusal with.
var bearerEnglishRefusals = map[string]bool{
	// missing: no credential at all, 401.
	"Access token required.": true,

	// invalidRequest: a malformed bearer request, 400.
	"The request body could not be parsed.":             true,
	"The Authorization header must be sent once.":       true,
	"The access_token parameter must be sent once.":     true,
	"The access token must be sent by one method only.": true,

	// invalidToken: a presented token that is refused, 401.
	"The access token is invalid.": true,
	"Invalid token subject":        true,
	"Session has been terminated":  true,
	"Session has expired":          true,

	// forbidden: a valid token that does not reach the route, 403.
	"Insufficient scope.": true,
	"This endpoint requires an access token issued for a user. Tokens obtained through the client credentials grant are not accepted.": true,
}

// bearerRefusalDir is the package that holds the bearer guards, relative to the source root.
const bearerRefusalDir = "authserver/internal/middleware"

// bearerRefusalFileFloor is how many non-test Go files that package holds at rest, as a floor so
// ordinary growth does not move it and as a parameter so a rule test can pin the refusal.
const bearerRefusalFileFloor = 10

// bearerRefusalDescriptionArg maps each refusal that carries a description to that argument's
// index. missing and internalError carry none.
var bearerRefusalDescriptionArg = map[string]int{
	"invalidRequest": 2,
	"invalidToken":   2,
	"forbidden":      3,
}

// bearerAPIWriterArgs maps what apiBearerRefusals writes through to the index of the text it writes.
var bearerAPIWriterArgs = map[string]int{
	"WriteError":      1,
	"BearerChallenge": 1,
}

// bearerAPIWriterType is the receiver whose methods write the admin and account API's envelope.
const bearerAPIWriterType = "apiBearerRefusals"

// bearerSentence is one sentence a bearer refusal is written with, located.
type bearerSentence struct {
	file     string
	line     int
	sentence string
}

// bearerRefusalScan is what one walk of the package found.
type bearerRefusalScan struct {
	sentences []bearerSentence
	problems  []string
	files     int
	// writerMethods counts the apiBearerRefusals methods read, so a rename that hides the writer
	// from the scan is fatal rather than a clean pass.
	writerMethods int
}

func TestBearerRefusals_EnglishOnly(t *testing.T) {
	assertBearerRefusals(t, guard.SourceRoot(t), bearerRefusalFileFloor, bearerEnglishRefusals)
}

// findBearerRefusals parses the non-test Go files of the bearer guards' package under root and
// returns every sentence a refusal is written with.
func findBearerRefusals(root string) (bearerRefusalScan, error) {
	dir := filepath.Join(root, filepath.FromSlash(bearerRefusalDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return bearerRefusalScan{}, errs.Wrapf(err, "reading %s", dir)
	}

	fset := token.NewFileSet()
	parsed := map[string]*ast.File{}
	consts := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			// A file that does not parse is a compile error the build owns.
			continue
		}
		parsed[bearerRefusalDir+"/"+name] = f
		for k, v := range packageStringConsts(f) {
			consts[k] = v
		}
	}

	scan := bearerRefusalScan{files: len(parsed)}
	for rel, f := range parsed {
		collectBearerRefusals(fset, f, rel, consts, &scan)
	}
	sort.Strings(scan.problems)
	return scan, nil
}

// assertBearerRefusals is the reporting half, taking the root, the floor and the table as parameters
// and failing through a guard.Reporter so a rule test can drive it against a fixture tree.
func assertBearerRefusals(r guard.Reporter, root string, floor int, table map[string]bool) {
	r.Helper()

	scan, err := findBearerRefusals(root)
	if err != nil {
		r.Fatalf("%v", err)
	}
	// A walk that reached nothing would pass every assertion below.
	if scan.files < floor || scan.writerMethods == 0 {
		r.Fatalf("walked %d non-test Go files under %s and %d %s method(s); the walk is no longer "+
			"reaching the bearer guards", scan.files, bearerRefusalDir, scan.writerMethods, bearerAPIWriterType)
	}

	for _, p := range scan.problems {
		r.Errorf("%s", p)
	}

	seen := map[string]bool{}
	var unlisted []string
	for _, s := range scan.sentences {
		seen[s.sentence] = true
		if !table[s.sentence] {
			unlisted = append(unlisted, s.file+":"+strconv.Itoa(s.line)+": "+strconv.Quote(s.sentence))
		}
	}
	sort.Strings(unlisted)
	if len(unlisted) > 0 {
		r.Errorf("%d bearer refusal sentence(s) not in bearerEnglishRefusals:\n\t%s\n\n"+
			"A bearer refusal on /api/v1/* is English and is written once, in the JSON body and in "+
			"the WWW-Authenticate challenge alike. Add the sentence to the table, in English and in "+
			"printable ASCII.", len(unlisted), strings.Join(unlisted, "\n\t"))
	}

	var orphaned []string
	for sentence := range table {
		if !seen[sentence] {
			orphaned = append(orphaned, strconv.Quote(sentence))
		}
	}
	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		r.Errorf("%d bearerEnglishRefusals entr(ies) no longer written anywhere: %s\n\n"+
			"Delete them. An entry nothing writes excuses whatever comes back under that spelling.",
			len(orphaned), strings.Join(orphaned, ", "))
	}
}

// collectBearerRefusals reads one file: the description at every refusal call, and what every
// apiBearerRefusals method writes.
func collectBearerRefusals(fset *token.FileSet, f *ast.File, rel string, consts map[string]string, scan *bearerRefusalScan) {
	problem := func(expr ast.Expr, what string) {
		scan.problems = append(scan.problems, rel+":"+strconv.Itoa(fset.Position(expr.Pos()).Line)+": "+
			what+". A bearer refusal on /api/v1/* is an English sentence from bearerEnglishRefusals, "+
			"written as a literal at the call, so the JSON body and the WWW-Authenticate challenge "+
			"carry the same string.")
	}
	read := func(expr ast.Expr) (string, bool) {
		if lit, ok := literalString(expr); ok {
			return lit, true
		}
		if ident, ok := unparen(expr).(*ast.Ident); ok {
			if value, ok := consts[ident.Name]; ok {
				return value, true
			}
		}
		return "", false
	}
	record := func(expr ast.Expr, sentence string) {
		scan.sentences = append(scan.sentences, bearerSentence{
			file: rel, line: fset.Position(expr.Pos()).Line, sentence: sentence,
		})
	}

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		writer := receiverTypeName(fn) == bearerAPIWriterType
		if writer {
			scan.writerMethods++
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, isMethod := unparen(call.Fun).(*ast.SelectorExpr)
			if isMethod {
				if at, carries := bearerRefusalDescriptionArg[sel.Sel.Name]; carries && at < len(call.Args) {
					description := call.Args[at]
					if sentence, readable := read(description); readable {
						record(description, sentence)
					} else {
						problem(description, sel.Sel.Name+"'s description is not a string literal")
					}
					return true
				}
			}
			if !writer {
				return true
			}
			name, ok := funcName(call.Fun)
			if !ok {
				return true
			}
			at, ok := bearerAPIWriterArgs[name]
			if !ok || at >= len(call.Args) {
				return true
			}
			text := call.Args[at]
			if ident, isIdent := unparen(text).(*ast.Ident); isIdent && ident.Name == "description" {
				return true
			}
			sentence, ok := read(text)
			switch {
			case !ok:
				problem(text, bearerAPIWriterType+"."+fn.Name.Name+" writes "+name+" something other "+
					"than its description parameter")
			case sentence == "" && name == "BearerChallenge":
				// A challenge naming the realm alone, which is what RFC 6750 section 3.1 asks of a
				// request carrying no credential.
			default:
				record(text, sentence)
			}
			return true
		})
	}
}

// receiverTypeName is the type a method is declared on, or empty for a function.
func receiverTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if ident, ok := t.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// funcName is the name a call is made through, bare or package-qualified.
func funcName(fun ast.Expr) (string, bool) {
	switch f := unparen(fun).(type) {
	case *ast.Ident:
		return f.Name, true
	case *ast.SelectorExpr:
		return f.Sel.Name, true
	}
	return "", false
}

// unparen strips the parentheses around an expression.
func unparen(e ast.Expr) ast.Expr {
	for {
		paren, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = paren.X
	}
}

// literalString is the value of a string literal.
func literalString(e ast.Expr) (string, bool) {
	lit, ok := unparen(e).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

// packageStringConsts returns the file's package-level string constants, so a sentence written as
// a named constant (invalidTokenDescription) is read as the value it holds.
func packageStringConsts(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				if lit, ok := literalString(value.Values[i]); ok {
					out[name.Name] = lit
				}
			}
		}
	}
	return out
}

// ---- the collector ---------------------------------------------------------------------------

// TestBearerRefusals_CollectorRuleTable pins the collector against source text, one row per rule,
// because the walk can only report what the collector sees.
func TestBearerRefusals_CollectorRuleTable(t *testing.T) {
	consts := map[string]string{"invalidTokenDescription": "The access token is invalid."}

	tests := []struct {
		name      string
		src       string
		sentences []string
		problems  int
	}{
		{
			name: "invalidRequest's third argument is its description",
			src: `package p
func g() { m.refusals.invalidRequest(w, r, "The Authorization header must be sent once.") }`,
			sentences: []string{"The Authorization header must be sent once."},
		},
		{
			name: "forbidden's fourth argument is its description, not its API code",
			src: `package p
func g() { m.refusals.forbidden(w, r, "INSUFFICIENT_SCOPE", "Insufficient scope.") }`,
			sentences: []string{"Insufficient scope."},
		},
		{
			name: "a package constant is read as the value it holds",
			src: `package p
func g() { m.refusals.invalidToken(w, r, invalidTokenDescription) }`,
			sentences: []string{"The access token is invalid."},
		},
		{
			name: "missing and internalError carry no description",
			src: `package p
func g() { m.refusals.missing(w, r); m.refusals.internalError(w, r, err, sid) }`,
		},
		{
			name: "a catalog sentence at the call is a problem",
			src: `package p
func g() { m.refusals.invalidToken(w, r, i18n.T(r.Context(), "bearer.session_terminated")) }`,
			problems: 1,
		},
		{
			name: "a sentence built at run time is a problem",
			src: `package p
func g(reason string) { m.refusals.invalidRequest(w, r, "The request is malformed: "+reason) }`,
			problems: 1,
		},
		{
			name: "the API writer forwarding its description writes no sentence of its own",
			src: `package p
func (apiBearerRefusals) invalidToken(w http.ResponseWriter, _ *http.Request, description string) {
	w.Header().Set("WWW-Authenticate", BearerChallenge("invalid_token", description))
	apiresponse.WriteError(w, description, "INVALID_TOKEN", http.StatusUnauthorized)
}`,
		},
		{
			name: "the API writer's own literal and a realm-only challenge",
			src: `package p
func (apiBearerRefusals) missing(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("WWW-Authenticate", BearerChallenge("", ""))
	apiresponse.WriteError(w, "Access token required.", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
}`,
			sentences: []string{"Access token required."},
		},
		{
			name: "the API writer translating the body is a problem",
			src: `package p
func (apiBearerRefusals) invalidToken(w http.ResponseWriter, r *http.Request, description string) {
	w.Header().Set("WWW-Authenticate", BearerChallenge("invalid_token", description))
	apiresponse.WriteError(w, i18n.T(r.Context(), description), "INVALID_TOKEN", http.StatusUnauthorized)
}`,
			problems: 1,
		},
		{
			name: "another surface's writer is not the API's",
			src: `package p
func (u userinfoBearerRefusals) invalidToken(w http.ResponseWriter, r *http.Request, description string) {
	u.refuse(w, r, "invalid_token", description, http.StatusUnauthorized)
}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "fixture.go", test.src, 0)
			require.NoError(t, err, "parsing the fixture")
			var scan bearerRefusalScan
			collectBearerRefusals(fset, f, "fixture.go", consts, &scan)

			var got []string
			for _, s := range scan.sentences {
				got = append(got, s.sentence)
			}
			assert.Equal(t, strings.Join(test.sentences, "|"), strings.Join(got, "|"), "sentences")
			assert.Len(t, scan.problems, test.problems, "problems: %v", scan.problems)
		})
	}
}

// ---- the reporting half ----------------------------------------------------------------------

// bearerRefusalFixture writes files under a fresh root, each keyed by its path relative to it.
func bearerRefusalFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

// bearerFixtureWriter is an apiBearerRefusals that forwards its description, as the real one does.
const bearerFixtureWriter = `package middleware

func (apiBearerRefusals) invalidToken(w http.ResponseWriter, _ *http.Request, description string) {
	w.Header().Set("WWW-Authenticate", BearerChallenge("invalid_token", description))
	apiresponse.WriteError(w, description, "INVALID_TOKEN", http.StatusUnauthorized)
}
`

// TestBearerRefusals_TheGuardPassesASurfaceThatMatchesItsTable is the clean direction, and it is
// what keeps each case below from passing for the wrong reason.
func TestBearerRefusals_TheGuardPassesASurfaceThatMatchesItsTable(t *testing.T) {
	root := bearerRefusalFixture(t, map[string]string{
		bearerRefusalDir + "/bearer_refusals.go": bearerFixtureWriter,
		bearerRefusalDir + "/api_auth.go": `package middleware

func g() { m.refusals.invalidToken(w, r, "Session has expired") }
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertBearerRefusals(r, root, 1, map[string]bool{"Session has expired": true})
	})

	assert.False(t, report.Failed(), "a surface matching its table failed the guard: %s", report.Text())
}

// TestBearerRefusals_TheGuardFailsOnASentenceOutsideTheTable is how a new refusal regresses: a
// guard written with a sentence nobody listed, or listed in Portuguese.
func TestBearerRefusals_TheGuardFailsOnASentenceOutsideTheTable(t *testing.T) {
	root := bearerRefusalFixture(t, map[string]string{
		bearerRefusalDir + "/bearer_refusals.go": bearerFixtureWriter,
		bearerRefusalDir + "/api_auth.go": `package middleware

func g() {
	m.refusals.invalidToken(w, r, "Session has expired")
	m.refusals.invalidToken(w, r, "Sessão expirada")
}
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertBearerRefusals(r, root, 1, map[string]bool{"Session has expired": true})
	})

	require.True(t, report.Failed(), "a sentence outside the table passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	require.Len(t, report.Errors, 1, "the listed sentence is written, so only one direction fires")
	assert.Contains(t, report.Text(), bearerRefusalDir+`/api_auth.go:5: "Sessão expirada"`)
	assert.Contains(t, report.Text(), "WWW-Authenticate")
}

// TestBearerRefusals_TheGuardFailsOnATranslatedRefusal is the other way it regresses: a catalog
// lookup at the call, or inside the API writer, which reads no sentence the table could list.
func TestBearerRefusals_TheGuardFailsOnATranslatedRefusal(t *testing.T) {
	root := bearerRefusalFixture(t, map[string]string{
		bearerRefusalDir + "/bearer_refusals.go": `package middleware

func (apiBearerRefusals) invalidToken(w http.ResponseWriter, r *http.Request, description string) {
	w.Header().Set("WWW-Authenticate", BearerChallenge("invalid_token", description))
	apiresponse.WriteError(w, i18n.T(r.Context(), description), "INVALID_TOKEN", http.StatusUnauthorized)
}
`,
		bearerRefusalDir + "/api_auth.go": `package middleware

func g() {
	m.refusals.invalidToken(w, r, "Session has expired")
	m.refusals.invalidToken(w, r, i18n.T(r.Context(), "bearer.session_terminated"))
}
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertBearerRefusals(r, root, 1, map[string]bool{"Session has expired": true})
	})

	require.True(t, report.Failed(), "a translated refusal passed the guard")
	require.Len(t, report.Errors, 2, "one finding per translated site: %s", report.Text())
	assert.Contains(t, report.Text(), bearerRefusalDir+"/api_auth.go:5: invalidToken's description is not a string literal")
	assert.Contains(t, report.Text(), bearerRefusalDir+"/bearer_refusals.go:5: apiBearerRefusals.invalidToken writes WriteError something other than its description parameter")
}

// TestBearerRefusals_TheGuardFailsOnATableEntryNothingWrites is the other direction on its own.
func TestBearerRefusals_TheGuardFailsOnATableEntryNothingWrites(t *testing.T) {
	root := bearerRefusalFixture(t, map[string]string{
		bearerRefusalDir + "/bearer_refusals.go": bearerFixtureWriter,
		bearerRefusalDir + "/api_auth.go": `package middleware

func g() { m.refusals.invalidToken(w, r, "Session has expired") }
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertBearerRefusals(r, root, 1, map[string]bool{
			"Session has expired":         true,
			"Session has been terminated": true,
		})
	})

	require.True(t, report.Failed(), "a table entry nothing writes passed the guard")
	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Text(), `no longer written anywhere: "Session has been terminated"`)
	assert.Contains(t, report.Text(), "Delete them")
}

// TestBearerRefusals_TheGuardIsFatalWhenTheWalkReachesNothing pins the guard's answer to the empty
// walk, which would otherwise pass every assertion.
func TestBearerRefusals_TheGuardIsFatalWhenTheWalkReachesNothing(t *testing.T) {
	root := bearerRefusalFixture(t, map[string]string{
		bearerRefusalDir + "/README.md": "no Go here\n",
	})

	report := guard.Run(func(r guard.Reporter) {
		assertBearerRefusals(r, root, 1, map[string]bool{})
	})

	require.True(t, report.Stopped, "a walk that reached nothing must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked 0 non-test Go files")
	assert.Contains(t, report.Fatal, "no longer reaching the bearer guards")
}

// TestBearerRefusals_TheGuardIsFatalWithoutTheAPIWriter covers the rename that would hide the
// writer: the files are read, but nothing in them is apiBearerRefusals any more.
func TestBearerRefusals_TheGuardIsFatalWithoutTheAPIWriter(t *testing.T) {
	root := bearerRefusalFixture(t, map[string]string{
		bearerRefusalDir + "/api_auth.go": `package middleware

func g() { m.refusals.invalidToken(w, r, "Session has expired") }
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertBearerRefusals(r, root, 1, map[string]bool{"Session has expired": true})
	})

	require.True(t, report.Stopped, "a walk that found no API writer must be fatal")
	assert.Contains(t, report.Fatal, "0 apiBearerRefusals method(s)")
}

// TestBearerRefusals_TheFileFloorIsBelowTheRealSurface holds the floor to the tree it guards.
func TestBearerRefusals_TheFileFloorIsBelowTheRealSurface(t *testing.T) {
	scan, err := findBearerRefusals(guard.SourceRoot(t))
	require.NoError(t, err)

	assert.GreaterOrEqual(t, scan.files, bearerRefusalFileFloor)
	assert.Less(t, bearerRefusalFileFloor, scan.files*2,
		"the floor has drifted far below the package it guards and would no longer catch a walk "+
			"that lost most of it")
}
