package apihandlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
)

// The admin and account API answers one error code per condition, and this file is what keeps that
// true. It is the contract lint decision 18 asked for: the survivor table below is the whole set of
// error_code values the surface may write, and the walk fails on a code that is not in it and on a
// table entry nothing writes.
//
// Before this, one condition was spelled several ways and nothing noticed. A rejected value came
// back as VALIDATION_ERROR 184 times, but also as USER_ID_REQUIRED, INVALID_USER_ID,
// CLIENT_ID_REQUIRED, INVALID_CLIENT_ID, ATTRIBUTE_ID_REQUIRED, INVALID_ATTRIBUTE_ID, KEY_REQUIRED,
// USER_SESSION_ID_REQUIRED, INVALID_USER_SESSION_ID, SESSION_IDENTIFIER_REQUIRED,
// SESSION_ID_REQUIRED, EMAIL_REQUIRED, PASSWORD_REQUIRED, CURRENT_PASSWORD_REQUIRED,
// INVALID_PHONE_COUNTRY, INVALID_IMAGE, OTP_ENABLE_NOT_SUPPORTED and INVALID_REQUEST, 65 sites in
// all; an absent entity came back as NOT_FOUND, USER_NOT_FOUND, CLIENT_NOT_FOUND,
// ATTRIBUTE_NOT_FOUND, SESSION_NOT_FOUND or USER_SESSION_NOT_FOUND, 50 sites; and a body that would
// not parse came back as INVALID_REQUEST or INVALID_REQUEST_BODY. No caller acted on any of those
// differences, and the documented rule for integrators is to route on the HTTP status code, so what
// the spellings bought was fifteen names for three conditions and a document that could not
// enumerate them (#279 decision 18).
//
// Both directions are checked on purpose. Emitted-is-in-the-table catches a retired spelling coming
// back, which is how this regresses: a new handler written from an old one. Table-is-emitted
// catches the table rotting into a list of codes the API no longer has, which is how a lint stops
// meaning anything.
//
// Two boundaries, stated rather than discovered later:
//
//   - The scan is lexical over three directories and it reads a code where a code is written, not
//     where one might be computed. A code position that is not a string literal is therefore a
//     failure in its own right, except inside the handful of primitives whose whole job is to pass
//     a caller's code through; those are named in apiErrorCodeForwarders. That is what step 4 of
//     this stage bought by moving readSessionRequest's two codes from a return value to a
//     writeJSONError call.
//   - writeValidationError's *i18n.LocalizedError arm writes the catalog key as the error_code
//     ("validator.email.too_long" and its 90-odd siblings), which is a deliberate second family
//     from #247 and not one of these. It arrives through localizedErr.Code, a selector rather than
//     a literal, inside a forwarder, so it is out of this table by construction rather than by an
//     exception someone has to remember.

// apiErrorCodes is the survivor table: every error_code the admin and account API may write, and
// who acts on it. "Category" means no caller routes on it and the HTTP status carries the meaning;
// it is the answer decision 18 flattened the spellings into.
var apiErrorCodes = map[string]string{
	// The three generic conditions decision 18 settled.
	"VALIDATION_ERROR":     "category: a rejected value, 400. Also routed on by the console's email-settings page.",
	"INVALID_REQUEST_BODY": "category: a body that will not parse, 400.",
	"NOT_FOUND":            "category: an absent entity, 404.",

	// Codes the admin console's Go code routes on, beyond VALIDATION_ERROR above.
	// isHandledAccountOTPError in adminconsole/.../handler_account_otp.go holds the first seven.
	"AUTHENTICATION_FAILED":                "adminconsole: isHandledAccountOTPError redraws the OTP form with the API's sentence.",
	"INVALID_OTP_CODE":                     "adminconsole: isHandledAccountOTPError.",
	"OTP_CODE_REQUIRED":                    "adminconsole: isHandledAccountOTPError.",
	"OTP_ENROLLMENT_NOT_PENDING":           "adminconsole: isHandledAccountOTPError.",
	"SECRET_KEY_NOT_ACCEPTED":              "adminconsole: isHandledAccountOTPError.",
	"OTP_ALREADY_ENABLED":                  "adminconsole: isHandledAccountOTPError, and handler_account_otp.go:176 directly.",
	"OTP_NOT_ENABLED":                      "adminconsole: isHandledAccountOTPError.",
	"INVALID_OR_EXPIRED_VERIFICATION_CODE": "adminconsole: handler_account_email_verification.go:139.",
	"SMTP_NOT_ENABLED":                     "adminconsole: handler_admin_settings_email.go's switch redraws the settings form.",
	"SEND_FAILED":                          "adminconsole: handler_admin_settings_email.go's switch.",

	// Conditions an integrator can act on, distinguishable from a plain rejected value. Named in
	// the agreement's section 4 as codes a caller acts on, and documented in openapi.yaml.
	"EMAIL_ALREADY_EXISTS": "409 on createUser: the address is taken, so the caller picks another.",
	"EMAIL_TOO_LONG":       "400: the address exceeds the column, so the caller shortens it.",
	"VALUE_TOO_LONG":       "400: an attribute value exceeds the column.",
	"FILE_TOO_LARGE":       "400 on an upload: the caller re-encodes smaller.",
	"NO_FILE":              "400 on an upload: the multipart part is missing.",
	"CONCURRENT_UPDATE":    "409 on a list save: the stored list changed after it was loaded, or another save added the same value at the same moment, so the caller reads the list again and retries.",

	// Authentication and authorization. A caller distinguishes "send a token", "the token is
	// malformed", "the token is not good enough" and "the session is gone", and retries differently
	// for each. ACCESS_TOKEN_REQUIRED, INVALID_TOKEN_FORMAT and INSUFFICIENT_SCOPE are the bearer
	// middleware's; the rest are handlers'.
	"ACCESS_TOKEN_REQUIRED": "401: no bearer token, so the caller obtains one.",
	"INVALID_TOKEN_FORMAT":  "401: the bearer token is not a JWT.",
	"INVALID_TOKEN":         "401: the bearer token did not validate.",
	"INVALID_SUBJECT":       "401: the token's subject is not a user this server knows.",
	"INVALID_SESSION":       "401: the session behind the token is gone.",
	"USER_CONTEXT_REQUIRED": "401: the endpoint needs a user, and the token carries none.",
	"UNAUTHORIZED":          "401: the caller may not act on this resource.",
	"INSUFFICIENT_SCOPE":    "403: the token's scopes do not cover the route.",
	"FORBIDDEN":             "403: the caller may not act on this resource.",

	// Key rotation, kept by decision 7 where every other 500-adjacent code went: a caller acts on
	// both, and openapi.yaml documents them.
	"ROTATION_IN_PROGRESS": "409 on rotateKeys: another rotation holds the lock, so the caller retries later.",
	"KEY_SET_INCOMPLETE":   "500 on rotateKeys: the key set is not in a rotatable state.",

	// Written outside a handler, by something in front of one.
	"INTERNAL_SERVER_ERROR": "category: every 500 on this surface, decision 7.",
	"METHOD_NOT_ALLOWED":    "405 from the public-settings endpoint, which answers JSON refusals since decision 17.",
	"TOO_MANY_REQUESTS":     "429 from the auth server's rate limiter: the caller waits and retries.",
}

// apiErrorCodeDirs are the three directories that write this envelope, relative to the source root.
// authserver/internal/handlers covers apihandlers and handler_public_settings.go; middleware uses
// the same apiresponse writer as the handlers.
var apiErrorCodeDirs = []string{
	"authserver/internal/handlers",
	"authserver/internal/apiresponse",
	"authserver/internal/middleware",
}

// apiErrorCodeArg maps a call that writes an error code to the argument index the code is in.
// Matched on the function's own name, so apiresponse.WriteError and a package-local WriteError are
// the same entry.
var apiErrorCodeArg = map[string]int{
	"writeJSONError": 2,
	"WriteError":     2,
	"emitAuthError":  1,
	// (w, r, err, message, code): the 500 that keeps an operation code a caller acts on. Its own
	// body forwards that code to writeJSONError, so it is a forwarder below as well.
	"writeInternalServerErrorWithCode": 4,
}

// apiErrorCodeForwarders are the functions whose code argument is their caller's, so a non-literal
// in the code position there is the design rather than a hole in it. Every other function must
// write a literal.
var apiErrorCodeForwarders = map[string]bool{
	"writeJSONError":                   true,
	"writeValidationError":             true,
	"writeInternalServerErrorWithCode": true,
	"WriteError":                       true,
	"WriteInternalServerError":         true,
	"emitAuthError":                    true,
}

// emittedAPICode is one error_code written on this surface, located.
type emittedAPICode struct {
	file string
	line int
	code string
}

func TestAPIErrorCodes_MatchTheSurvivorTable(t *testing.T) {
	assertAPIErrorCodes(t, testutil.SourceRoot(t), apiErrorCodeDirs, apiErrorCodeFileFloor, apiErrorCodes)
}

// apiErrorCodeFileFloor is how many non-test Go files the three directories hold at rest. It is a
// floor rather than an exact count so ordinary growth does not move it, and it is a parameter
// rather than a literal so a rule test can pin the refusal itself.
const apiErrorCodeFileFloor = 60

// findAPIErrorCodes walks dirs under root and returns every error_code written on that surface, the
// code positions it could not read as a literal, and how many non-test Go files it parsed.
func findAPIErrorCodes(root string, dirs []string) ([]emittedAPICode, []string, int, error) {
	var files []string
	for _, dir := range dirs {
		start := filepath.Join(root, filepath.FromSlash(dir))
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "mocks" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return nil, nil, 0, errs.Wrapf(err, "walking %s", start)
		}
	}

	fset := token.NewFileSet()
	parsed := make(map[string]*ast.File, len(files))
	consts := map[string]string{}
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			// A file that does not parse is a compile error the build owns, and reporting it
			// here would send the reader to the wrong place.
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, nil, 0, errs.Wrapf(err, "relating %s to %s", path, root)
		}
		rel = filepath.ToSlash(rel)
		parsed[rel] = f
		for name, value := range stringConstsIn(f) {
			consts[name] = value
		}
	}

	var emitted []emittedAPICode
	var problems []string
	for rel, f := range parsed {
		codes, probs := collectAPIErrorCodes(fset, f, rel, consts)
		emitted = append(emitted, codes...)
		problems = append(problems, probs...)
	}
	sort.Strings(problems)
	return emitted, problems, len(files), nil
}

// assertAPIErrorCodes is the reporting half, taking the root, the scope, the floor and the table as
// parameters and failing through a testutil.Reporter so a rule test can drive it against a fixture
// tree. Without that seam these lines are reached only by the call above, which walks a surface
// that has matched its table since #279.
func assertAPIErrorCodes(r testutil.Reporter, root string, dirs []string, floor int, table map[string]string) {
	r.Helper()

	emitted, problems, files, err := findAPIErrorCodes(root, dirs)
	if err != nil {
		r.Fatalf("%v", err)
	}
	// A walk that reached nothing would pass every assertion below, which is the one way a guard
	// like this fails in the permissive direction.
	if files < floor {
		r.Fatalf("walked only %d non-test Go files under %s; the walk is no longer reaching the "+
			"API sources", files, strings.Join(dirs, ", "))
	}

	for _, p := range problems {
		r.Errorf("%s", p)
	}

	seen := map[string]bool{}
	var unknown []string
	for _, e := range emitted {
		seen[e.code] = true
		if _, ok := table[e.code]; !ok {
			unknown = append(unknown, e.file+":"+strconv.Itoa(e.line)+": "+e.code)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		r.Errorf("%d error_code(s) the API writes are not in the survivor table:\n\t%s\n\n"+
			"One code per condition: a rejected value is VALIDATION_ERROR, a body that will not "+
			"parse is INVALID_REQUEST_BODY, an absent entity is NOT_FOUND. Add an entry to "+
			"apiErrorCodes only for a code a caller can act on, and say who acts on it (#279 "+
			"decision 18).", len(unknown), strings.Join(unknown, "\n\t"))
	}

	var orphaned []string
	for code := range table {
		if !seen[code] {
			orphaned = append(orphaned, code)
		}
	}
	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		r.Errorf("%d survivor-table entr(ies) no longer written anywhere: %s\n\n"+
			"Delete them. A table listing codes the API cannot produce documents nothing and "+
			"stops being read.", len(orphaned), strings.Join(orphaned, ", "))
	}
}

// stringConstsIn returns the file's package-level string constants, so a code written as a named
// constant (apiresponse's internalServerErrorCode) is read as the value it holds.
func stringConstsIn(f *ast.File) map[string]string {
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
				if lit, ok := stringLiteralValue(value.Values[i]); ok {
					out[name.Name] = lit
				}
			}
		}
	}
	return out
}

// collectAPIErrorCodes reads every error_code written in one file, from the three positions one can
// be written in, and reports each code position that is neither a literal nor a forwarder's
// pass-through.
func collectAPIErrorCodes(fset *token.FileSet, f *ast.File, rel string, consts map[string]string) ([]emittedAPICode, []string) {
	var codes []emittedAPICode
	problems := writerValues(fset, f, rel)

	record := func(expr ast.Expr, enclosing, position string) {
		line := fset.Position(expr.Pos()).Line
		if lit, ok := stringLiteralValue(expr); ok {
			codes = append(codes, emittedAPICode{file: rel, line: line, code: lit})
			return
		}
		if ident, ok := expr.(*ast.Ident); ok {
			if lit, ok := consts[ident.Name]; ok {
				codes = append(codes, emittedAPICode{file: rel, line: line, code: lit})
				return
			}
		}
		if apiErrorCodeForwarders[enclosing] {
			return
		}
		problems = append(problems, rel+":"+strconv.Itoa(line)+": "+position+" is not a string "+
			"literal, so no table can hold it to one code per condition. Write the code at the "+
			"call site, or pass it through a forwarder named in apiErrorCodeForwarders (#279 "+
			"decision 18).")
	}

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		enclosing := fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.CallExpr:
				name, ok := calleeName(e.Fun)
				if !ok {
					return true
				}
				index, ok := apiErrorCodeArg[name]
				if !ok || index >= len(e.Args) {
					return true
				}
				record(e.Args[index], enclosing, name+"'s code argument")
			case *ast.CompositeLit:
				if !isErrorResponseType(e.Type) {
					return true
				}
				for _, elt := range e.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != "ErrorCode" {
						continue
					}
					record(kv.Value, enclosing, "ErrorResponse.ErrorCode")
				}
			}
			return true
		})
	}
	return codes, problems
}

// calleeName is the function's own name, whether it was called bare, through a package qualifier,
// or through parentheses. (writeJSONError)(...) writes exactly what writeJSONError(...) writes, and
// a collector reading only the bare form is one pair of brackets away from seeing nothing.
func calleeName(fun ast.Expr) (string, bool) {
	switch f := unparenExpr(fun).(type) {
	case *ast.Ident:
		return f.Name, true
	case *ast.SelectorExpr:
		return f.Sel.Name, true
	}
	return "", false
}

// unparenExpr strips the parentheses around an expression.
func unparenExpr(e ast.Expr) ast.Expr {
	for {
		paren, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = paren.X
	}
}

// writerValues reports each place a writer named in apiErrorCodeArg is named without being called.
// A writer stored in a variable and called through it leaves a bare identifier the collector cannot
// resolve, so the codes it writes are invisible to the survivor table -- the same hole a
// parenthesized callee opened, one indirection further along. Refusing the value is the answer
// rather than following it, which would mean tracking every assignment, parameter and field it
// passes through; nothing on this surface names one today.
func writerValues(fset *token.FileSet, f *ast.File, rel string) []string {
	callees := map[*ast.Ident]bool{}
	selectors := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := unparenExpr(call.Fun).(type) {
		case *ast.Ident:
			callees[fun] = true
		case *ast.SelectorExpr:
			selectors[fun] = true
		}
		return true
	})

	var problems []string
	report := func(pos token.Pos, name string) {
		problems = append(problems, rel+":"+strconv.Itoa(fset.Position(pos).Line)+": "+name+
			" is named here without being called, so any code it later writes is invisible to the "+
			"survivor table. Call it where the code is written (#279 decision 18).")
	}
	declared := map[*ast.Ident]bool{}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			declared[fn.Name] = true
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch it := n.(type) {
		case *ast.SelectorExpr:
			if _, known := apiErrorCodeArg[it.Sel.Name]; known && !selectors[it] {
				report(it.Pos(), it.Sel.Name)
			}
			// The selector's own Sel is this name, not an independent mention of it, so the
			// Ident arm below must not see it a second time.
			return false
		case *ast.Ident:
			if _, known := apiErrorCodeArg[it.Name]; known && !callees[it] && !declared[it] {
				report(it.Pos(), it.Name)
			}
		}
		return true
	})
	return problems
}

// isErrorResponseType reports whether a composite literal builds api.ErrorResponse, written either
// qualified or bare.
func isErrorResponseType(t ast.Expr) bool {
	switch x := t.(type) {
	case *ast.Ident:
		return x.Name == "ErrorResponse"
	case *ast.SelectorExpr:
		return x.Sel.Name == "ErrorResponse"
	}
	return false
}

func stringLiteralValue(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

// TestAPIErrorCodes_CollectorRuleTable pins the collector against source text, one row per rule,
// because the walk above can only report what the collector sees and a collector that saw nothing
// would report nothing wrong.
func TestAPIErrorCodes_CollectorRuleTable(t *testing.T) {
	consts := map[string]string{"internalServerErrorCode": "INTERNAL_SERVER_ERROR"}

	tests := []struct {
		name     string
		src      string
		codes    []string
		problems int
	}{
		{
			name: "writeJSONError's third argument is a code",
			src: `package p
func HandleX() { writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound) }`,
			codes: []string{"NOT_FOUND"},
		},
		{
			name: "WriteError through a package qualifier is a code",
			src: `package p
func HandleX() { apiresponse.WriteError(w, "Method not allowed", "METHOD_NOT_ALLOWED", 405) }`,
			codes: []string{"METHOD_NOT_ALLOWED"},
		},
		{
			name: "emitAuthError's second argument is a code",
			src: `package p
func HandleX() { emitAuthError(w, "INSUFFICIENT_SCOPE", "Insufficient scope.", 403, true) }`,
			codes: []string{"INSUFFICIENT_SCOPE"},
		},
		{
			name: "an ErrorResponse literal's ErrorCode field is a code",
			src: `package p
func HandleX() { _ = json.NewEncoder(w).Encode(api.ErrorResponse{ErrorCode: "TOO_MANY_REQUESTS", ErrorDescription: "d"}) }`,
			codes: []string{"TOO_MANY_REQUESTS"},
		},
		{
			name: "a named string constant resolves to its value",
			src: `package p
func HandleX() { WriteError(w, "m", internalServerErrorCode, 500) }`,
			codes: []string{"INTERNAL_SERVER_ERROR"},
		},
		{
			name: "a computed code outside a forwarder is a problem",
			src: `package p
func HandleX() { writeJSONError(w, message, code, http.StatusBadRequest) }`,
			problems: 1,
		},
		{
			name: "the same computed code inside a forwarder is the design",
			src: `package p
func writeJSONError(w http.ResponseWriter, message, code string, statusCode int) {
	apiresponse.WriteError(w, message, code, statusCode)
}`,
			problems: 0,
		},
		{
			name: "a localized error's catalog key passes through writeValidationError untouched",
			src: `package p
func writeValidationError(w http.ResponseWriter, r *http.Request, err error) {
	writeJSONError(w, localizedErr.Localize(r.Context()), localizedErr.Code, http.StatusBadRequest)
	writeJSONError(w, errorDetail.GetDescription(), "VALIDATION_ERROR", http.StatusBadRequest)
}`,
			codes: []string{"VALIDATION_ERROR"},
		},
		{
			// The three shapes the final review's round 3 got three retired codes past the
			// collector with. A parenthesized callee writes exactly what the bare one writes, and
			// a writer stored in a value writes it one indirection later with no name left to
			// resolve; the first is now read as the call it is, the second two are refused at the
			// point the writer is named.
			name: "a parenthesized writer is still a writer",
			src: `package p
func HandleX() { (writeJSONError)(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound) }`,
			codes: []string{"USER_NOT_FOUND"},
		},
		{
			name: "a writer stored in a value is refused where it is named",
			src: `package p
func HandleX() {
	write := writeJSONError
	write(w, "Client not found", "CLIENT_NOT_FOUND", http.StatusNotFound)
}`,
			problems: 1,
		},
		{
			name: "a package-qualified writer stored in a value is refused the same way",
			src: `package p
func HandleX() {
	write := apiresponse.WriteError
	write(w, "Attribute not found", "ATTRIBUTE_NOT_FOUND", http.StatusNotFound)
}`,
			problems: 1,
		},
		{
			name: "a code-shaped literal somewhere else is not a code",
			src: `package p
func HandleX() { r.Method = "DELETE"; alg := "RS256"; _ = alg }`,
		},
		{
			name: "a package-level var initializer is not a call and holds nothing",
			src: `package p
var codes = []string{"USER_NOT_FOUND"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "fixture.go", test.src, 0)
			if err != nil {
				t.Fatalf("parsing the fixture: %v", err)
			}
			codes, problems := collectAPIErrorCodes(fset, f, "fixture.go", consts)

			var got []string
			for _, c := range codes {
				got = append(got, c.code)
			}
			if strings.Join(got, ",") != strings.Join(test.codes, ",") {
				t.Errorf("codes: got %v, want %v", got, test.codes)
			}
			if len(problems) != test.problems {
				t.Errorf("problems: got %d %v, want %d", len(problems), problems, test.problems)
			}
		})
	}
}

// ---- the reporting half ----------------------------------------------------------------------
//
// TestAPIErrorCodes_CollectorRuleTable asserts on what the collector returned for one file at a
// time. The lines that turn those codes into a failure -- both directions of the table comparison,
// the unreadable code position, and the file floor -- were reached only by
// TestAPIErrorCodes_MatchTheSurvivorTable, which walks a surface that has matched its table since
// #279, so blinding them disables the contract lint with nothing going red.

// apiErrorCodeFixture writes a one-directory surface and returns its root.
func apiErrorCodeFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

// apiErrorCodeFixtureDirs is the one directory the fixtures below write into.
var apiErrorCodeFixtureDirs = []string{"authserver/internal/handlers"}

// TestAPIErrorCodes_TheGuardPassesASurfaceThatMatchesItsTable is the clean direction, and it is
// what keeps each case below from passing for the wrong reason.
func TestAPIErrorCodes_TheGuardPassesASurfaceThatMatchesItsTable(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX() { writeJSONError(w, "User not found", "NOT_FOUND", 404) }
`,
	})

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAPIErrorCodes(r, root, apiErrorCodeFixtureDirs, 1, map[string]string{
			"NOT_FOUND": "category: an absent entity, 404.",
		})
	})

	assert.False(t, report.Failed(), "a surface matching its table failed the guard: %s", report.Text())
}

// TestAPIErrorCodes_TheGuardFailsOnACodeOutsideTheTable is the direction that catches a retired
// spelling coming back, which is how this regresses: a new handler written from an old one.
func TestAPIErrorCodes_TheGuardFailsOnACodeOutsideTheTable(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX() { writeJSONError(w, "User not found", "USER_NOT_FOUND", 404) }
`,
	})

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAPIErrorCodes(r, root, apiErrorCodeFixtureDirs, 1, map[string]string{
			"NOT_FOUND": "category: an absent entity, 404.",
		})
	})

	require.True(t, report.Failed(), "a code outside the table passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/users.go:3")
	assert.Contains(t, report.Text(), "USER_NOT_FOUND")
	assert.Contains(t, report.Text(), "not in the survivor table")
	assert.Contains(t, report.Text(), "decision 18")
	// And the entry nothing writes any more is reported alongside it, since both directions run.
	assert.Contains(t, report.Text(), "no longer written anywhere: NOT_FOUND")
}

// TestAPIErrorCodes_TheGuardFailsOnATableEntryNothingWrites is the other direction on its own, and
// it is the one that keeps the table from rotting into a list of codes the API no longer has --
// which is how a lint stops meaning anything.
func TestAPIErrorCodes_TheGuardFailsOnATableEntryNothingWrites(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX() { writeJSONError(w, "User not found", "NOT_FOUND", 404) }
`,
	})

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAPIErrorCodes(r, root, apiErrorCodeFixtureDirs, 1, map[string]string{
			"NOT_FOUND": "category: an absent entity, 404.",
			"RETIRED":   "nothing writes this any more.",
		})
	})

	require.True(t, report.Failed(), "a table entry nothing writes passed the guard")
	require.Len(t, report.Errors, 1, "the emitted code is in the table, so only one direction fires")
	assert.Contains(t, report.Text(), "no longer written anywhere: RETIRED")
	assert.Contains(t, report.Text(), "Delete them")
}

// TestAPIErrorCodes_TheGuardFailsOnACodePositionItCannotRead holds the first of the two boundaries
// the file header states. The scan reads a code where a code is written, so a code position that is
// not a literal is a failure in its own right rather than a site quietly skipped.
func TestAPIErrorCodes_TheGuardFailsOnACodePositionItCannotRead(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX(code string) { writeJSONError(w, "User not found", code, 404) }
`,
	})

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAPIErrorCodes(r, root, apiErrorCodeFixtureDirs, 1, map[string]string{})
	})

	require.True(t, report.Failed(), "an unreadable code position passed the guard")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/users.go:3")
}

// TestAPIErrorCodes_TheGuardIsFatalBelowTheFileFloor pins this guard's own answer to the empty
// walk. It is a floor rather than a zero because the surface is four named directories: a walk that
// reached one of them and not the others would pass every assertion above while checking a quarter
// of the contract.
func TestAPIErrorCodes_TheGuardIsFatalBelowTheFileFloor(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX() { writeJSONError(w, "User not found", "NOT_FOUND", 404) }
`,
	})

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAPIErrorCodes(r, root, apiErrorCodeFixtureDirs, 2, map[string]string{
			"NOT_FOUND": "category: an absent entity, 404.",
		})
	})

	require.True(t, report.Stopped, "a walk below the floor must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked only 1 non-test Go files")
	assert.Contains(t, report.Fatal, "no longer reaching the API sources")
}

// TestAPIErrorCodes_TheFileFloorIsBelowTheRealSurface holds the floor to the tree it guards. A
// constant set above the real count would fail every run; one set far below it would stop being a
// floor, so the margin is what this pins.
func TestAPIErrorCodes_TheFileFloorIsBelowTheRealSurface(t *testing.T) {
	_, _, files, err := findAPIErrorCodes(testutil.SourceRoot(t), apiErrorCodeDirs)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, files, apiErrorCodeFileFloor)
	assert.Less(t, apiErrorCodeFileFloor, files*2,
		"the floor has drifted far below the surface it guards and would no longer catch a walk "+
			"that lost most of it")
}
