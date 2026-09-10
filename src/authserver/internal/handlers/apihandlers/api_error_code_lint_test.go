package apihandlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

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
//   - The scan is lexical over four directories and it reads a code where a code is written, not
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
	"TOO_MANY_REQUESTS":     "429 from core's rate limiter: the caller waits and retries.",
}

// apiErrorCodeDirs are the four directories that write this envelope, relative to the source root.
// authserver/internal/handlers covers apihandlers and handler_public_settings.go; the two
// middleware directories write it without going through a helper, the rate limiter because it lives
// in core and cannot see the authserver's unexported writer.
var apiErrorCodeDirs = []string{
	"authserver/internal/handlers",
	"authserver/internal/apiresponse",
	"authserver/internal/middleware",
	"core/middleware",
}

// apiErrorCodeArg maps a call that writes an error code to the argument index the code is in.
// Matched on the function's own name, so apiresponse.WriteError and a package-local WriteError are
// the same entry.
var apiErrorCodeArg = map[string]int{
	"writeJSONError": 2,
	"WriteError":     2,
	"emitAuthError":  1,
}

// apiErrorCodeForwarders are the functions whose code argument is their caller's, so a non-literal
// in the code position there is the design rather than a hole in it. Every other function must
// write a literal.
var apiErrorCodeForwarders = map[string]bool{
	"writeJSONError":           true,
	"writeValidationError":     true,
	"WriteError":               true,
	"WriteInternalServerError": true,
	"emitAuthError":            true,
}

// emittedAPICode is one error_code written on this surface, located.
type emittedAPICode struct {
	file string
	line int
	code string
}

func TestAPIErrorCodes_MatchTheSurvivorTable(t *testing.T) {
	root := testutil.SourceRoot(t)

	var files []string
	for _, dir := range apiErrorCodeDirs {
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
			t.Fatalf("walking %s: %v", start, err)
		}
	}
	// A walk that reached nothing would pass every assertion below, which is the one way a guard
	// like this fails in the permissive direction.
	if len(files) < 60 {
		t.Fatalf("walked only %d non-test Go files under %s; the walk is no longer reaching the "+
			"API sources", len(files), strings.Join(apiErrorCodeDirs, ", "))
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
			t.Fatalf("relating %s to %s: %v", path, root, err)
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
	for _, p := range problems {
		t.Errorf("%s", p)
	}

	seen := map[string]bool{}
	var unknown []string
	for _, e := range emitted {
		seen[e.code] = true
		if _, ok := apiErrorCodes[e.code]; !ok {
			unknown = append(unknown, e.file+":"+strconv.Itoa(e.line)+": "+e.code)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Errorf("%d error_code(s) the API writes are not in the survivor table:\n\t%s\n\n"+
			"One code per condition: a rejected value is VALIDATION_ERROR, a body that will not "+
			"parse is INVALID_REQUEST_BODY, an absent entity is NOT_FOUND. Add an entry to "+
			"apiErrorCodes only for a code a caller can act on, and say who acts on it (#279 "+
			"decision 18).", len(unknown), strings.Join(unknown, "\n\t"))
	}

	var orphaned []string
	for code := range apiErrorCodes {
		if !seen[code] {
			orphaned = append(orphaned, code)
		}
	}
	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		t.Errorf("%d survivor-table entr(ies) no longer written anywhere: %s\n\n"+
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
	var problems []string

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

// calleeName is the function's own name, whether it was called bare or through a package qualifier.
func calleeName(fun ast.Expr) (string, bool) {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name, true
	case *ast.SelectorExpr:
		return f.Sel.Name, true
	}
	return "", false
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
