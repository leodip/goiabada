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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/guard"
)

// The admin and account API answers a person's refusal in the language the request names, and this
// file is what keeps that true. The admin console shows the API's sentence for a 400 or a 409 and
// its own page for every other status, so those two statuses are the whole surface a person reads.
// Every 400 or 409 written here in English must be one of the sentences in machineOnlyRefusals, each
// of which names the class of #559 decision 1 it belongs to: a body that does not parse, an id in
// the path or query that is missing or malformed, a list save's missing expected* list, and the
// annotate* query parameters. Those address an integrator debugging a request, for whom English is the documented
// default. Every other refusal goes through writeLocalizedError or writeValidationError with a
// catalog key, and arrives in pt-BR when the console's page is in pt-BR (#559 decisions 1 and 4).
//
// Both directions are checked, as the survivor table beside it checks them. A sentence outside the
// table is how this regresses: a new handler written from an old one, answering a person in English
// through writeJSONError. A table entry nothing writes is how the table rots into a list that
// excuses whatever comes back under that spelling.
//
// The boundaries, stated rather than discovered later:
//
//   - The scan is lexical over authserver/internal/handlers, and reads a message and a status where
//     they are written. A 400 or 409 whose message is not a literal, or a write whose status is not
//     a constant, is a failure in its own right, except inside the writers named in
//     englishRefusalForwarders, whose whole job is to pass a caller's message through.
//   - writeLocalizedError and writeValidationError are exempt by name: each forwards a caller's
//     error, and what it writes is that error's own. writeValidationError's last arm writes an
//     error that is neither localized nor an oauth.ErrorDetail as its English text; a validator
//     returning one is held by the catalog's parity test only when it returns a catalog key.
//   - A writer stored in a value, rather than called, is refused by writerValues in
//     api_error_code_lint_test.go over the same directory, so it cannot carry a sentence past this
//     scan either.
//   - A sentence is matched by its spelling, wherever it is written. An id read from a decoded body
//     is a field like any other, not a malformed target, so its refusal goes through
//     writeLocalizedError even when a path id's English refusal says the same words, as the group
//     attribute's groupId does with handler.group_attribute.group_id_required.
//   - The bearer middleware's 400 is outside the scope: it answers RFC 6750's invalid_request before
//     any handler runs, on a token no console request can send twice. Its refusals are held English
//     by TestBearerRefusals_EnglishOnly in internal/middleware instead.

// machineOnlyClass is one of the four classes of #559 decision 1, the refusals only a malformed
// request can produce.
type machineOnlyClass string

const (
	classUnparseableBody  machineOnlyClass = "a body that does not parse"
	classMissingOrBadID   machineOnlyClass = "an id in the path or query that is missing or malformed"
	classMissingExpected  machineOnlyClass = "a list save's missing expected* list"
	classAnnotateArgument machineOnlyClass = "an annotate* query parameter"
)

// machineOnlyClasses is the closed set a table entry may name.
var machineOnlyClasses = map[machineOnlyClass]bool{
	classUnparseableBody:  true,
	classMissingOrBadID:   true,
	classMissingExpected:  true,
	classAnnotateArgument: true,
}

// machineOnlyRefusals is every 400 or 409 sentence the admin and account API may still write in
// English, and the class of #559 decision 1 that keeps it English.
var machineOnlyRefusals = map[string]machineOnlyClass{
	"Invalid request body": classUnparseableBody,

	"Attribute ID is required":       classMissingOrBadID,
	"Client ID is required":          classMissingOrBadID,
	"Consent ID is required":         classMissingOrBadID,
	"Group ID is required":           classMissingOrBadID,
	"Group attribute ID is required": classMissingOrBadID,
	"Permission ID is required":      classMissingOrBadID,
	"Resource ID is required":        classMissingOrBadID,
	// The browser-session endpoint's, whose id rides in the body. That endpoint is not the admin or
	// account API: its one caller is the console's session backend, whose refusals no person reads
	// (#559 decision 3).
	"Session id is required":         classMissingOrBadID,
	"User ID is required":            classMissingOrBadID,
	"User session ID is required":    classMissingOrBadID,
	"Invalid attribute ID":           classMissingOrBadID,
	"Invalid client ID":              classMissingOrBadID,
	"Invalid client ID format":       classMissingOrBadID,
	"Invalid consent ID format":      classMissingOrBadID,
	"Invalid group ID":               classMissingOrBadID,
	"Invalid group ID format":        classMissingOrBadID,
	"Invalid group attribute ID":     classMissingOrBadID,
	"Invalid key ID":                 classMissingOrBadID,
	"Invalid permission ID format":   classMissingOrBadID,
	"Invalid resource ID":            classMissingOrBadID,
	"Invalid resource ID format":     classMissingOrBadID,
	"Invalid user ID":                classMissingOrBadID,
	"Invalid user ID format":         classMissingOrBadID,
	"Invalid user session ID format": classMissingOrBadID,

	"expectedGroupIds is required: send the group ids as you last read them, or [] if there were none.":                            classMissingExpected,
	"expectedPermissionIds is required: send the permission ids as you last read them, or [] if there were none.":                  classMissingExpected,
	"expectedPermissions is required: send the resource's permissions as you last read them, or [] if there were none.":            classMissingExpected,
	"expectedResourceIds is required: send the resource ids as you last read them, or [] if there were none.":                      classMissingExpected,
	"expectedRedirectURIs is required: send the redirect URIs as you last read them, or [] if there were none.":                    classMissingExpected,
	"expectedPostLogoutRedirectURIs is required: send the sign-out redirect URIs as you last read them, or [] if there were none.": classMissingExpected,
	"expectedWebOrigins is required: send the web origins as you last read them, or [] if there were none.":                        classMissingExpected,

	"annotateGroupMembership and annotatePermissionId cannot be used together": classAnnotateArgument,
	"annotatePermissionId is required":                                         classAnnotateArgument,
	"Invalid annotateGroupMembership value":                                    classAnnotateArgument,
	"Invalid annotatePermissionId":                                             classAnnotateArgument,
	"Invalid annotatePermissionId value":                                       classAnnotateArgument,
}

// englishRefusalDirs is the directory that writes the API's refusals, relative to the source root.
var englishRefusalDirs = []string{"authserver/internal/handlers"}

// englishRefusalFileFloor is how many non-test Go files that directory holds at rest, as a floor
// so ordinary growth does not move it and as a parameter so a rule test can pin the refusal.
const englishRefusalFileFloor = 80

// englishRefusalWriters maps a writer of the API envelope to the argument indexes of its message
// and its status. Matched on the function's own name, so apiresponse.WriteError and a
// package-local WriteError are the same entry.
var englishRefusalWriters = map[string]struct{ message, status int }{
	"writeJSONError": {message: 1, status: 3},
	"WriteError":     {message: 1, status: 3},
}

// englishRefusalForwarders are the functions whose message and status are their caller's, so a
// non-literal in either position there is the design rather than a hole in it.
var englishRefusalForwarders = map[string]bool{
	// The primitive: its caller names the message, and the call is what this guard reads.
	"writeJSONError": true,
	// The two that forward a caller's localized error (#559 decision 4).
	"writeLocalizedError":  true,
	"writeValidationError": true,
}

// writtenRefusal is one 400 or 409 sentence written on this surface, located.
type writtenRefusal struct {
	file     string
	line     int
	sentence string
}

func TestAPIRefusals_EnglishOnlyForTheMachineOnlyClasses(t *testing.T) {
	assertAPIRefusals(t, guard.SourceRoot(t), englishRefusalDirs, englishRefusalFileFloor, machineOnlyRefusals)
}

// findAPIRefusals walks dirs under root and returns every 400 or 409 sentence written there, the
// positions it could not read, and how many non-test Go files it parsed.
func findAPIRefusals(root string, dirs []string) ([]writtenRefusal, []string, int, error) {
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
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
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
			// A file that does not parse is a compile error the build owns.
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, nil, 0, errs.Wrapf(err, "relating %s to %s", path, root)
		}
		parsed[filepath.ToSlash(rel)] = f
		for name, value := range stringConstsIn(f) {
			consts[name] = value
		}
	}

	var written []writtenRefusal
	var problems []string
	for rel, f := range parsed {
		refusals, probs := collectAPIRefusals(fset, f, rel, consts)
		written = append(written, refusals...)
		problems = append(problems, probs...)
	}
	sort.Strings(problems)
	return written, problems, len(files), nil
}

// assertAPIRefusals is the reporting half, taking the root, the scope, the floor and the table as
// parameters and failing through a guard.Reporter so a rule test can drive it against a fixture
// tree.
func assertAPIRefusals(r guard.Reporter, root string, dirs []string, floor int, table map[string]machineOnlyClass) {
	r.Helper()

	written, problems, files, err := findAPIRefusals(root, dirs)
	if err != nil {
		r.Fatalf("%v", err)
	}
	// A walk that reached nothing would pass every assertion below.
	if files < floor {
		r.Fatalf("walked only %d non-test Go files under %s; the walk is no longer reaching the "+
			"API sources", files, strings.Join(dirs, ", "))
	}

	for _, p := range problems {
		r.Errorf("%s", p)
	}

	var unclassed []string
	for sentence, class := range table {
		if !machineOnlyClasses[class] {
			unclassed = append(unclassed, strconv.Quote(sentence)+" names "+strconv.Quote(string(class)))
		}
	}
	sort.Strings(unclassed)
	if len(unclassed) > 0 {
		r.Errorf("%d machine-only entr(ies) name no class of #559 decision 1:\n\t%s\n\n"+
			"An English refusal is kept only for a body that does not parse, an id in the path or "+
			"query that is missing or malformed, a missing expected* list, or an annotate* parameter.",
			len(unclassed), strings.Join(unclassed, "\n\t"))
	}

	seen := map[string]bool{}
	var english []string
	for _, w := range written {
		seen[w.sentence] = true
		if _, ok := table[w.sentence]; !ok {
			english = append(english, w.file+":"+strconv.Itoa(w.line)+": "+strconv.Quote(w.sentence))
		}
	}
	sort.Strings(english)
	if len(english) > 0 {
		r.Errorf("%d 400 or 409 refusal(s) the API writes in English:\n\t%s\n\n"+
			"A person reads these on the admin console in its own language. Put the sentence in "+
			"both catalogs and write it through writeLocalizedError(w, r, i18n.NewLocalizedError("+
			"i18n.ErrCode..., nil), code, status), which keeps its code and status. Add it to "+
			"machineOnlyRefusals only when it is one of the four classes of #559 decision 1.",
			len(english), strings.Join(english, "\n\t"))
	}

	var orphaned []string
	for sentence := range table {
		if !seen[sentence] {
			orphaned = append(orphaned, strconv.Quote(sentence))
		}
	}
	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		r.Errorf("%d machine-only entr(ies) no longer written anywhere: %s\n\n"+
			"Delete them. An entry nothing writes excuses whatever comes back under that spelling.",
			len(orphaned), strings.Join(orphaned, ", "))
	}
}

// collectAPIRefusals reads every 400 or 409 sentence written in one file, and reports each write
// whose status or, at a 400 or 409, whose message it cannot read outside a forwarder.
func collectAPIRefusals(fset *token.FileSet, f *ast.File, rel string, consts map[string]string) ([]writtenRefusal, []string) {
	var refusals []writtenRefusal
	var problems []string
	problem := func(expr ast.Expr, what string) {
		problems = append(problems, rel+":"+strconv.Itoa(fset.Position(expr.Pos()).Line)+": "+what+
			", so no table can hold it to the machine-only classes. Write a 400 or 409 a person "+
			"reads through writeLocalizedError with a catalog key, or a machine-only sentence as a "+
			"literal at the call (#559 decision 4).")
	}

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		forwarder := englishRefusalForwarders[fn.Name.Name]
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.CallExpr:
				name, ok := calleeName(e.Fun)
				if !ok {
					return true
				}
				at, ok := englishRefusalWriters[name]
				if !ok || at.message >= len(e.Args) || at.status >= len(e.Args) {
					return true
				}
				refusal, known := isRefusalStatus(e.Args[at.status])
				if !known {
					if !forwarder {
						problem(e.Args[at.status], name+"'s status is not a constant")
					}
					return true
				}
				if !refusal {
					return true
				}
				message := e.Args[at.message]
				line := fset.Position(message.Pos()).Line
				if lit, ok := stringLiteralValue(message); ok {
					refusals = append(refusals, writtenRefusal{file: rel, line: line, sentence: lit})
					return true
				}
				if ident, ok := message.(*ast.Ident); ok {
					if lit, ok := consts[ident.Name]; ok {
						refusals = append(refusals, writtenRefusal{file: rel, line: line, sentence: lit})
						return true
					}
				}
				if !forwarder {
					problem(message, name+"'s message at a 400 or 409 is not a string literal")
				}
			case *ast.CompositeLit:
				if isErrorResponseType(e.Type) && !forwarder {
					problem(e, "an ErrorResponse built by hand carries its description apart from its status")
				}
			}
			return true
		})
	}
	return refusals, problems
}

// isRefusalStatus reads a status argument: refusal is whether it is 400 or 409, and known is
// whether it could be read at all. A status is read from net/http's named constant or from a
// number.
func isRefusalStatus(expr ast.Expr) (refusal, known bool) {
	switch s := unparenExpr(expr).(type) {
	case *ast.SelectorExpr:
		pkg, ok := s.X.(*ast.Ident)
		if !ok || pkg.Name != "http" || !strings.HasPrefix(s.Sel.Name, "Status") {
			return false, false
		}
		return s.Sel.Name == "StatusBadRequest" || s.Sel.Name == "StatusConflict", true
	case *ast.BasicLit:
		if s.Kind != token.INT {
			return false, false
		}
		return s.Value == "400" || s.Value == "409", true
	}
	return false, false
}

// TestAPIRefusals_CollectorRuleTable pins the collector against source text, one row per rule,
// because the walk can only report what the collector sees.
func TestAPIRefusals_CollectorRuleTable(t *testing.T) {
	consts := map[string]string{"invalidBody": "Invalid request body"}

	tests := []struct {
		name      string
		src       string
		sentences []string
		problems  int
	}{
		{
			name: "writeJSONError at 400 writes its second argument",
			src: `package p
func HandleX() { writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest) }`,
			sentences: []string{"Invalid user ID"},
		},
		{
			name: "a 409 is a refusal a person reads",
			src: `package p
func HandleX() { writeJSONError(w, "The list changed.", "CONCURRENT_UPDATE", http.StatusConflict) }`,
			sentences: []string{"The list changed."},
		},
		{
			name: "a status written as a number is read as one",
			src: `package p
func HandleX() { apiresponse.WriteError(w, "Name is required", "VALIDATION_ERROR", 400) }`,
			sentences: []string{"Name is required"},
		},
		{
			name: "a refusal written inside a handler's closure is read",
			src: `package p
func HandleX() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		(writeJSONError)(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
	}
}`,
			sentences: []string{"Resource ID is required"},
		},
		{
			name: "a named string constant resolves to its value",
			src: `package p
func HandleX() { writeJSONError(w, invalidBody, "INVALID_REQUEST_BODY", http.StatusBadRequest) }`,
			sentences: []string{"Invalid request body"},
		},
		{
			name: "a 404, a 401 and a 500 are not this surface",
			src: `package p
func HandleX() {
	writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
	writeJSONError(w, "Unauthorized", "INVALID_TOKEN", 401)
	writeJSONError(w, fmt.Sprintf("%s. Request Id: %v", message, id), code, http.StatusInternalServerError)
}`,
		},
		{
			name: "a formatted sentence at 400 is a problem",
			src: `package p
func HandleX(field string) { writeJSONError(w, "Invalid value for "+field, "VALIDATION_ERROR", http.StatusBadRequest) }`,
			problems: 1,
		},
		{
			name: "a sentence read from a variable at 409 is a problem",
			src: `package p
func HandleX(message string) { writeJSONError(w, message, "CONCURRENT_UPDATE", http.StatusConflict) }`,
			problems: 1,
		},
		{
			name: "a status the collector cannot read is a problem",
			src: `package p
func HandleX(status int) { writeJSONError(w, "Something went wrong", "VALIDATION_ERROR", status) }`,
			problems: 1,
		},
		{
			name: "the localizing writers forward their caller's error",
			src: `package p
func writeLocalizedError(w http.ResponseWriter, r *http.Request, message *i18n.LocalizedError, code string, statusCode int) {
	writeJSONError(w, message.Localize(r.Context()), code, statusCode)
}
func writeValidationError(w http.ResponseWriter, r *http.Request, err error) {
	writeJSONError(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
}`,
		},
		{
			name: "a call through a localizing writer writes no English",
			src: `package p
func HandleX() {
	writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeListSaveChangedSinceLoaded, nil), "CONCURRENT_UPDATE", http.StatusConflict)
	writeValidationError(w, r, err)
}`,
		},
		{
			name: "an error envelope built by hand is a problem, since its status is written elsewhere",
			src: `package p
func HandleX() { _ = json.NewEncoder(w).Encode(api.ErrorResponse{ErrorCode: "VALIDATION_ERROR", ErrorDescription: "Name is required"}) }`,
			problems: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "fixture.go", test.src, 0)
			require.NoError(t, err, "parsing the fixture")
			refusals, problems := collectAPIRefusals(fset, f, "fixture.go", consts)

			var got []string
			for _, w := range refusals {
				got = append(got, w.sentence)
			}
			assert.Equal(t, strings.Join(test.sentences, "|"), strings.Join(got, "|"), "sentences")
			assert.Len(t, problems, test.problems, "problems: %v", problems)
		})
	}
}

// ---- the reporting half ----------------------------------------------------------------------

// TestAPIRefusals_TheGuardPassesASurfaceThatMatchesItsTable is the clean direction, and it is what
// keeps each case below from passing for the wrong reason.
func TestAPIRefusals_TheGuardPassesASurfaceThatMatchesItsTable(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX() {
	writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
	writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeEmailAlreadyExists, nil), "EMAIL_ALREADY_EXISTS", http.StatusConflict)
}
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertAPIRefusals(r, root, englishRefusalDirs, 1, map[string]machineOnlyClass{
			"Invalid user ID": classMissingOrBadID,
		})
	})

	assert.False(t, report.Failed(), "a surface matching its table failed the guard: %s", report.Text())
}

// TestAPIRefusals_TheGuardFailsOnAnEnglishRefusal is the direction that catches a person's refusal
// written in English, which is how this regresses: a new handler written from an old one.
func TestAPIRefusals_TheGuardFailsOnAnEnglishRefusal(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/resources.go": `package handlers

func HandleX() { writeJSONError(w, "Resource identifier is required.", "VALIDATION_ERROR", http.StatusBadRequest) }
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertAPIRefusals(r, root, englishRefusalDirs, 1, map[string]machineOnlyClass{
			"Invalid user ID": classMissingOrBadID,
		})
	})

	require.True(t, report.Failed(), "an English refusal passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), `authserver/internal/handlers/resources.go:3: "Resource identifier is required."`)
	assert.Contains(t, report.Text(), "writeLocalizedError")
	assert.Contains(t, report.Text(), "#559 decision 1")
	// And the entry nothing writes any more is reported alongside it, since both directions run.
	assert.Contains(t, report.Text(), `no longer written anywhere: "Invalid user ID"`)
}

// TestAPIRefusals_TheGuardFailsOnATableEntryNothingWrites is the other direction on its own.
func TestAPIRefusals_TheGuardFailsOnATableEntryNothingWrites(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX() { writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest) }
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertAPIRefusals(r, root, englishRefusalDirs, 1, map[string]machineOnlyClass{
			"Invalid user ID":  classMissingOrBadID,
			"Invalid group ID": classMissingOrBadID,
		})
	})

	require.True(t, report.Failed(), "a table entry nothing writes passed the guard")
	require.Len(t, report.Errors, 1, "the written sentence is in the table, so only one direction fires")
	assert.Contains(t, report.Text(), `no longer written anywhere: "Invalid group ID"`)
	assert.Contains(t, report.Text(), "Delete them")
}

// TestAPIRefusals_TheGuardFailsOnAnEntryNamingNoClass holds every entry to one of decision 1's four
// classes, so the table cannot become a place to park a sentence nobody translated.
func TestAPIRefusals_TheGuardFailsOnAnEntryNamingNoClass(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX() { writeJSONError(w, "Name is required", "VALIDATION_ERROR", http.StatusBadRequest) }
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertAPIRefusals(r, root, englishRefusalDirs, 1, map[string]machineOnlyClass{
			"Name is required": machineOnlyClass("nobody translated it yet"),
		})
	})

	require.True(t, report.Failed(), "an entry naming no class passed the guard")
	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Text(), `"Name is required" names "nobody translated it yet"`)
}

// TestAPIRefusals_TheGuardFailsOnARefusalItCannotRead holds the first boundary the header states:
// a sentence the scan cannot read is a failure rather than a site quietly skipped.
func TestAPIRefusals_TheGuardFailsOnARefusalItCannotRead(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/users.go": `package handlers

func HandleX(message string) { writeJSONError(w, message, "VALIDATION_ERROR", http.StatusBadRequest) }
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertAPIRefusals(r, root, englishRefusalDirs, 1, map[string]machineOnlyClass{})
	})

	require.True(t, report.Failed(), "an unreadable refusal passed the guard")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/users.go:3")
}

// TestAPIRefusals_TheGuardIsFatalWhenTheWalkReachesNothing pins the guard's answer to the empty
// walk, which would otherwise pass every assertion.
func TestAPIRefusals_TheGuardIsFatalWhenTheWalkReachesNothing(t *testing.T) {
	root := apiErrorCodeFixture(t, map[string]string{
		"authserver/internal/handlers/README.md": "no Go here\n",
	})

	report := guard.Run(func(r guard.Reporter) {
		assertAPIRefusals(r, root, englishRefusalDirs, 1, map[string]machineOnlyClass{})
	})

	require.True(t, report.Stopped, "a walk that reached nothing must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked only 0 non-test Go files")
	assert.Contains(t, report.Fatal, "no longer reaching the API sources")
}

// TestAPIRefusals_TheFileFloorIsBelowTheRealSurface holds the floor to the tree it guards.
func TestAPIRefusals_TheFileFloorIsBelowTheRealSurface(t *testing.T) {
	_, _, files, err := findAPIRefusals(guard.SourceRoot(t), englishRefusalDirs)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, files, englishRefusalFileFloor)
	assert.Less(t, englishRefusalFileFloor, files*2,
		"the floor has drifted far below the surface it guards and would no longer catch a walk "+
			"that lost most of it")
}
