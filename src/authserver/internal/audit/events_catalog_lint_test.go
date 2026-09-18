package audit

// The one place the audit event names are held to "every declared event is in the catalog, and
// every catalogued event is declared".
//
// The rule exists because the two lists in events.go are written by hand and read by different
// people. A declaration is added by whoever emits the event; the catalog is read by the admin
// console's filter dropdown, over GET /api/v1/admin/audit-logs/event-types. Forget the second
// edit and the event is written to audit_logs and cannot be filtered for, which is the shape of
// defect an operator meets as "the log is missing rows" rather than as "the dropdown is short".
//
// Before this, nothing caught it. The suite looked like it did:
// TestAuditEventTypes_MatchesConstants compared the catalog against allAuditConstants, a THIRD
// hand-maintained list inside the test file, so it held two hand-written lists to each other
// and never reached the declarations. An Audit* constant added to the const block alone,
// touching neither the catalog nor that list, passed the whole package (#209; demonstrated
// against the pre-#351 tree by probe/audit-gap.sh).
//
// Both lists are parsed out of the source rather than generated from it, which is what every
// other text-against-code guard in this tree does -- AssertAgentDocs and AssertArchitecture both
// parse. Generating the catalog would close the gap by construction and cost a generator, one
// more go:generate line, a committed artifact and a third entry in the lint tier's
// regeneration check, for a list that changes a few times a year; it would also take over
// the alphabetical ordering TestAuditEventTypes_Alphabetical asserts today (#351
// decision 10).
//
// It reads and parses one file and nothing else: no database, no git, no network.

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

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditCatalogFile is the one file holding both lists, relative to the source root, forward
// slashes. Splitting them across files is not an extension point: the guard's whole claim is
// that the two edits an event needs are next to each other and checked together.
//
// That claim is checked rather than stated, by auditDeclarationsOutsideTheCatalogFile below.
// Without it the scope is the hole: an Audit* constant declared in any other file of this
// package is compared against nothing, so it can be emitted and absent from the catalog with
// every comparison here passing -- which is exactly the #209 defect, surviving inside the guard
// written to close it.
const auditCatalogFile = "authserver/internal/audit/events.go"

// auditCatalogSource is what one parse of that file yields: the Audit* constants it declares,
// name to value, and the identifier names the AuditEventTypes composite literal lists, in the
// order it lists them.
//
// The names are read as whole identifiers off the syntax tree rather than matched out of the
// text. That is not a stylistic preference: a pattern over the text has to state a character
// class, and the obvious letters-only one truncates AuditUpdatedClientOAuth2Flows at the digit
// to AuditUpdatedClientOAuth, which would then be reported as declared-but-not-catalogued and
// as catalogued-but-not-declared at once -- a difference that is not there (#209). An
// identifier off the tree cannot be truncated, and TestAuditCatalog_TheParserKeepsDigitsWhole
// pins that.
//
// mutable is the one shape that is neither: an Audit* name bound to a string with var rather
// than const, inside the catalog file. It is collected separately because it is refused rather
// than compared -- see the report in assertAuditCatalogComplete.
type auditCatalogSource struct {
	declared   map[string]string
	catalogued []string
	mutable    []string
}

// parseAuditCatalogSource reads the declarations and the catalog out of one Go file.
//
// AuditEventTypes itself is a var rather than a const, so it is never mistaken for one of the
// names it lists. A catalog entry that is not a bare identifier -- a string literal written out
// instead of the constant, say -- is reported under the spelling it was written with, so the
// failure sends the reader to the line rather than silently dropping the entry and reporting
// the constant it duplicates as missing.
//
// Every OTHER Audit* var bound to a string goes to src.mutable rather than to src.declared,
// because an event name declared that way is refused. Without this the var branch reaches only
// AuditEventTypes, so `var AuditFoo = "foo"` written into this file is in neither list: not
// compared against the catalog here, and not reached by the sibling scan below, which reads
// every file of the package EXCEPT this one. The sibling scan's own advice is to move an
// outside declaration into this file, so the guard would be telling an author how to make a
// declaration invisible to it.
func parseAuditCatalogSource(path string) (auditCatalogSource, error) {
	src := auditCatalogSource{declared: map[string]string{}}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return src, err
	}

	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		switch gen.Tok {
		case token.CONST:
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "Audit") || i >= len(vs.Values) {
						continue
					}
					value, ok := stringLiteralValue(vs.Values[i])
					if !ok {
						continue
					}
					src.declared[name.Name] = value
				}
			}
		case token.VAR:
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if name.Name != "AuditEventTypes" {
						if !strings.HasPrefix(name.Name, "Audit") || i >= len(vs.Values) {
							continue
						}
						if _, ok := stringLiteralValue(vs.Values[i]); !ok {
							continue
						}
						src.mutable = append(src.mutable, name.Name)
						continue
					}
					if len(vs.Names) != 1 || len(vs.Values) != 1 {
						continue
					}
					lit, ok := vs.Values[0].(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, elt := range lit.Elts {
						if id, ok := elt.(*ast.Ident); ok {
							src.catalogued = append(src.catalogued, id.Name)
							continue
						}
						if value, ok := stringLiteralValue(elt); ok {
							src.catalogued = append(src.catalogued, strconv.Quote(value))
							continue
						}
						src.catalogued = append(src.catalogued, "<not an identifier>")
					}
				}
			}
		}
	}

	sort.Strings(src.mutable)
	return src, nil
}

// stringLiteralValue unwraps a plain double-quoted string literal, which is how every audit
// event value is written. Anything else -- a concatenation, a reference to another constant --
// is refused rather than guessed at, so a value the guard cannot read is absent from the map
// instead of present with the wrong content.
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

// auditDeclarationsOutsideTheCatalogFile reads every other production Go file in the audit
// package and returns the Audit* string declarations they carry, "file: Name" apiece, alongside
// the names of the files it read.
//
// It returns what it scanned because an empty finding here is indistinguishable from a walk that
// reached nothing: the directory moving, or the suffix test going wrong, would leave this
// reporting no declarations outside the catalog file forever, which is the passing answer.
// TestAuditCatalog_TheSiblingScanReadsTheRestOfThePackage holds it to having read the real
// package's other file.
//
// Consts and vars alike, because the prefix is what makes a name an audit event here and a
// mutable one would escape a const-only scan for no reason. Test files are excluded: this file's
// own fixtures declare Audit* constants inside string literals, and a fixture is not a
// declaration the binary carries.
func auditDeclarationsOutsideTheCatalogFile(dir, catalogFile string) (scanned []string, outside []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == catalogFile {
			continue
		}
		scanned = append(scanned, name)

		f, parseErr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if parseErr != nil {
			return scanned, nil, parseErr
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if !strings.HasPrefix(ident.Name, "Audit") || i >= len(vs.Values) {
						continue
					}
					if _, ok := stringLiteralValue(vs.Values[i]); !ok {
						continue
					}
					outside = append(outside, name+": "+ident.Name)
				}
			}
		}
	}

	sort.Strings(outside)
	return scanned, outside, nil
}

// TestAuditCatalog_MatchesTheDeclarations holds the real file to the rule, and the compiled
// AuditEventTypes to the file.
func TestAuditCatalog_MatchesTheDeclarations(t *testing.T) {
	path := filepath.Join(testutil.SourceRoot(t), filepath.FromSlash(auditCatalogFile))
	assertAuditCatalogComplete(t, path, AuditEventTypes)
}

// assertAuditCatalogComplete is the reporting half, taking the file and the compiled slice as
// parameters and failing through a testutil.Reporter so a rule test can drive it against a
// fixture. Without that seam these lines are reached only by the call above, over a file that
// is correct by construction the moment anyone looks at it.
//
// It checks three things, and the third is the one that is easy to leave out. Parsing a file
// proves something about a file; it proves nothing about the binary unless the parsed values
// are held against what the binary actually carries. A guard pointed at a path that no longer
// participates in the build would otherwise pass forever.
func assertAuditCatalogComplete(r testutil.Reporter, path string, compiled []string) {
	r.Helper()

	src, err := parseAuditCatalogSource(path)
	if err != nil {
		r.Fatalf("parsing %s: %v", path, err)
	}
	// Either list coming back empty means the parse found nothing rather than that the tree is
	// clean, which is the one way a guard like this fails silently in the direction that
	// matters: the declarations moved, or the catalog was renamed, and every comparison below
	// then holds two empty sets to each other and passes.
	if len(src.declared) == 0 {
		r.Fatalf("parsed no Audit* declarations out of %s", path)
	}
	if len(src.catalogued) == 0 {
		r.Fatalf("parsed no AuditEventTypes entries out of %s", path)
	}

	// The declarations the parse above cannot see, because they are in another file. Reported
	// before the comparisons rather than folded into them: the answer is to move the constant
	// beside the catalog, not to add it to a catalog the guard would then be reading out of two
	// places.
	_, outside, err := auditDeclarationsOutsideTheCatalogFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		r.Fatalf("reading the audit package beside %s: %v", path, err)
	}
	if len(outside) > 0 {
		r.Errorf("%d Audit* declaration(s) in the audit package but outside %s:\n\t%s\n\n"+
			"Every audit event name is declared beside AuditEventTypes, because that is the only "+
			"way one guard can hold the two edits an event needs to each other: a name declared "+
			"elsewhere is emitted, written to audit_logs, and absent from the filter dropdown "+
			"with nothing going red. Move it into %s, declared with const. If it is not an event "+
			"name, it does not belong under the Audit prefix in this package (#209).",
			len(outside), auditCatalogFile, strings.Join(outside, "\n\t"), auditCatalogFile)
	}

	// An event name declared with var inside the catalog file. Refused rather than compared,
	// because a name that can be assigned again is not a name: AuditEventTypes is built from
	// these values at init, so a later write leaves the catalog the operator filters on and the
	// value an emission writes to audit_logs as two different strings, with every comparison
	// below still holding. Every one of the 100 event identifiers is a const, so this forbids
	// nothing the package does.
	if len(src.mutable) > 0 {
		r.Errorf("%d Audit* name(s) declared with var in %s:\n\t%s\n\n"+
			"An audit event name is a const. Declaring one with var puts it outside every "+
			"comparison this guard makes -- it is not one of the declarations checked against "+
			"the catalog, and the scan that reads the rest of the package deliberately skips "+
			"this file -- so it would be emitted and absent from the filter dropdown with "+
			"nothing going red, which is the defect this guard exists to catch. Declare it "+
			"with const, beside the others. AuditEventTypes is the one var here (#209).",
			len(src.mutable), auditCatalogFile, strings.Join(src.mutable, "\n\t"))
	}

	inCatalog := map[string]bool{}
	for _, name := range src.catalogued {
		inCatalog[name] = true
	}

	var missing []string
	for name := range src.declared {
		if !inCatalog[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		r.Errorf("%d audit event(s) declared in %s but absent from AuditEventTypes:\n\t%s\n\n"+
			"The catalog is what GET /api/v1/admin/audit-logs/event-types serves and what the "+
			"admin console's audit log filter dropdown is built from, so an event missing from "+
			"it is written to audit_logs and cannot be filtered for. Add it to the slice, in "+
			"alphabetical order (#209).",
			len(missing), auditCatalogFile, strings.Join(missing, "\n\t"))
	}

	var undeclared []string
	for _, name := range src.catalogued {
		if _, ok := src.declared[name]; !ok {
			undeclared = append(undeclared, name)
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		r.Errorf("%d AuditEventTypes entr(ies) in %s with no Audit* declaration beside them:\n\t%s\n\n"+
			"Every entry must be one of the constants declared above it, so the catalog cannot "+
			"offer the operator a filter value nothing can ever write (#209).",
			len(undeclared), auditCatalogFile, strings.Join(undeclared, "\n\t"))
	}

	// The file against the binary. Order matters here as well as membership: the catalog is
	// served in the order it is written and TestAuditEventTypes_Alphabetical holds that order.
	want := make([]string, 0, len(src.catalogued))
	for _, name := range src.catalogued {
		want = append(want, src.declared[name])
	}
	if len(want) != len(compiled) {
		r.Errorf("%s lists %d audit events but the compiled AuditEventTypes carries %d; "+
			"the guard is not reading the file the binary was built from",
			auditCatalogFile, len(want), len(compiled))
		return
	}
	for i := range want {
		if want[i] != compiled[i] {
			r.Errorf("AuditEventTypes[%d] is %q in the compiled slice and %q in %s; "+
				"the guard is not reading the file the binary was built from",
				i, compiled[i], want[i], auditCatalogFile)
			return
		}
	}
}

// auditCatalogFixture writes a fixture events.go and returns its path.
func auditCatalogFixture(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	return path
}

// TestAuditCatalog_TheGuardFailsOnADeclarationMissingFromTheCatalog is the #209 defect itself:
// the constant added and the catalog entry forgotten. probe/audit-gap.sh demonstrated that this
// passed the whole package before this guard existed.
func TestAuditCatalog_TheGuardFailsOnADeclarationMissingFromTheCatalog(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd  = "auth_failed_pwd"
	AuditForgottenEvent = "forgotten_event"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
	})

	require.True(t, report.Failed(), "a declaration missing from the catalog passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "AuditForgottenEvent")
	assert.Contains(t, report.Text(), "absent from AuditEventTypes")
	assert.Contains(t, report.Text(), "#209")
	// And it does not also report the other direction, which is what a checker comparing two
	// differently-derived lists gets wrong.
	assert.NotContains(t, report.Text(), "no Audit* declaration beside them")
}

// TestAuditCatalog_TheGuardFailsOnACatalogEntryThatIsNotDeclared is the other direction: a name
// the catalog offers the operator that nothing declares, so nothing can ever write it.
func TestAuditCatalog_TheGuardFailsOnACatalogEntryThatIsNotDeclared(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
	AuditVerifiedPhone,
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd", "verified_phone"})
	})

	require.True(t, report.Failed(), "an undeclared catalog entry passed the guard")
	assert.False(t, report.Stopped)
	assert.Contains(t, report.Text(), "AuditVerifiedPhone")
	assert.Contains(t, report.Text(), "no Audit* declaration beside them")
	assert.NotContains(t, report.Text(), "absent from AuditEventTypes")
}

// TestAuditCatalog_TheGuardPassesAMatchingPair is the other half of the first two: without it,
// a checker that failed on everything would satisfy them both.
func TestAuditCatalog_TheGuardPassesAMatchingPair(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
	AuditVerifiedEmail = "verified_email"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
	AuditVerifiedEmail,
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd", "verified_email"})
	})

	assert.False(t, report.Failed(), "a matching pair failed the guard: %s", report.Text())
}

// TestAuditCatalog_TheGuardIsFatalWhenItParsesNoDeclarations pins the empty-parse seam. It is
// the likeliest way this guard goes quiet: the scope is one file, so the declarations moving
// out of it empties the parse without emptying anything else, and two empty sets compare equal.
func TestAuditCatalog_TheGuardIsFatalWhenItParsesNoDeclarations(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

// The names moved elsewhere.

var AuditEventTypes = []string{}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, nil)
	})

	require.True(t, report.Stopped, "an empty parse must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "parsed no Audit* declarations")
}

// TestAuditCatalog_TheGuardIsFatalWhenItParsesNoCatalog is the same seam from the other side: a
// catalog renamed or emptied leaves the declarations intact, so the first fatal does not fire.
func TestAuditCatalog_TheGuardIsFatalWhenItParsesNoCatalog(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditEventNames = []string{
	AuditAuthFailedPwd,
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "parsed no AuditEventTypes entries")
}

// TestAuditCatalog_TheGuardFailsWhenTheFileAndTheBinaryDisagree pins the third check. The two
// comparisons above are file-against-file and would pass for a file the build never sees, which
// is what a moved package or a stale path constant leaves behind.
func TestAuditCatalog_TheGuardFailsWhenTheFileAndTheBinaryDisagree(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
	AuditVerifiedEmail = "verified_email"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
	AuditVerifiedEmail,
}
`)

	t.Run("a different length", func(t *testing.T) {
		report := testutil.RunGuard(func(r testutil.Reporter) {
			assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
		})
		require.True(t, report.Failed())
		assert.Contains(t, report.Text(),
			"lists 2 audit events but the compiled AuditEventTypes carries 1")
	})

	t.Run("a different value at the same position", func(t *testing.T) {
		report := testutil.RunGuard(func(r testutil.Reporter) {
			assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd", "verified_phone"})
		})
		require.True(t, report.Failed())
		assert.Contains(t, report.Text(), `AuditEventTypes[1] is "verified_phone" in the compiled slice`)
	})
}

// TestAuditCatalog_TheParserKeepsDigitsWhole is the case #209 warned about, kept because the
// property still has to hold however the names are read. A pattern over the text with a
// letters-only class truncates this name at the digit, and the guard then reports the same
// event as both missing and undeclared.
func TestAuditCatalog_TheParserKeepsDigitsWhole(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditUpdatedClientOAuth2Flows = "updated_client_oauth2_flows"
)

var AuditEventTypes = []string{
	AuditUpdatedClientOAuth2Flows,
}
`)

	src, err := parseAuditCatalogSource(path)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"AuditUpdatedClientOAuth2Flows": "updated_client_oauth2_flows"},
		src.declared)
	assert.Equal(t, []string{"AuditUpdatedClientOAuth2Flows"}, src.catalogued)

	// And the real file carries that name, so the case is about this tree rather than about a
	// fixture that happens to contain a digit.
	assert.Contains(t, AuditEventTypes, AuditUpdatedClientOAuth2Flows)
}

// TestAuditCatalog_ACatalogEntryThatIsNotAnIdentifierIsReportedAsWritten pins the one shape the
// parse cannot turn into a name. A literal written out instead of the constant duplicates a
// value the catalog already has, so dropping it silently would report the constant it duplicates
// as declared-but-absent and send the reader to the wrong line.
func TestAuditCatalog_ACatalogEntryThatIsNotAnIdentifierIsReportedAsWritten(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditEventTypes = []string{
	"auth_failed_pwd",
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), `"auth_failed_pwd"`)
	assert.Contains(t, report.Text(), "no Audit* declaration beside them")
	assert.Contains(t, report.Text(), "AuditAuthFailedPwd")
	assert.Contains(t, report.Text(), "absent from AuditEventTypes")
}

// auditSiblingFixture writes another production file beside a fixture events.go, which is the
// one shape the parse of events.go alone cannot see.
func auditSiblingFixture(t *testing.T, catalogPath, name, src string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(catalogPath), name), []byte(src), 0o644))
}

// TestAuditCatalog_TheGuardFailsOnADeclarationOutsideTheCatalogFile is the #209 defect in the
// one place this guard could not see it: the constant added to another file of the package, the
// catalog entry forgotten, and every comparison over events.go passing because the declaration
// was never in the set being compared.
func TestAuditCatalog_TheGuardFailsOnADeclarationOutsideTheCatalogFile(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
}
`)
	auditSiblingFixture(t, path, "audit.go", `package audit

const AuditForgottenOutsideEvents = "forgotten_outside_events"
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
	})

	require.True(t, report.Failed(), "a declaration outside the catalog file passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "audit.go: AuditForgottenOutsideEvents")
	assert.Contains(t, report.Text(), "outside")
	// The two same-file comparisons have nothing to say about it, so it must not be reported as
	// a name the catalog is missing as well: the fix is to move it, not to list it twice.
	assert.NotContains(t, report.Text(), "absent from AuditEventTypes")
}

// TestAuditCatalog_TheSiblingScanPassesAPackageWhoseOtherFilesDeclareNoEvents is the other half:
// without it a scan that flagged everything would satisfy the case above. audit.go really does
// declare AuditLogger, so a rule reading "any Audit* name" rather than "any Audit* name bound to
// a string" would fail the real package on the type that gives the package its purpose.
func TestAuditCatalog_TheSiblingScanPassesAPackageWhoseOtherFilesDeclareNoEvents(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
}
`)
	auditSiblingFixture(t, path, "audit.go", `package audit

type AuditLogger struct{}

const auditQueueDepth = 100

func AuditNothing() string { return "not a declaration" }
`)
	auditSiblingFixture(t, path, "audit_helpers_test.go", `package audit

const AuditOnlyInATestFile = "only_in_a_test_file"
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
	})

	assert.False(t, report.Failed(), "a package with no event declared outside the catalog file failed the guard: %s", report.Text())
}

// TestAuditCatalog_TheSiblingScanReadsTheRestOfThePackage is the walk that reached nothing. The
// scan reports an absence, and an absence is what a walk that read no files reports too, so
// without this the directory moving under it would leave it passing forever.
func TestAuditCatalog_TheSiblingScanReadsTheRestOfThePackage(t *testing.T) {
	dir := filepath.Dir(filepath.Join(testutil.SourceRoot(t), filepath.FromSlash(auditCatalogFile)))

	scanned, outside, err := auditDeclarationsOutsideTheCatalogFile(dir, "events.go")

	require.NoError(t, err)
	assert.Contains(t, scanned, "audit.go", "the scan read no production file beside events.go")
	assert.NotContains(t, scanned, "events.go", "the catalog file is parsed by the comparison above, not by this scan")
	assert.NotContains(t, scanned, "events_test.go", "a test file is not a declaration the binary carries")
	assert.Empty(t, outside, "the audit event names all belong in events.go")
}

// TestAuditCatalog_TheSiblingScanReadsEveryProductionFileAndNotJustTheFirst is the partial-walk
// case. The one above proves the scan reached a file; it cannot tell that apart from a scan that
// stops after the first directory entry, because every other fixture here has exactly one
// eligible sibling and os.ReadDir returns it first. So the declaration goes in the LATER file,
// and the set of names read is asserted whole rather than by membership: an early stop and a
// per-file omission both change that set.
func TestAuditCatalog_TheSiblingScanReadsEveryProductionFileAndNotJustTheFirst(t *testing.T) {
	path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
}
`)
	auditSiblingFixture(t, path, "audit.go", `package audit

type AuditLogger struct{}
`)
	auditSiblingFixture(t, path, "zz_more_events.go", `package audit

const AuditForgottenInALaterFile = "forgotten_in_a_later_file"
`)
	auditSiblingFixture(t, path, "zz_more_events_test.go", `package audit

const AuditForgottenInALaterTestFile = "forgotten_in_a_later_test_file"
`)

	scanned, outside, err := auditDeclarationsOutsideTheCatalogFile(filepath.Dir(path), "events.go")

	require.NoError(t, err)
	// Whole, in os.ReadDir's order: the catalog file and the test file are the two exclusions,
	// and everything else the package carries is read.
	assert.Equal(t, []string{"audit.go", "zz_more_events.go"}, scanned)
	assert.Equal(t, []string{"zz_more_events.go: AuditForgottenInALaterFile"}, outside)

	// And the reporting half says so, so this is a property of the guard rather than of a
	// helper nothing drives.
	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
	})
	require.True(t, report.Failed(), "a declaration in the second production file passed the guard")
	assert.Contains(t, report.Text(), "zz_more_events.go: AuditForgottenInALaterFile")
}

// TestAuditCatalog_TheGuardFailsOnAnEventNameDeclaredWithVar takes the declaration kind on both
// sides of the catalog-file boundary, because the guard reaches the two sides through different
// code and each was pinned by const alone.
//
// Outside: the sibling scan accepts const and var by design, and every fixture gave it a const,
// so dropping token.VAR from its condition left the package green. Inside: parseAuditCatalogSource
// read no var but AuditEventTypes, so a var written into events.go was in neither list -- and
// since the sibling scan skips events.go, doing what the outside failure tells you to do was
// what made the declaration invisible.
func TestAuditCatalog_TheGuardFailsOnAnEventNameDeclaredWithVar(t *testing.T) {
	t.Run("outside the catalog file", func(t *testing.T) {
		path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
}
`)
		auditSiblingFixture(t, path, "audit.go", `package audit

var AuditForgottenOutsideAsAVar = "forgotten_outside_as_a_var"
`)

		report := testutil.RunGuard(func(r testutil.Reporter) {
			assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
		})

		require.True(t, report.Failed(), "a var event name outside the catalog file passed the guard")
		assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
		assert.Contains(t, report.Text(), "audit.go: AuditForgottenOutsideAsAVar")
		// The advice has to land it somewhere the guard can see, which is the const block.
		assert.Contains(t, report.Text(), "declared with const")
	})

	t.Run("inside the catalog file", func(t *testing.T) {
		path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditForgottenInsideEvents = "forgotten_inside_events"

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
}
`)

		report := testutil.RunGuard(func(r testutil.Reporter) {
			assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
		})

		require.True(t, report.Failed(), "a var event name inside the catalog file passed the guard")
		assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
		assert.Contains(t, report.Text(), "AuditForgottenInsideEvents")
		assert.Contains(t, report.Text(), "declared with var")
		// Reported as the one thing it is. It is not in src.declared, so reporting it as a
		// declaration missing from the catalog as well would send the reader to add a var to
		// the slice, which is the wrong edit.
		assert.NotContains(t, report.Text(), "absent from AuditEventTypes")
		assert.NotContains(t, report.Text(), "but outside")
	})

	// The pass half. Without it a check refusing every Audit* var would satisfy both cases
	// above, and it would be wrong in the same way the sibling scan would be wrong to refuse
	// the AuditLogger type: what makes a name an event here is the prefix AND a string value,
	// so a var of some other type keeps the prefix legitimately.
	t.Run("an Audit name that is not bound to a string is left alone", func(t *testing.T) {
		path := auditCatalogFixture(t, `package audit

const (
	AuditAuthFailedPwd = "auth_failed_pwd"
)

var AuditLoggerDefault *AuditLogger

var AuditRetryBudget = 3

var auditQueueName = "audit_queue"

var AuditEventTypes = []string{
	AuditAuthFailedPwd,
}
`)

		report := testutil.RunGuard(func(r testutil.Reporter) {
			assertAuditCatalogComplete(r, path, []string{"auth_failed_pwd"})
		})

		assert.False(t, report.Failed(), "a non-event Audit* var failed the guard: %s", report.Text())
	})

	// And the var the package really does have is not caught by any of it: AuditEventTypes is
	// the catalog, so a rule reading "no Audit* var" would fail the real file outright.
	t.Run("AuditEventTypes itself is untouched", func(t *testing.T) {
		src, err := parseAuditCatalogSource(
			filepath.Join(testutil.SourceRoot(t), filepath.FromSlash(auditCatalogFile)))
		require.NoError(t, err)
		assert.Empty(t, src.mutable, "the real catalog file declares no event name with var")
		assert.NotEmpty(t, src.catalogued, "AuditEventTypes was read as the catalog")
	})
}
