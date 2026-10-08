package apihandlers

// The audit log page's key catalog, held to every audit payload the auth server writes (#522
// decision 9).
//
// The details keys were inconsistent because nobody saw them in one place: clientId held a row id
// at some sites and a wire identifier at others, and the client IP had three spellings. The Audit
// log page now lists every key with its meaning, as it lists every event, and this holds that table
// to the code in both directions: a key some audit Log call writes and the table lacks fails, so
// does a row naming a key nothing writes, and so does a key that is not snake_case. A new key, or a
// second name for a concept that already has one, then shows up in review as a row.
//
// The keys are read from the source with go/types rather than matched in the text, because most
// payloads are not a literal at the call: a local extended on some branches, a helper's return, a
// map handed down three rate-limiter functions and extended at the bottom. A details argument the
// walk cannot follow to its keys is reported rather than skipped, since a guard that skips what it
// cannot read narrows itself without anything going red.
//
// It reads files and nothing else.

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// auditKeysSection is the section of the audit log page whose table is the key catalog.
var auditKeysSection = docSection{auditLogPage, "### Details"}

// auditKeysCodeDir is the module whose audit Log calls the catalog is held to, relative to the
// repository root.
const auditKeysCodeDir = "src/authserver"

func TestAuditLogDocs_TheKeyCatalogIsWhatTheAuthServerWrites(t *testing.T) {
	assertAuditDetailsKeys(t, filepath.Dir(guard.SourceRoot(t)), auditKeysCodeDir, auditKeysSection)
}

// docAuditLogCallLine is a line opening an audit Log call: a call of a method named Log whose
// event is one of the audit package's constants. Every call in the tree is written this way, so a
// text count of these lines is a count of the calls reached by a means that shares nothing with
// the walk's type-checking.
var docAuditLogCallLine = regexp.MustCompile(`\.Log\([^,]+,\s*audit\.Event`)

// TestAuditLogDocs_TheKeyWalkReachesEveryAuditLogCall is the partial walk. A Log call the walk
// does not recognize contributes no key and no finding, so a walk that stopped recognizing some
// would pass with every key it did reach listed.
func TestAuditLogDocs_TheKeyWalkReachesEveryAuditLogCall(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	walk, err := walkAuditDetails(root, auditKeysCodeDir)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var want []string
	err = filepath.WalkDir(filepath.Join(root, auditKeysCodeDir), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if auditKeysSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(content), "\n") {
			if docAuditLogCallLine.MatchString(line) {
				want = append(want, filepath.ToSlash(rel)+":"+strconv.Itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(want) < 100 {
		t.Fatalf("the text count found %d audit Log calls, too few to be the tree's", len(want))
	}
	if !slices.Equal(walk.sites, want) {
		t.Errorf("the walk reached the audit Log calls\n%q\nthe text has them at\n%q", walk.sites, want)
	}
}

// auditKeysFixtureCode is a package writing audit details in every shape the walk follows: a
// literal at the call, a local extended after it is built, a map a helper returns, a map handed
// down a chain of parameters and extended at the bottom, a map returned by the function a
// parameter names, a map a helper extends after it is built, and a map held under a key. Each shape contributes keys of
// its own, so a shape the walk stops following leaves its keys listed and written by nothing.
// render's map never reaches the audit log, and its key is no audit key.
const auditKeysFixtureCode = `package fixture

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
)

type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

type limiter struct{ auditLogger AuditLogger }

type subjectFunc func(r *http.Request) (string, map[string]interface{}, bool)

func literal(ctx context.Context, auditLogger AuditLogger) {
	auditLogger.Log(ctx, audit.EventCreatedUser, map[string]interface{}{
		"user_id": 1,
	})
}

func extended(ctx context.Context, auditLogger AuditLogger, userId int64) {
	details := map[string]interface{}{"ip": "203.0.113.1"}
	if userId != 0 {
		details["email_digest"] = "digest"
	}
	auditLogger.Log(ctx, audit.EventAuthFailedPwd, details)
}

func helperDetails(clientId int64) map[string]interface{} {
	return map[string]interface{}{"client_id": clientId}
}

func fromHelper(ctx context.Context, auditLogger AuditLogger) {
	auditLogger.Log(ctx, audit.EventViewedClientSecret, helperDetails(1))
}

func (l *limiter) report(ctx context.Context, details map[string]interface{}) {
	if details == nil {
		details = map[string]interface{}{}
	}
	details["limiter"] = "pwd"
	l.auditLogger.Log(ctx, audit.EventRateLimitExceeded, details)
}

func (l *limiter) refuse(ctx context.Context, details map[string]interface{}) {
	l.report(ctx, details)
}

func (l *limiter) byTarget(ctx context.Context) {
	l.refuse(ctx, map[string]interface{}{"target_id": 1})
}

func tokenSubject(r *http.Request) (string, map[string]interface{}, bool) {
	return "subject", map[string]interface{}{"logged_in_user": "subject"}, true
}

func (l *limiter) bySubject(r *http.Request, subject subjectFunc) {
	_, audited, ok := subject(r)
	if !ok {
		return
	}
	l.refuse(r.Context(), audited)
}

func (l *limiter) route(r *http.Request) {
	l.bySubject(r, tokenSubject)
}

func addMethod(details map[string]interface{}) {
	details["method"] = "GET"
}

func forwarded(ctx context.Context, auditLogger AuditLogger) {
	details := map[string]interface{}{"route": "/users"}
	addMethod(details)
	auditLogger.Log(ctx, audit.EventAdministratorChangeRefused, details)
}

func nested(ctx context.Context, auditLogger AuditLogger) {
	previous := map[string]interface{}{"token_lifetime": 300}
	details := map[string]interface{}{"old": previous}
	details["new"] = map[string]interface{}{"token_lifetime": 600}
	auditLogger.Log(ctx, audit.EventUpdatedTokensSettings, details)
}

func render() map[string]interface{} {
	return map[string]interface{}{"pageTitle": "Users"}
}
`

// auditKeysFixtureKeys is every key auditKeysFixtureCode writes, in a catalog row each.
var auditKeysFixtureKeys = []string{
	"client_id", "email_digest", "ip", "limiter", "logged_in_user", "method", "new", "old", "route", "target_id",
	"token_lifetime", "user_id",
}

// auditKeysFixtureUnfollowable is a file of the same package whose payloads the walk must refuse
// or report: a key that is not snake_case, at the top or inside a map held under a key, and a key
// the catalog lacks, beside three details arguments it cannot follow.
const auditKeysFixtureUnfollowable = `package fixture

import (
	"context"

	"github.com/leodip/goiabada/authserver/internal/audit"
)

type holder struct{ details map[string]interface{} }

func camel(ctx context.Context, auditLogger AuditLogger) {
	auditLogger.Log(ctx, audit.EventCreatedClient, map[string]interface{}{
		"clientId":           1,
		"client_secret_hint": "hint",
		"new":                map[string]interface{}{"tokenLifetime": 600},
	})
}

func field(ctx context.Context, auditLogger AuditLogger, h holder) {
	auditLogger.Log(ctx, audit.EventDeletedClient, h.details)
}

func dynamicKey(ctx context.Context, auditLogger AuditLogger, name string) {
	details := map[string]interface{}{}
	details[name] = 1
	auditLogger.Log(ctx, audit.EventDeletedUser, details)
}

func LogFor(ctx context.Context, auditLogger AuditLogger, details map[string]interface{}) {
	auditLogger.Log(ctx, audit.EventDeletedGroup, details)
}
`

// auditKeysCatalog is a Details section whose table has one row per key, each with a meaning.
func auditKeysCatalog(keys []string) string {
	page := "### Details\n\nKeys are snake_case.\n\n| Key | Meaning |\n|---|---|\n"
	for _, key := range keys {
		page += "| `" + key + "` | What " + key + " holds. |\n"
	}
	return page + "\n### Next\n\n| `outside_the_section` | Not read. |\n"
}

// writeAuditKeysFixture writes a fixture repository: the page at site/audit.mdx and each Go file
// under src/authserver/internal/fixture.
func writeAuditKeysFixture(t *testing.T, page string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeDocFixture(t, root, "site/audit.mdx", page)
	for name, code := range files {
		writeDocFixture(t, root, "src/authserver/internal/fixture/"+name, code)
	}
	return root
}

// fixtureLine is the line of code holding text, so an expected finding names the line the
// fixture puts it on rather than a number kept in step by hand.
func fixtureLine(t *testing.T, code, text string) string {
	t.Helper()
	for i, line := range strings.Split(code, "\n") {
		if strings.Contains(line, text) {
			return strconv.Itoa(i + 1)
		}
	}
	t.Fatalf("the fixture holds no line with %q", text)
	return ""
}

var auditKeysFixtureSection = docSection{"site/audit.mdx", "### Details"}

func TestAuditLogDocs_AKeyCatalogMatchingThePayloadsPasses(t *testing.T) {
	root := writeAuditKeysFixture(t, auditKeysCatalog(auditKeysFixtureKeys),
		map[string]string{"fixture.go": auditKeysFixtureCode})

	report := guard.Run(func(r guard.Reporter) {
		assertAuditDetailsKeys(r, root, "src/authserver", auditKeysFixtureSection)
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a catalog matching the payloads failed: %+v", report)
	}
}

// TestAuditLogDocs_AKeyCatalogDisagreeingWithThePayloadsFails reports every finding the guard
// makes, each naming the page and section, or the file and line.
func TestAuditLogDocs_AKeyCatalogDisagreeingWithThePayloadsFails(t *testing.T) {
	page := "### Details\n\n" +
		"| Key | Meaning |\n|---|---|\n" +
		"| `client_id` | The client's row id. |\n" +
		"| `retired_key` | Written by nothing. |\n" +
		"| `client_id` | Listed twice. |\n" +
		"| `email_digest` | |\n" +
		"| ip | Not backticked. |\n" +
		"| `limiter` | The limiter. | extra |\n"
	for _, key := range []string{"logged_in_user", "method", "new", "old", "route", "target_id", "token_lifetime"} {
		page += "| `" + key + "` | What " + key + " holds. |\n"
	}
	root := writeAuditKeysFixture(t, page, map[string]string{
		"fixture.go":      auditKeysFixtureCode,
		"unfollowable.go": auditKeysFixtureUnfollowable,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertAuditDetailsKeys(r, root, "src/authserver", auditKeysFixtureSection)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	code := "src/authserver/internal/fixture/"
	unfollowable := auditKeysFixtureUnfollowable
	fixture := auditKeysFixtureCode
	where := "site/audit.mdx: ### Details"
	want := []string{
		where + " lists retired_key, which no audit Log call writes",
		where + " lists client_id twice",
		where + " gives email_digest no meaning",
		where + ` has a row whose key is not one backticked snake_case key: "ip"`,
		where + ` has a row of 3 cells, want key and meaning: ["` + "`limiter`" + `" "The limiter." "extra"]`,
		code + "unfollowable.go:" + fixtureLine(t, unfollowable, "h.details") +
			": the keys of this audit Log call cannot be read: h.details is not a local variable, a parameter, a map literal or a call",
		code + "unfollowable.go:" + fixtureLine(t, unfollowable, "details[name] = 1") +
			": the keys of the audit Log call at " + code + "unfollowable.go:" +
			fixtureLine(t, unfollowable, "audit.EventDeletedUser") + " cannot be read: the key name is not a constant string",
		code + "unfollowable.go:" + fixtureLine(t, unfollowable, "audit.EventDeletedGroup") +
			": the keys of this audit Log call cannot be read: details is a parameter of LogFor, which is exported, so not every caller is in sight",
		code + "unfollowable.go:" + fixtureLine(t, unfollowable, `"clientId"`) +
			" writes the audit details key clientId, which is not snake_case",
		code + "unfollowable.go:" + fixtureLine(t, unfollowable, `"tokenLifetime"`) +
			" writes the audit details key tokenLifetime, which is not snake_case",
		where + " does not list client_secret_hint, which " + code + "unfollowable.go:" +
			fixtureLine(t, unfollowable, `"client_secret_hint"`) + " writes",
		where + " does not list ip, which " + code + "fixture.go:" + fixtureLine(t, fixture, `"ip"`) + " writes",
		where + " does not list limiter, which " + code + "fixture.go:" + fixtureLine(t, fixture, `"limiter"`) + " writes",
		where + " does not list user_id, which " + code + "fixture.go:" + fixtureLine(t, fixture, `"user_id"`) + " writes",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestAuditLogDocs_AKeyCatalogWithNoSectionStops(t *testing.T) {
	root := writeAuditKeysFixture(t, "### Payloads\n\n| Key | Meaning |\n|---|---|\n| `user_id` | The user. |\n",
		map[string]string{"fixture.go": auditKeysFixtureCode})

	report := guard.Run(func(r guard.Reporter) {
		assertAuditDetailsKeys(r, root, "src/authserver", auditKeysFixtureSection)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### Details") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestAuditLogDocs_AKeyCatalogWithNoTableStops(t *testing.T) {
	root := writeAuditKeysFixture(t, "### Details\n\n- `user_id`: the user.\n",
		map[string]string{"fixture.go": auditKeysFixtureCode})

	report := guard.Run(func(r guard.Reporter) {
		assertAuditDetailsKeys(r, root, "src/authserver", auditKeysFixtureSection)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no table") {
		t.Errorf("a section without its table did not stop the check: %+v", report)
	}
}

// TestAuditLogDocs_AKeyWalkReachingNoAuditLogCallStops is the walk that reached nothing: code
// with no audit Log call writes no key, and a catalog listing none would then pass.
func TestAuditLogDocs_AKeyWalkReachingNoAuditLogCallStops(t *testing.T) {
	root := writeAuditKeysFixture(t, auditKeysCatalog([]string{"user_id"}), map[string]string{"fixture.go": `package fixture

func render() map[string]interface{} {
	return map[string]interface{}{"pageTitle": "Users"}
}
`})

	report := guard.Run(func(r guard.Reporter) {
		assertAuditDetailsKeys(r, root, "src/authserver", auditKeysFixtureSection)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no audit Log call") {
		t.Errorf("a walk reaching no audit Log call did not stop the check: %+v", report)
	}
}

// auditImportPath is the audit package. A Log call whose event is one of its constants is an audit
// Log call whatever the receiver's type resolves to.
const auditImportPath = "github.com/leodip/goiabada/authserver/internal/audit"

// auditKeySpelling is snake_case, the spelling the logging convention gives an attribute and this
// catalog gives a key.
var auditKeySpelling = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

// assertAuditDetailsKeys is the reporting half of the key catalog's check: one failure per finding
// of auditDetailsKeyFindings; a stop for a section not found, holding no table, or a walk that
// reached no audit Log call, since a check that read nothing proves nothing.
func assertAuditDetailsKeys(r guard.Reporter, root, codeDir string, section docSection) {
	r.Helper()
	findings, err := auditDetailsKeyFindings(root, codeDir, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// auditDetailsKeyFindings reads the table in section, one row per details key with its meaning,
// and walks every audit Log call under codeDir. It returns one finding per row that is not a key
// some call writes, lists a key a second time or gives it no meaning, then one per details
// argument the walk cannot read, then one per key written that is not snake_case, and one per
// snake_case key written with no row. It returns an error, and no findings, for a section not
// found or holding no table, and for a walk that reached no audit Log call.
func auditDetailsKeyFindings(root, codeDir string, section docSection) ([]string, error) {
	text, err := docSectionText(root, section)
	if err != nil {
		return nil, err
	}
	rows := docTableRows(text)
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %s holds no table of the audit details keys", section.page, section.heading)
	}
	walk, err := walkAuditDetails(root, codeDir)
	if err != nil {
		return nil, err
	}
	if len(walk.sites) == 0 {
		return nil, fmt.Errorf("the walk found no audit Log call under %s", codeDir)
	}

	where := section.page + ": " + section.heading
	var findings []string
	listed := make(map[string]bool)
	for _, cells := range rows {
		if len(cells) != 2 {
			findings = append(findings, fmt.Sprintf("%s has a row of %d cells, want key and meaning: %q",
				where, len(cells), cells))
			continue
		}
		match := docAuditEventCell.FindStringSubmatch(cells[0])
		if match == nil {
			findings = append(findings, fmt.Sprintf("%s has a row whose key is not one backticked snake_case key: %q",
				where, cells[0]))
			continue
		}
		key := match[1]
		switch {
		case walk.keys[key] == nil:
			findings = append(findings, where+" lists "+key+", which no audit Log call writes")
		case listed[key]:
			findings = append(findings, where+" lists "+key+" twice")
		case cells[1] == "":
			findings = append(findings, where+" gives "+key+" no meaning")
		}
		listed[key] = true
	}

	findings = append(findings, walk.unfollowed...)

	keys := make([]string, 0, len(walk.keys))
	for key := range walk.keys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !auditKeySpelling.MatchString(key) {
			findings = append(findings, walk.keys[key][0]+" writes the audit details key "+key+", which is not snake_case")
		}
	}
	for _, key := range keys {
		if auditKeySpelling.MatchString(key) && !listed[key] {
			findings = append(findings, where+" does not list "+key+", which "+walk.keys[key][0]+" writes")
		}
	}
	return findings, nil
}

// auditDetailsWalk is what walking the audit Log calls found: each key their details carry, with
// the places it is written, "file:line" relative to the root; one finding per place the walk could
// not read a key; and the place of every audit Log call it reached.
type auditDetailsWalk struct {
	keys       map[string][]string
	unfollowed []string
	sites      []string
}

// auditKeysSkippedDir is a directory no production package of the module lives in.
func auditKeysSkippedDir(name string) bool {
	return name == "testdata" || name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".")
}

// walkAuditDetails type-checks every package under codeDir whose production files call a method
// named Log, and reads the keys of each audit Log call's details from the package's own source.
//
// A details argument is followed to every map it can be: a map literal, a local variable through
// each assignment to it, a parameter through the argument every caller passes, a call through the
// return statements of the function it calls, and a call through a function-typed parameter
// through each function its callers pass. Along the way every key assigned into one of those
// variables counts, and so does every key a function of the package assigns into a parameter the
// map is passed as. Anything else is reported rather than skipped: a key that is not a constant
// string, a map read from a field, a parameter of an exported function or of one used as a value,
// whose callers are not all in sight. Imports are stubbed: everything the walk follows is in the
// package that calls Log.
func walkAuditDetails(root, codeDir string) (auditDetailsWalk, error) {
	walk := auditDetailsWalk{keys: map[string][]string{}}
	byDir := map[string][]string{}
	var dirs []string
	err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(codeDir)), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if auditKeysSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir := filepath.Dir(path)
		if _, seen := byDir[dir]; !seen {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], path)
		return nil
	})
	if err != nil {
		return walk, fmt.Errorf("walking %s: %w", codeDir, err)
	}

	written := map[string]map[string]bool{}
	unfollowed := map[string]bool{}
	var sites []auditPlace
	imports := auditStubImporter{}
	for _, dir := range dirs {
		if err := walkAuditDetailsIn(root, byDir[dir], imports, written, unfollowed, &sites); err != nil {
			return walk, err
		}
	}

	for key, places := range written {
		walk.keys[key] = sortedAuditPlaces(places)
	}
	walk.unfollowed = sortedAuditPlaces(unfollowed)
	sort.Slice(sites, func(i, j int) bool { return sites[i].less(sites[j]) })
	for _, site := range sites {
		walk.sites = append(walk.sites, site.String())
	}
	return walk, nil
}

// auditPlace is a line of a file, relative to the root with forward slashes.
type auditPlace struct {
	file string
	line int
}

func (p auditPlace) String() string { return p.file + ":" + strconv.Itoa(p.line) }

func (p auditPlace) less(q auditPlace) bool {
	if p.file != q.file {
		return p.file < q.file
	}
	return p.line < q.line
}

// sortedAuditPlaces is the set's members in file and line order. A member is a place, or a place
// followed by ": " and what is there.
func sortedAuditPlaces(set map[string]bool) []string {
	members := make([]string, 0, len(set))
	for member := range set {
		members = append(members, member)
	}
	parse := func(member string) auditPlace {
		place, _, _ := strings.Cut(member, ": ")
		file, line, _ := strings.Cut(place, ":")
		n, _ := strconv.Atoi(line)
		return auditPlace{file, n}
	}
	sort.Slice(members, func(i, j int) bool {
		p, q := parse(members[i]), parse(members[j])
		if p != q {
			return p.less(q)
		}
		return members[i] < members[j]
	})
	return members
}

// walkAuditDetailsIn checks the production files of one directory, a package per package clause,
// and walks each audit Log call in them. A directory none of whose files spells a Log call is not
// checked at all.
func walkAuditDetailsIn(root string, paths []string, imports auditStubImporter,
	written map[string]map[string]bool, unfollowed map[string]bool, sites *[]auditPlace) error {

	fset := token.NewFileSet()
	byPackage := map[string][]*ast.File{}
	var packages []string
	spellsLog := false
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		spellsLog = spellsLog || strings.Contains(string(content), ".Log(")
		file, err := parser.ParseFile(fset, path, content, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		if _, seen := byPackage[file.Name.Name]; !seen {
			packages = append(packages, file.Name.Name)
		}
		byPackage[file.Name.Name] = append(byPackage[file.Name.Name], file)
	}
	if !spellsLog {
		return nil
	}

	for _, name := range packages {
		info := &types.Info{
			Types: map[ast.Expr]types.TypeAndValue{},
			Defs:  map[*ast.Ident]types.Object{},
			Uses:  map[*ast.Ident]types.Object{},
		}
		conf := types.Config{
			Importer: imports,
			// Every import is a stub, so most of what go/types says about these files is that a
			// package it never read has no such member. What the walk asks is answered inside the
			// package: which variable an identifier is, which function a call calls, which
			// constant a key is.
			Error:                    func(error) {},
			DisableUnusedImportCheck: true,
		}
		files := byPackage[name]
		pkg, _ := conf.Check(filepath.Dir(paths[0]), fset, files, info)
		index := newAuditDetailsIndex(root, fset, info, pkg, files)
		for _, call := range index.logCalls {
			trace := &auditDetailsTrace{
				index: index, call: index.place(call.Pos()), written: written, unfollowed: unfollowed,
				seen: map[any]bool{},
			}
			*sites = append(*sites, trace.call)
			trace.details(call.Args[2])
		}
	}
	return nil
}

// auditStubImporter answers every import with an empty package, named as the last element of its
// path that is not a major version.
type auditStubImporter map[string]*types.Package

func (s auditStubImporter) Import(path string) (*types.Package, error) {
	if pkg, ok := s[path]; ok {
		return pkg, nil
	}
	elements := strings.Split(path, "/")
	name := elements[len(elements)-1]
	if len(elements) > 1 && len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
		name = elements[len(elements)-2]
	}
	pkg := types.NewPackage(path, name)
	pkg.MarkComplete()
	s[path] = pkg
	return pkg, nil
}

// auditParam is where a parameter is declared: the index-th parameter of fn, or of lit when it is
// a function literal's.
type auditParam struct {
	fn    *types.Func
	lit   *ast.FuncLit
	index int
}

// auditWrite is one value assigned to a variable: rhs, or the result-th result of call when one
// call assigns several variables, or why the value cannot be followed when it is neither.
type auditWrite struct {
	rhs    ast.Expr
	call   *ast.CallExpr
	result int
	at     token.Pos
	why    string
}

// auditKeyWrite is a key assigned into a map variable, and the value assigned when the walk can
// tell which it is.
type auditKeyWrite struct {
	key   ast.Expr
	value ast.Expr
}

// auditForward is a variable passed as the index-th argument of a call to fn.
type auditForward struct {
	fn    *types.Func
	index int
}

// auditDetailsIndex is what one checked package says about the variables and functions a details
// argument can flow through.
type auditDetailsIndex struct {
	root      string
	fset      *token.FileSet
	info      *types.Info
	pkg       *types.Package
	funcDecls map[*types.Func]*ast.FuncDecl
	params    map[*types.Var]auditParam
	writes    map[*types.Var][]auditWrite
	keyWrites map[*types.Var][]auditKeyWrite
	calls     map[*types.Func][]*ast.CallExpr
	asValue   map[*types.Func]bool
	forwards  map[*types.Var][]auditForward
	logCalls  []*ast.CallExpr
}

func newAuditDetailsIndex(root string, fset *token.FileSet, info *types.Info, pkg *types.Package,
	files []*ast.File) *auditDetailsIndex {

	index := &auditDetailsIndex{
		root: root, fset: fset, info: info, pkg: pkg,
		funcDecls: map[*types.Func]*ast.FuncDecl{},
		params:    map[*types.Var]auditParam{},
		writes:    map[*types.Var][]auditWrite{},
		keyWrites: map[*types.Var][]auditKeyWrite{},
		calls:     map[*types.Func][]*ast.CallExpr{},
		asValue:   map[*types.Func]bool{},
		forwards:  map[*types.Var][]auditForward{},
	}
	called := map[*ast.Ident]bool{}

	declareParams := func(fields *ast.FieldList, param func(index int) auditParam) {
		i := 0
		for _, field := range fields.List {
			if len(field.Names) == 0 {
				i++
				continue
			}
			for _, name := range field.Names {
				if v, ok := info.Defs[name].(*types.Var); ok {
					index.params[v] = param(i)
				}
				i++
			}
		}
	}

	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if fn, ok := info.Defs[n.Name].(*types.Func); ok {
					index.funcDecls[fn] = n
					declareParams(n.Type.Params, func(i int) auditParam { return auditParam{fn: fn, index: i} })
				}
			case *ast.FuncLit:
				declareParams(n.Type.Params, func(i int) auditParam { return auditParam{lit: n, index: i} })
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					switch lhs := ast.Unparen(lhs).(type) {
					case *ast.Ident:
						v := index.variable(lhs)
						if v == nil {
							continue
						}
						index.writes[v] = append(index.writes[v], index.write(n.Lhs, n.Rhs, i, n.Pos()))
					case *ast.IndexExpr:
						if x, ok := ast.Unparen(lhs.X).(*ast.Ident); ok {
							if v := index.variable(x); v != nil {
								write := auditKeyWrite{key: lhs.Index}
								if len(n.Lhs) == len(n.Rhs) {
									write.value = n.Rhs[i]
								}
								index.keyWrites[v] = append(index.keyWrites[v], write)
							}
						}
					}
				}
			case *ast.ValueSpec:
				for i, name := range n.Names {
					v, ok := info.Defs[name].(*types.Var)
					if !ok || len(n.Values) == 0 {
						continue
					}
					index.writes[v] = append(index.writes[v], index.write(identExprs(n.Names), n.Values, i, name.Pos()))
				}
			case *ast.RangeStmt:
				for _, e := range []ast.Expr{n.Key, n.Value} {
					if id, ok := e.(*ast.Ident); ok {
						if v := index.variable(id); v != nil {
							index.writes[v] = append(index.writes[v], auditWrite{at: id.Pos(), why: id.Name + " is a range variable"})
						}
					}
				}
			case *ast.CallExpr:
				fn, id := index.callee(n)
				if id != nil {
					called[id] = true
				}
				if fn != nil {
					index.calls[fn] = append(index.calls[fn], n)
					for i, arg := range n.Args {
						if argId, ok := ast.Unparen(arg).(*ast.Ident); ok {
							if v, ok := info.Uses[argId].(*types.Var); ok {
								index.forwards[v] = append(index.forwards[v], auditForward{fn: fn, index: i})
							}
						}
					}
				}
				if index.isAuditLogCall(n) {
					index.logCalls = append(index.logCalls, n)
				}
			}
			return true
		})
	}
	for id, obj := range info.Uses {
		if fn, ok := obj.(*types.Func); ok && fn.Pkg() == pkg && !called[id] {
			index.asValue[fn] = true
		}
	}
	return index
}

// identExprs is names as expressions.
func identExprs(names []*ast.Ident) []ast.Expr {
	exprs := make([]ast.Expr, len(names))
	for i, name := range names {
		exprs[i] = name
	}
	return exprs
}

// write is the value the i-th of lhs is assigned from rhs.
func (x *auditDetailsIndex) write(lhs, rhs []ast.Expr, i int, at token.Pos) auditWrite {
	if len(lhs) == len(rhs) {
		return auditWrite{rhs: rhs[i], at: at}
	}
	if len(rhs) == 1 {
		if call, ok := ast.Unparen(rhs[0]).(*ast.CallExpr); ok {
			return auditWrite{call: call, result: i, at: at}
		}
	}
	return auditWrite{at: at, why: types.ExprString(lhs[i]) + " is assigned from " + types.ExprString(rhs[0]) +
		", which this walk cannot follow"}
}

// variable is the local or package variable id names, or nil.
func (x *auditDetailsIndex) variable(id *ast.Ident) *types.Var {
	obj := x.info.Defs[id]
	if obj == nil {
		obj = x.info.Uses[id]
	}
	v, _ := obj.(*types.Var)
	if v == nil || v.IsField() {
		return nil
	}
	return v
}

// callee is the function of this package call calls by name, and the identifier naming it.
func (x *auditDetailsIndex) callee(call *ast.CallExpr) (*types.Func, *ast.Ident) {
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	default:
		return nil, nil
	}
	fn, ok := x.info.Uses[id].(*types.Func)
	if !ok || fn.Pkg() != x.pkg {
		return nil, id
	}
	return fn, id
}

// isAuditLogCall reports whether call is a call of a method named Log taking a context, an event
// and the details: its event is one of the audit package's constants, or the method resolves to
// that shape.
func (x *auditDetailsIndex) isAuditLogCall(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Log" || len(call.Args) != 3 {
		return false
	}
	if event, isSelector := ast.Unparen(call.Args[1]).(*ast.SelectorExpr); isSelector {
		if pkgId, isIdent := event.X.(*ast.Ident); isIdent {
			if pkgName, isPkg := x.info.Uses[pkgId].(*types.PkgName); isPkg && pkgName.Imported().Path() == auditImportPath {
				return true
			}
		}
	}
	fn, ok := x.info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	params := fn.Type().(*types.Signature).Params()
	if params.Len() != 3 || !types.Identical(params.At(1).Type(), types.Typ[types.String]) {
		return false
	}
	details, ok := params.At(2).Type().Underlying().(*types.Map)
	if !ok || !types.Identical(details.Key(), types.Typ[types.String]) {
		return false
	}
	elem, ok := details.Elem().Underlying().(*types.Interface)
	return ok && elem.Empty()
}

// place is pos as a line of a file relative to the root.
func (x *auditDetailsIndex) place(pos token.Pos) auditPlace {
	position := x.fset.Position(pos)
	rel, err := filepath.Rel(x.root, position.Filename)
	if err != nil {
		rel = position.Filename
	}
	return auditPlace{filepath.ToSlash(rel), position.Line}
}

// auditDetailsTrace follows the details argument of one audit Log call.
type auditDetailsTrace struct {
	index      *auditDetailsIndex
	call       auditPlace
	written    map[string]map[string]bool
	unfollowed map[string]bool
	// seen holds each variable, function result and parameter already followed, so a cycle
	// through a chain of calls ends.
	seen map[any]bool
}

// unreadable records that the keys at pos cannot be read, and why.
func (t *auditDetailsTrace) unreadable(pos token.Pos, why string) {
	place := t.index.place(pos)
	if place == t.call {
		t.unfollowed[place.String()+": the keys of this audit Log call cannot be read: "+why] = true
		return
	}
	t.unfollowed[place.String()+": the keys of the audit Log call at "+t.call.String()+" cannot be read: "+why] = true
}

// once reports whether key is followed for the first time.
func (t *auditDetailsTrace) once(key any) bool {
	if t.seen[key] {
		return false
	}
	t.seen[key] = true
	return true
}

// details follows e, a value the details can be, to the keys it carries.
func (t *auditDetailsTrace) details(e ast.Expr) {
	e = ast.Unparen(e)
	if tv, ok := t.index.info.Types[e]; ok && tv.IsNil() {
		return
	}
	switch e := e.(type) {
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				t.unreadable(elt.Pos(), types.ExprString(elt)+" is not a key and a value")
				continue
			}
			t.key(kv.Key, kv.Value)
		}
	case *ast.Ident:
		v, ok := t.index.info.Uses[e].(*types.Var)
		if !ok {
			t.unreadable(e.Pos(), e.Name+" is not a variable")
			return
		}
		t.variable(v, e)
	case *ast.CallExpr:
		t.result(e, 0)
	default:
		t.unreadable(e.Pos(), types.ExprString(e)+" is not a local variable, a parameter, a map literal or a call")
	}
}

// key records the key k names, and when the value it holds is a map with string keys, that map's
// keys: they are payload keys as much as the ones beside k.
func (t *auditDetailsTrace) key(k, value ast.Expr) {
	if valueType := t.index.info.Types[value].Type; value != nil && valueType != nil {
		if m, ok := valueType.Underlying().(*types.Map); ok {
			if key, ok := m.Key().Underlying().(*types.Basic); ok && key.Kind() == types.String {
				t.details(value)
			}
		}
	}
	tv := t.index.info.Types[k]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		t.unreadable(k.Pos(), "the key "+types.ExprString(k)+" is not a constant string")
		return
	}
	key := constant.StringVal(tv.Value)
	if t.written[key] == nil {
		t.written[key] = map[string]bool{}
	}
	t.written[key][t.index.place(k.Pos()).String()] = true
}

// variable follows v, which at names: every value assigned to it, every key assigned into it, every
// key a function it is passed to assigns into it, and when it is a parameter every argument its
// callers pass.
func (t *auditDetailsTrace) variable(v *types.Var, at ast.Expr) {
	if !t.once(v) {
		return
	}
	if v.Parent() == t.index.pkg.Scope() {
		t.unreadable(at.Pos(), v.Name()+" is a package-level variable")
		return
	}
	for _, w := range t.index.writes[v] {
		switch {
		case w.why != "":
			t.unreadable(w.at, w.why)
		case w.call != nil:
			t.result(w.call, w.result)
		default:
			t.details(w.rhs)
		}
	}
	t.keysAssignedInto(v)
	t.callerArguments(v, at, t.details)
}

// keysAssignedInto records every key assigned into v, and into each parameter of this package's
// functions v is passed as.
func (t *auditDetailsTrace) keysAssignedInto(v *types.Var) {
	//nolint:unused // map key, read whole by the map's equality, never by selector
	type into struct{ v *types.Var }
	if !t.once(into{v}) {
		return
	}
	for _, write := range t.index.keyWrites[v] {
		t.key(write.key, write.value)
	}
	for _, forward := range t.index.forwards[v] {
		if param := t.index.param(forward.fn, forward.index); param != nil {
			t.keysAssignedInto(param)
		}
	}
}

// param is the index-th parameter of fn, or nil when fn has none there or is variadic there.
func (x *auditDetailsIndex) param(fn *types.Func, index int) *types.Var {
	params := fn.Type().(*types.Signature).Params()
	if index >= params.Len() {
		return nil
	}
	return params.At(index)
}

// callerArguments follows, when v is a parameter, the argument each caller passes in its place.
func (t *auditDetailsTrace) callerArguments(v *types.Var, at ast.Expr, follow func(ast.Expr)) {
	param, ok := t.index.params[v]
	if !ok {
		return
	}
	switch {
	case param.lit != nil:
		t.unreadable(at.Pos(), v.Name()+" is a parameter of a function literal, whose callers are not in sight")
	case param.fn.Exported():
		t.unreadable(at.Pos(), v.Name()+" is a parameter of "+param.fn.Name()+
			", which is exported, so not every caller is in sight")
	case t.index.asValue[param.fn]:
		t.unreadable(at.Pos(), v.Name()+" is a parameter of "+param.fn.Name()+
			", which is used as a value, so not every caller is in sight")
	case param.fn.Type().(*types.Signature).Variadic() &&
		param.index == param.fn.Type().(*types.Signature).Params().Len()-1:
		t.unreadable(at.Pos(), v.Name()+" is the variadic parameter of "+param.fn.Name())
	default:
		for _, call := range t.index.calls[param.fn] {
			if param.index < len(call.Args) {
				follow(call.Args[param.index])
			}
		}
	}
}

// result follows the index-th result of call.
func (t *auditDetailsTrace) result(call *ast.CallExpr, index int) {
	fun := ast.Unparen(call.Fun)
	var obj types.Object
	switch fun := fun.(type) {
	case *ast.Ident:
		obj = t.index.info.Uses[fun]
	case *ast.SelectorExpr:
		obj = t.index.info.Uses[fun.Sel]
	}
	switch obj := obj.(type) {
	case *types.Builtin:
		if obj.Name() == "make" {
			return // an empty map
		}
	case *types.Func:
		if decl := t.index.funcDecls[obj]; decl != nil && decl.Body != nil {
			t.returns(decl.Body, obj.Type().(*types.Signature), index)
			return
		}
	case *types.Var:
		if _, isSelector := fun.(*ast.SelectorExpr); !isSelector {
			t.functionValues(obj, fun, index)
			return
		}
	}
	t.unreadable(call.Pos(), types.ExprString(call.Fun)+" is not a function this package declares")
}

// returns follows the index-th result of every return statement in body, a function's whose
// signature is sig, leaving out those of the function literals inside it.
func (t *auditDetailsTrace) returns(body *ast.BlockStmt, sig *types.Signature, index int) {
	//nolint:unused // map key, read whole by the map's equality, never by selector
	type result struct {
		body  *ast.BlockStmt
		index int
	}
	if !t.once(result{body, index}) {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			switch {
			case len(n.Results) == 0 && index < sig.Results().Len():
				named := sig.Results().At(index)
				t.variable(named, &ast.Ident{NamePos: n.Pos(), Name: named.Name()})
			case len(n.Results) == 1 && sig.Results().Len() > 1:
				if call, ok := ast.Unparen(n.Results[0]).(*ast.CallExpr); ok {
					t.result(call, index)
				}
			case index < len(n.Results):
				t.details(n.Results[index])
			}
		}
		return true
	})
}

// functionValues follows v, a variable of function type called at fun, to each function it can
// hold, and the index-th result of each.
func (t *auditDetailsTrace) functionValues(v *types.Var, fun ast.Expr, index int) {
	//nolint:unused // map key, read whole by the map's equality, never by selector
	type held struct {
		v     *types.Var
		index int
	}
	if !t.once(held{v, index}) {
		return
	}
	follow := func(e ast.Expr) { t.functionValue(e, index) }
	for _, w := range t.index.writes[v] {
		if w.rhs == nil {
			t.unreadable(w.at, v.Name()+" is assigned a function this walk cannot follow")
			continue
		}
		follow(w.rhs)
	}
	t.callerArguments(v, fun, follow)
}

// functionValue follows e, a function value, to the index-th result of the function it is.
func (t *auditDetailsTrace) functionValue(e ast.Expr, index int) {
	e = ast.Unparen(e)
	if lit, ok := e.(*ast.FuncLit); ok {
		if sig, ok := t.index.info.Types[lit].Type.(*types.Signature); ok {
			t.returns(lit.Body, sig, index)
			return
		}
	}
	var id *ast.Ident
	switch e := e.(type) {
	case *ast.Ident:
		id = e
	case *ast.SelectorExpr:
		id = e.Sel
	}
	if id != nil {
		switch obj := t.index.info.Uses[id].(type) {
		case *types.Func:
			if decl := t.index.funcDecls[obj]; decl != nil && decl.Body != nil {
				t.returns(decl.Body, obj.Type().(*types.Signature), index)
				return
			}
		case *types.Var:
			if id == e {
				t.functionValues(obj, e, index)
				return
			}
		}
	}
	t.unreadable(e.Pos(), types.ExprString(e)+" is not a function this package declares")
}
