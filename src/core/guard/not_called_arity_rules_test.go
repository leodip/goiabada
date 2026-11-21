package guard

// Seam 1: the rule AssertNotCalledArity enforces, over a fixture module written into a temp tree
// and walked through the same function the real callers use.
//
// The synthetic half exists because the real half cannot fail informatively. #421 gave every
// vacuous assertion in the tree its real arity, so from here on the real call sites walk a clean
// tree and would pass identically whether the rule still fires or has quietly stopped matching
// anything. Every fixture below is a shape that was in the tree, or one that would have made the
// walk answer by spelling rather than by type.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// notCalledTestifyModules are the modules a fixture importing testify's mock requires: testify
// itself and the two modules its mock and assert packages import. The go command refuses to load a
// module whose go.mod leaves out a module one of its packages imports.
var notCalledTestifyModules = []string{
	"github.com/stretchr/testify",
	"github.com/stretchr/objx",
	"go.yaml.in/yaml/v3",
}

// requireTestify makes the fixture module at mod require the real testify, at the versions core
// pins, with core's go.sum beside it. The guard reads testify's own Mock, so a fixture double has
// to embed that and not a stand-in; the module cache already holds those versions, because core's
// own tests build with them, so the tree loads offline.
func requireTestify(t *testing.T, root, mod string) {
	t.Helper()
	core := filepath.Join(SourceRoot(t), "core")
	goMod, err := os.ReadFile(filepath.Join(core, "go.mod"))
	require.NoError(t, err)
	versions := requiredVersions(string(goMod))

	requires := "\nrequire (\n"
	for _, path := range notCalledTestifyModules {
		require.NotEmpty(t, versions[path], "core's go.mod requires no %s", path)
		requires += "\t" + path + " " + versions[path] + "\n"
	}
	modFile := filepath.Join(root, filepath.FromSlash(mod), "go.mod")
	own, err := os.ReadFile(modFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(modFile, append(own, requires+")\n"...), 0o644))

	sum, err := os.ReadFile(filepath.Join(core, "go.sum"))
	require.NoError(t, err)
	writeFixture(t, root, mod+"/go.sum", string(sum))
}

// requiredVersions reads the version of each module a go.mod requires, from a one-line require or a
// require block, with any comment removed.
func requiredVersions(goMod string) map[string]string {
	versions := map[string]string{}
	inBlock := false
	for _, line := range strings.Split(goMod, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && fields[0] == "require" && fields[1] == "(":
			inBlock = true
		case inBlock && len(fields) == 1 && fields[0] == ")":
			inBlock = false
		case len(fields) == 3 && fields[0] == "require":
			versions[fields[1]] = fields[2]
		case inBlock && len(fields) == 2:
			versions[fields[0]] = fields[1]
		}
	}
	return versions
}

func TestRequiredVersions_ReadsBothRequireFormsWithTheirComments(t *testing.T) {
	assert.Equal(t, map[string]string{
		"github.com/stretchr/testify": "v1.12.1",
		"github.com/stretchr/objx":    "v0.8.0",
		"go.yaml.in/yaml/v3":          "v3.0.6",
	}, requiredVersions("module example.com/mod\n\ngo 1.24\n\n"+
		"require (\n\tgithub.com/stretchr/testify v1.12.1\n\tgo.yaml.in/yaml/v3 v3.0.6 // indirect\n)\n\n"+
		"require github.com/stretchr/objx v0.8.0 // indirect\n"))
}

// notCalledFixtureModule writes the module every rule-table case shares: a package of generated
// doubles, a type with a method spelled like the assertion that is no double, a package named mock
// that is not testify's, and nothing else. The module requires the real testify. The caller adds
// the file holding the assertions.
func notCalledFixtureModule(t *testing.T, root string) {
	t.Helper()

	// No go line: makeLoadable writes the toolchain's, which is at least the newest one the modules
	// testify brings in declare, as core's own go line is.
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n")
	requireTestify(t, root, "mod")
	makeLoadable(t, root)

	writeFixture(t, root, "mod/doubles/database.go", `package doubles

import (
	"context"

	mock "github.com/stretchr/testify/mock"
)

type Tx struct{}

type User struct{}

// Database is the shape every generated double in this tree has: a struct embedding testify's
// Mock, with one method per interface method, each passing its own parameters to Called.
type Database struct {
	mock.Mock
}

func NewDatabase() *Database { return &Database{} }

func (_mock *Database) CreateUser(ctx context.Context, tx *Tx, user *User) error {
	ret := _mock.Called(ctx, tx, user)
	return ret.Error(0)
}

func (_mock *Database) GetUserById(ctx context.Context, tx *Tx, id int64) error {
	ret := _mock.Called(ctx, tx, id)
	return ret.Error(0)
}

func (_mock *Database) Query(query string, args ...interface{}) error {
	ret := _mock.Called(query, args)
	return ret.Error(0)
}
`)

	writeFixture(t, root, "mod/doubles/creator.go", `package doubles

import (
	"context"

	mock "github.com/stretchr/testify/mock"
)

// UserCreator declares CreateUser too, at a different arity. Nothing but the receiver's type tells
// the two apart, which is why the rule resolves the receiver instead of indexing by method name.
type UserCreator struct {
	mock.Mock
}

func NewUserCreator() *UserCreator { return &UserCreator{} }

func (_mock *UserCreator) CreateUser(ctx context.Context, user *User) error {
	ret := _mock.Called(ctx, user)
	return ret.Error(0)
}
`)

	writeFixture(t, root, "mod/plain/plain.go", `package plain

// NotADouble embeds nothing of testify's and declares a method spelled like the assertion. A call
// of it is no testify assertion, so it is no site, whatever its arguments.
type NotADouble struct{}

func New() *NotADouble { return &NotADouble{} }

func (n *NotADouble) Log(a int, b int, c int) {}

func (n *NotADouble) AssertNotCalled(t any, methodName string, arguments ...any) bool {
	return true
}
`)

	writeFixture(t, root, "mod/fakemock/mock.go", `package mock

// Mock is spelled as testify's is, in a package named as testify's is, and is neither. A struct
// embedding it is written mock.Mock exactly as a generated double is.
type Mock struct{}

func (m *Mock) AssertNotCalled(t any, methodName string, arguments ...any) bool {
	return true
}
`)
}

// notCalledNames renders the findings as "<method> <given>/<want> on <recv>" so a failure names
// what was missed rather than printing a struct.
func notCalledNames(findings []notCalledFinding) []string {
	names := make([]string, 0, len(findings))
	for _, f := range findings {
		names = append(names, f.method+" "+strconv.Itoa(f.given)+"/"+strconv.Itoa(f.want)+
			" on "+f.recv)
	}
	return names
}

// TestNotCalledArity_TheRuleTable builds one module carrying every shape at once and asserts the
// exact set of findings. One module rather than one per row, because the interesting half of this
// rule is resolution: a row that cannot see the doubles it asserts against cannot exercise it.
func TestNotCalledArity_TheRuleTable(t *testing.T) {
	root := t.TempDir()
	notCalledFixtureModule(t, root)

	writeFixture(t, root, "mod/tests/rules_test.go", `package tests

import (
	"context"
	"testing"

	"example.com/mod/doubles"
	"example.com/mod/plain"
	mock "github.com/stretchr/testify/mock"
)

// local is a double declared beside the assertions rather than imported, because a rule that only
// resolved through an import would pass this file by.
type local struct {
	mock.Mock
}

func (_mock *local) Send(ctx context.Context, to string) error {
	ret := _mock.Called(ctx, to)
	return ret.Error(0)
}

// held carries a double in a field, which is how a table-driven test in this tree reaches one.
type held struct {
	database *doubles.Database
}

func newHeld() *held { return &held{database: doubles.NewDatabase()} }

func TestRules(t *testing.T) {
	database := doubles.NewDatabase()
	creator := doubles.NewUserCreator()
	sender := &local{}
	h := newHeld()
	other := plain.New()

	// Row 1: the bare form. Three parameters, no matchers, so the comparison can never be true.
	database.AssertNotCalled(t, "CreateUser")

	// Row 2: a partial list, which is the same defect reached by a rename rather than by habit.
	database.AssertNotCalled(t, "GetUserById", mock.Anything)

	// Row 3: the correct arity, which must survive untouched.
	database.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything, mock.Anything)

	// Rows 4 and 5: one method name, two doubles, two arities. Each is held to its own receiver's
	// signature, so the first passes and the second is a finding although the spelling matches.
	creator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)

	// Row 6: a double declared in this package rather than imported.
	sender.AssertNotCalled(t, "Send")

	// Row 7: the receiver reached through a struct field.
	h.database.AssertNotCalled(t, "CreateUser", mock.Anything)

	// Row 8: a name the resolved double does not declare, which can never match anything.
	database.AssertNotCalled(t, "DeleteUser", mock.Anything, mock.Anything, mock.Anything)

	// Row 9: a method named through a variable, whose arity no walk can read.
	for _, name := range []string{"CreateUser"} {
		database.AssertNotCalled(t, name, mock.Anything, mock.Anything, mock.Anything)
	}

	// Row 10: a variadic method, whose recorded length is not its parameter count.
	database.AssertNotCalled(t, "Query", mock.Anything, mock.Anything)

	// Row 11: a method of the name on a type that is no double. Two matchers against a Log of
	// three would be a finding if the walk matched the spelling.
	other.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)

	// Rows 14 and 15: a method expression, whose first argument is the receiver. Three matchers
	// against a CreateUser of three pass; one is a finding.
	(*doubles.Database).AssertNotCalled(database, t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
	(*doubles.Database).AssertNotCalled(database, t, "CreateUser", mock.Anything)
}
`)
	writeFixture(t, root, "mod/tests/lookalike_test.go", `package tests

import (
	"testing"

	"example.com/mod/fakemock"
)

// lookalike embeds a Mock written mock.Mock, from a package named mock that is not testify's.
type lookalike struct {
	mock.Mock
}

func (l *lookalike) Ping(a int) {}

func TestLookalike(t *testing.T) {
	// Row 12: the assertion spelled exactly as on a double, through the lookalike's own method.
	// No matcher against a Ping of one would be a finding if the walk matched the package name.
	(&lookalike{}).AssertNotCalled(t, "Ping")
}
`)

	// Row 13: a test-support helper in a production file of a package that has tests too. The test
	// build checks that file twice, once with the package's tests, and it is one site.
	writeFixture(t, root, "mod/support/support.go", `package support

import (
	"example.com/mod/doubles"
	mock "github.com/stretchr/testify/mock"
)

func AssertNoUserCreated(t mock.TestingT, database *doubles.Database) {
	database.AssertNotCalled(t, "CreateUser", mock.Anything)
}
`)
	writeFixture(t, root, "mod/support/support_test.go", `package support

import (
	"testing"

	"example.com/mod/doubles"
)

func TestSupport(t *testing.T) {
	AssertNoUserCreated(t, doubles.NewDatabase())
}
`)

	findings, blocked, sites, err := findNotCalledArity(root, []string{"mod"})
	require.NoError(t, err)
	assert.Equal(t, 13, sites,
		"every testify assertion is reached once, including the three the walk refuses, and "+
			"neither call of a method merely spelled like it")

	assert.Equal(t, []string{
		"CreateUser 1/3 on *doubles.Database",
		"CreateUser 0/3 on *doubles.Database",
		"GetUserById 1/3 on *doubles.Database",
		"CreateUser 2/3 on *doubles.Database",
		"Send 0/2 on *local",
		"CreateUser 1/3 on *doubles.Database",
		"CreateUser 1/3 on *doubles.Database",
	}, notCalledNames(findings))

	require.Len(t, blocked, 3)
	assert.Contains(t, blocked[0].why, "does not declare")
	assert.Contains(t, blocked[1].why, "string literal")
	assert.Contains(t, blocked[2].why, "variadic")
}

// TestNotCalledArity_AWalkThatReachesNoAssertionIsNotAPass pins the one way this guard stops
// guarding without anything going red. A dirs argument that no longer names any Go source reaches
// no assertion, finds nothing, and would otherwise be indistinguishable from a tree whose every
// assertion is correct.
func TestNotCalledArity_AWalkThatReachesNoAssertionIsNotAPass(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "mod", "empty"), 0o755))

	findings, blocked, sites, err := findNotCalledArity(root, []string{"mod/empty"})
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Empty(t, blocked)
	assert.Zero(t, sites, "AssertNotCalledArity turns a zero site count into a t.Fatalf")
}

// A //line directive before the package clause moves where a diagnostic points, not where the file
// is: a test file in a walked directory is walked whatever it maps itself to, and its site is
// reported at its own line.
func TestNotCalledArity_ALineDirectiveDoesNotTakeAFileOutOfTheWalk(t *testing.T) {
	root := t.TempDir()
	notCalledFixtureModule(t, root)
	writeFixture(t, root, "mod/held/generated_test.go", `//line ../elsewhere/generated.go:1
package held

import (
	"testing"

	"example.com/mod/doubles"
)

func TestGenerated(t *testing.T) {
	doubles.NewDatabase().AssertNotCalled(t, "CreateUser")
}
`)

	findings, blocked, sites, err := findNotCalledArity(root, []string{"mod/held"})
	require.NoError(t, err)
	assert.Equal(t, 1, sites)
	assert.Empty(t, blocked)
	require.Equal(t, []string{"CreateUser 0/3 on *doubles.Database"}, notCalledNames(findings))
	assert.Equal(t, "mod/held/generated_test.go", findings[0].file)
	assert.Equal(t, 11, findings[0].line)
}

// TestNotCalledArity_SitesOutsideTheWalkedDirsAreNotHeld keeps the dirs argument meaningful: the
// module is loaded whole, but only the sites in the directories the caller named are held.
func TestNotCalledArity_SitesOutsideTheWalkedDirsAreNotHeld(t *testing.T) {
	root := t.TempDir()
	notCalledFixtureModule(t, root)
	writeFixture(t, root, "mod/held/held_test.go", `package held

import (
	"testing"

	"example.com/mod/doubles"
	mock "github.com/stretchr/testify/mock"
)

func TestHeld(t *testing.T) {
	doubles.NewDatabase().AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
}
`)
	writeFixture(t, root, "mod/elsewhere/elsewhere_test.go", `package elsewhere

import (
	"testing"

	"example.com/mod/doubles"
)

func TestElsewhere(t *testing.T) {
	doubles.NewDatabase().AssertNotCalled(t, "CreateUser")
}
`)

	findings, refused, sites, err := findNotCalledArity(root, []string{"mod/held"})
	require.NoError(t, err)
	assert.Equal(t, 1, sites)
	assert.Empty(t, notCalledNames(findings), "the vacuous site is outside the walked dirs")
	assert.Empty(t, refused)
}

// Seam 2: the reporting half. Everything above asserts on what findNotCalledArity returned, which
// leaves the lines that turn those findings into a failure untested -- and those are the lines
// whose loss disables the guard in every module at once. See the note on Reporter in guard.go.

// TestNotCalledArity_TheGuardFailsOnAVacuousAssertion drives the reporting half against a tree
// that holds one, and asserts the reader is told where it is, what it compared, and what to do.
func TestNotCalledArity_TheGuardFailsOnAVacuousAssertion(t *testing.T) {
	root := t.TempDir()
	notCalledFixtureModule(t, root)
	writeFixture(t, root, "mod/tests/rules_test.go", `package tests

import (
	"testing"

	"example.com/mod/doubles"
)

func TestRules(t *testing.T) {
	database := doubles.NewDatabase()
	database.AssertNotCalled(t, "CreateUser")
}
`)

	report := Run(func(r Reporter) {
		assertNotCalledArity(r, root, []string{"mod"})
	})

	require.True(t, report.Failed(), "a tree with a vacuous assertion passed the guard")
	assert.False(t, report.Stopped, "a vacuous assertion is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "mod/tests/rules_test.go:11")
	assert.Contains(t, report.Text(),
		"passes 0 matcher(s) to *doubles.Database.CreateUser, which takes 3")
	assert.Contains(t, report.Text(), "1 AssertNotCalled assertion(s) that can never fail")
	assert.Contains(t, report.Text(), "#421")
}

// TestNotCalledArity_TheGuardPassesAnAssertionCarryingItsRealArity is the other direction, and it
// is what keeps the case above from passing for the wrong reason. A harness that called everything
// a failure would satisfy that assertion on a clean tree too.
func TestNotCalledArity_TheGuardPassesAnAssertionCarryingItsRealArity(t *testing.T) {
	root := t.TempDir()
	notCalledFixtureModule(t, root)
	writeFixture(t, root, "mod/tests/rules_test.go", `package tests

import (
	"testing"

	"example.com/mod/doubles"
	mock "github.com/stretchr/testify/mock"
)

func TestRules(t *testing.T) {
	database := doubles.NewDatabase()
	database.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
}
`)

	report := Run(func(r Reporter) {
		assertNotCalledArity(r, root, []string{"mod"})
	})

	assert.False(t, report.Failed(),
		"an assertion carrying a matcher per parameter failed the guard: %s", report.Text())
}

// TestNotCalledArity_TheGuardIsFatalOnAnEmptyWalk completes the seam the finder test above could
// only assert indirectly, through the site count. A scope holding no assertion is the way this
// guard stops guarding with nothing going red, so it has to be fatal rather than clean.
func TestNotCalledArity_TheGuardIsFatalOnAnEmptyWalk(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "mod", "empty"), 0o755))

	report := Run(func(r Reporter) {
		assertNotCalledArity(r, root, []string{"mod/empty"})
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no AssertNotCalled call under")
	assert.Contains(t, report.Fatal, "mod/empty", "the fatal names the dirs that covered nothing")
}

// TestNotCalledArity_ABuildSelectingNoPackageIsAnEmptyWalk: a module whose only file a custom
// build tag selects holds no package the test build reads. That is an empty walk, reported as one,
// and not a load failure.
func TestNotCalledArity_ABuildSelectingNoPackageIsAnEmptyWalk(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "mod/go.mod", "module example.com/mod\n\ngo 1.24\n")
	writeFixture(t, root, "mod/tests/rules_test.go", "//go:build customtag\n\npackage tests\n")
	makeLoadable(t, root)

	report := Run(func(r Reporter) {
		assertNotCalledArity(r, root, []string{"mod/tests"})
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no AssertNotCalled call under")
	assert.NotContains(t, report.Fatal, "selects no package", "an empty build is no load failure")
}

// TestNotCalledArity_AModuleSelectingNoPackageDoesNotStopTheOthers: a module the build selects no
// package of contributes nothing, and the modules beside it are still read and reported.
func TestNotCalledArity_AModuleSelectingNoPackageDoesNotStopTheOthers(t *testing.T) {
	root := t.TempDir()
	// No go line, as in the shared module: a go line here would be the tree's, and testify's modules
	// declare a later one.
	writeFixture(t, root, "first/go.mod", "module example.com/first\n")
	writeFixture(t, root, "first/tests/rules_test.go", "//go:build customtag\n\npackage tests\n")
	notCalledFixtureModule(t, root)
	writeFixture(t, root, "mod/tests/rules_test.go", `package tests

import (
	"testing"

	"example.com/mod/doubles"
)

func TestRules(t *testing.T) {
	database := doubles.NewDatabase()
	database.AssertNotCalled(t, "CreateUser")
}
`)

	report := Run(func(r Reporter) {
		assertNotCalledArity(r, root, []string{"first/tests", "mod/tests"})
	})

	require.False(t, report.Stopped, "an empty module stopped the walk: %s", report.Fatal)
	assert.Contains(t, report.Text(), "mod/tests/rules_test.go:11")
	assert.Contains(t, report.Text(), "passes 0 matcher(s) to *doubles.Database.CreateUser, which takes 3")
}

// TestNotCalledArity_TheGuardReportsAMethodNamedThroughAVariable holds the other half of the
// reporting: a shape no walk can hold to an arity is an error of its own rather than a silent
// narrowing. The shape here is the one the tree actually had -- a helper looping over method names its callers
// passed, which was vacuous at every one of them and which no arity check could have read.
func TestNotCalledArity_TheGuardReportsAMethodNamedThroughAVariable(t *testing.T) {
	root := t.TempDir()
	notCalledFixtureModule(t, root)
	writeFixture(t, root, "mod/tests/rules_test.go", `package tests

import (
	"testing"

	"example.com/mod/doubles"
	mock "github.com/stretchr/testify/mock"
)

func assertNotAttempted(t *testing.T, database *doubles.Database, methods ...string) {
	for _, method := range methods {
		database.AssertNotCalled(t, method, mock.Anything, mock.Anything)
	}
}

func TestRules(t *testing.T) {
	assertNotAttempted(t, doubles.NewDatabase(), "CreateUser")
}
`)

	report := Run(func(r Reporter) {
		assertNotCalledArity(r, root, []string{"mod"})
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), "mod/tests/rules_test.go:12")
	assert.Contains(t, report.Text(), "string literal")
}

// TestNotCalledArity_TheGuardIsFatalOnAPackageThatDoesNotCompile holds decision 3 of #420. The
// module is read type-checked, and a package that does not compile leaves its assertions unread,
// which is a pass nobody sees. The guard stops instead, naming the package.
func TestNotCalledArity_TheGuardIsFatalOnAPackageThatDoesNotCompile(t *testing.T) {
	root := t.TempDir()
	notCalledFixtureModule(t, root)
	writeFixture(t, root, "mod/tests/rules_test.go", `package tests

import (
	"testing"

	"example.com/mod/doubles"
)

func TestRules(t *testing.T) {
	database := doubles.NewDatabase()
	database.AssertNotCalled(t, "CreateUser", undeclared)
}
`)

	report := Run(func(r Reporter) {
		assertNotCalledArity(r, root, []string{"mod"})
	})

	require.True(t, report.Stopped, "a package that does not compile must stop the guard: %s", report.Text())
	assert.Contains(t, report.Fatal, "example.com/mod/tests")
	assert.Contains(t, report.Fatal, "undeclared")
	assert.Contains(t, report.Fatal, "cannot be read until it does")
}

// Seam 3: the premise. Everything above is consistent with a rule that refuses a shape which is in
// fact harmless. These two doubles measure testify's matching against testify, so a release that
// started matching on the method name alone leaves the guard standing over a defect that no longer
// exists with something going red to say so.
//
// Neither assertion below is one this guard refuses, which is not a dodge but the demonstration
// itself: the recorded argument list is whatever the double passes to Called, and honestDouble and
// driftedDouble differ in exactly that. Writing the refused shape here would have needed an
// admission table, and an admission is a worse answer than a second double.

// honestDouble records what it declares, which is what mockery generates and what the rule reads.
type honestDouble struct {
	mock.Mock
}

func (d *honestDouble) Log(ctx context.Context, event string, details map[string]any) {
	d.Called(ctx, event, details)
}

// driftedDouble declares one parameter and records three. No generator writes this; it is here
// because it is the one way to watch a matcher list of the wrong length meet a recorded call
// without writing a matcher list of the wrong length.
type driftedDouble struct {
	mock.Mock
}

func (d *driftedDouble) Log(event string) {
	d.Called(context.Background(), event, map[string]any(nil))
}

// recordingT is the whole of testify's TestingT, recording rather than failing, so a test can
// observe what an assertion said without saying it.
type recordingT struct {
	failed bool
}

func (r *recordingT) Logf(string, ...interface{})   {}
func (r *recordingT) Errorf(string, ...interface{}) { r.failed = true }
func (r *recordingT) FailNow()                      {}

// TestNotCalledArity_TestifySeesACallItsMatchersLineUpWith is the half that says the assertion
// works at all: a matcher per recorded argument finds the call and fails.
func TestNotCalledArity_TestifySeesACallItsMatchersLineUpWith(t *testing.T) {
	double := &honestDouble{}
	double.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
	double.Log(context.Background(), "an event", nil)

	live := &recordingT{}
	assert.False(t, double.AssertNotCalled(live, "Log", mock.Anything, mock.Anything, mock.Anything),
		"an assertion carrying a matcher per recorded argument has to see the call")
	assert.True(t, live.failed)
}

// TestNotCalledArity_TestifyMissesACallItsMatchersDoNotLineUpWith is the defect itself, and the
// whole reason the guard exists: the same assertion over a shorter matcher list passes although
// the call happened, and says nothing.
func TestNotCalledArity_TestifyMissesACallItsMatchersDoNotLineUpWith(t *testing.T) {
	double := &driftedDouble{}
	double.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
	double.Log("an event")

	vacuous := &recordingT{}
	assert.True(t, double.AssertNotCalled(vacuous, "Log", mock.Anything),
		"testify accepted an AssertNotCalled whose matcher list is shorter than the recorded "+
			"argument list, against a method that was called: this is the defect #421 exists to "+
			"refuse, and the guard is built on it")
	assert.False(t, vacuous.failed)
}
