package data

// The one place the repository is held to "no production code saves a user by writing back the
// row it read".
//
// UpdateUser writes every column record.User does not tag dont-update, from the model the caller
// holds. A request holds that model from its own start, so whatever another request wrote in
// between is silently undone: an administrator's disable after its revocation sweep has run, a
// password change or reset, so the old password works again, an OTP enable or disable (#471).
// Each save therefore writes only the columns it means to change, through a narrow write, and one
// that depends on what it read is a compare-and-set. UpdateUser itself stays on the Database
// interface, because the data and integration tiers seed their fixtures through it, so the
// compiler cannot hold the rule; this test does.
//
// It reads and parses files and nothing else, as the bare-transaction lint beside it does, so it
// runs in the authserver internal tier on every CI job.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wholeRowUserSaveExemptions are the files still allowed to call UpdateUser, each with its reason,
// relative to the source root, forward slashes. A legitimate reason says why no concurrent writer
// of that user can exist. The entries below are not that: they are the sites #471 found, each a
// known defect left listed until the change that converts it to a narrow write deletes its row,
// and an entry whose file no longer calls UpdateUser fails the guard, so none outlives its site.
// The list is not the place for a new site.
var wholeRowUserSaveExemptions = map[string]string{
	"authserver/internal/handlers/apihandlers/handler_api_users_crud.go": "the reset code stamped " +
		"on a user the administrator just created with a set-password email, not yet converted: " +
		"it writes back the whole row after the insert and can undo a change made in between (#471)",
	"authserver/internal/otpcredential/otpcredential.go": "establishing and removing an " +
		"authenticator, not yet converted: each writes back the whole row and can undo a " +
		"concurrent disable, password change or the other OTP change (#471)",
}

// updateUserCall is one call expression selecting UpdateUser.
type updateUserCall struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
}

// findUpdateUserCalls walks root for non-test Go files and reports every CALL to a method or
// function named UpdateUser, exempt files included, since the reporting half needs to know which
// exemptions still have a site. Declarations are not calls: the Database interface, commondb's
// implementation and the generated mock all declare the name and keep it, and the mock's
// expectation names it in a string. Parsing is what tells them apart. A longer name, such as
// UpdateUserGroup, is a different method and is not matched.
func findUpdateUserCalls(root string) ([]updateUserCall, int, error) {
	var calls []updateUserCall
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns.
			return nil
		}
		files++
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			case *ast.Ident:
				name = fun.Name
			}
			if name == "UpdateUser" {
				calls = append(calls, updateUserCall{file: rel, line: fset.Position(call.Pos()).Line})
			}
			return true
		})
		return nil
	})
	return calls, files, err
}

// TestNoWholeRowUserSave holds the real tree to the rule.
func TestNoWholeRowUserSave(t *testing.T) {
	assertNoWholeRowUserSave(t, guard.SourceRoot(t), wholeRowUserSaveExemptions)
}

// assertNoWholeRowUserSave is the reporting half, taking the root and the exemptions as
// parameters and failing through a guard.Reporter so a rule test can drive it against a fixture
// tree.
func assertNoWholeRowUserSave(r guard.Reporter, root string, exempt map[string]string) {
	r.Helper()

	calls, files, err := findUpdateUserCalls(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A root that somehow held no Go files walks nothing and would otherwise pass.
	if files == 0 {
		r.Fatalf("walked no Go files under %s", root)
	}

	calling := map[string]bool{}
	var unlisted []string
	for _, c := range calls {
		calling[c.file] = true
		if _, ok := exempt[c.file]; !ok {
			unlisted = append(unlisted, c.file+":"+itoa(c.line))
		}
	}
	if len(unlisted) > 0 {
		r.Errorf("%d production UpdateUser call(s):\n\t%s\n\n"+
			"Save a user through a narrow write that names only the columns the save changes, "+
			"such as SetUserPasswordHash, TrySetUserEmail or TrySetUserEnabled, adding one to the "+
			"Database interface when none covers those columns; a save that depends on what the "+
			"request read is a compare-and-set that reports whether it matched. UpdateUser writes "+
			"back every column of the row as the request read it, so it silently undoes whatever "+
			"another request changed in between: an administrator's disable, a password change "+
			"or reset, an OTP change (#471). It stays on the interface for the data and "+
			"integration tiers' fixtures only.",
			len(unlisted), strings.Join(unlisted, "\n\t"))
	}

	var stale, unreasoned []string
	for file, reason := range exempt {
		if !calling[file] {
			stale = append(stale, file)
		}
		if strings.TrimSpace(reason) == "" {
			unreasoned = append(unreasoned, file)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		r.Errorf("%d UpdateUser exemption(s) for a file that no longer calls it:\n\t%s\n\n"+
			"Delete the row: an exemption outliving its site would admit the next whole-row save "+
			"written in that file.", len(stale), strings.Join(stale, "\n\t"))
	}
	if len(unreasoned) > 0 {
		sort.Strings(unreasoned)
		r.Errorf("%d UpdateUser exemption(s) with no reason:\n\t%s\n\n"+
			"Each row says why no concurrent writer of that user can exist.",
			len(unreasoned), strings.Join(unreasoned, "\n\t"))
	}
}

// writeUpdateUserFixture is a tree holding the three shapes that must never be reported: the
// interface declaration, a mockery-shaped declaration and expectation, and a narrow write.
func writeUpdateUserFixture(t *testing.T, root string) {
	t.Helper()
	writeLintFixture(t, root, "authserver/internal/data/database.go", `package data

import "database/sql"

type User struct{}

type Database interface {
	UpdateUser(tx *sql.Tx, user *User) error
	UpdateUserGroup(tx *sql.Tx, user *User) error
	SetUserPasswordHash(tx *sql.Tx, userId int64, passwordHash string) error
}
`)
	writeLintFixture(t, root, "authserver/internal/data/mocks/database_mock.go", `package mocks

type mocker struct{}

func (m *mocker) On(name string, args ...any) *mocker { return m }

type Database struct{ mock mocker }

func (_mock *Database) UpdateUser(user any) error { return nil }

type Database_Expecter struct{ mock *mocker }

func (_e *Database_Expecter) UpdateUser(user any) *mocker { return _e.mock.On("UpdateUser", user) }
`)
	writeLintFixture(t, root, "authserver/internal/handlers/narrow.go", `package handlers

type db interface {
	SetUserPasswordHash(userId int64, passwordHash string) error
	UpdateUserGroup(userId int64) error
}

// A comment naming UpdateUser() is not a call.
const message = "UpdateUser() failed"

func save(d db) error {
	if err := d.UpdateUserGroup(1); err != nil {
		return err
	}
	return d.SetUserPasswordHash(1, message)
}
`)
}

// TestNoWholeRowUserSave_TheCheckerTellsACallFromADeclaration drives the finder over a tree with
// each shape the real tree contains, so a finder that has quietly stopped matching anything, or
// started matching declarations, longer names or test files, is caught here rather than trusted.
func TestNoWholeRowUserSave_TheCheckerTellsACallFromADeclaration(t *testing.T) {
	root := t.TempDir()
	writeUpdateUserFixture(t, root)
	// Not reported: a test file, where fixtures are seeded through UpdateUser.
	writeLintFixture(t, root, "authserver/tests/data/user_test.go", `package data

func seed(db interface{ UpdateUser() error }) error { return db.UpdateUser() }
`)
	// Reported: a call through a selector, and one through a bare identifier.
	writeLintFixture(t, root, "authserver/internal/handlers/whole.go", `package handlers

type wholeRow interface{ UpdateUser(id int64) error }

func whole(d wholeRow) error {
	return d.UpdateUser(1)
}
`)
	writeLintFixture(t, root, "core/user/local.go", `package user

func UpdateUser() error { return nil }

func owner() error { return UpdateUser() }
`)

	calls, files, err := findUpdateUserCalls(root)
	require.NoError(t, err)
	assert.Equal(t, 5, files, "every non-test file is parsed")
	assert.Equal(t, []updateUserCall{
		{file: "authserver/internal/handlers/whole.go", line: 6},
		{file: "core/user/local.go", line: 5},
	}, calls)
}

// TestNoWholeRowUserSave_TheGuardFailsOnAnUnlistedCall is a tree that must fail: a production call
// in a file the exemptions do not name.
func TestNoWholeRowUserSave_TheGuardFailsOnAnUnlistedCall(t *testing.T) {
	root := t.TempDir()
	writeUpdateUserFixture(t, root)
	writeLintFixture(t, root, "authserver/internal/handlers/whole.go", `package handlers

type wholeRow interface{ UpdateUser(id int64) error }

func whole(d wholeRow) error {
	return d.UpdateUser(1)
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoWholeRowUserSave(r, root, map[string]string{})
	})

	require.True(t, report.Failed(), "a production UpdateUser call passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/whole.go:6")
	assert.Contains(t, report.Text(), "narrow write")
	assert.Contains(t, report.Text(), "#471")
}

// TestNoWholeRowUserSave_TheGuardPassesNarrowWritesAndListedSites is a tree that must pass: the
// shapes that are not calls, and a call in a file the exemptions name with a reason.
func TestNoWholeRowUserSave_TheGuardPassesNarrowWritesAndListedSites(t *testing.T) {
	root := t.TempDir()
	writeUpdateUserFixture(t, root)
	writeLintFixture(t, root, "authserver/internal/bootstrap/seed.go", `package bootstrap

type wholeRow interface{ UpdateUser(id int64) error }

func seed(d wholeRow) error {
	return d.UpdateUser(1)
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoWholeRowUserSave(r, root, map[string]string{
			"authserver/internal/bootstrap/seed.go": "the row is created in this same transaction",
		})
	})

	assert.False(t, report.Failed(), "the guard failed a tree with no unlisted call: %s", report.Text())
}

// TestNoWholeRowUserSave_TheGuardFailsOnAStaleExemption is the direction that keeps the list from
// outliving its sites: a listed file that makes no call, or no longer exists, fails, while a listed
// file that still calls passes.
func TestNoWholeRowUserSave_TheGuardFailsOnAStaleExemption(t *testing.T) {
	root := t.TempDir()
	writeUpdateUserFixture(t, root)
	writeLintFixture(t, root, "authserver/internal/handlers/still.go", `package handlers

type wholeRow interface{ UpdateUser(id int64) error }

func still(d wholeRow) error {
	return d.UpdateUser(1)
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoWholeRowUserSave(r, root, map[string]string{
			"authserver/internal/handlers/still.go":  "still calls it",
			"authserver/internal/handlers/narrow.go": "converted, but the row was left",
			"authserver/internal/handlers/gone.go":   "deleted, but the row was left",
		})
	})

	require.True(t, report.Failed(), "a stale exemption passed the guard")
	assert.False(t, report.Stopped, "a stale exemption is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/narrow.go")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/gone.go")
	assert.NotContains(t, report.Text(), "authserver/internal/handlers/still.go")
}

// TestNoWholeRowUserSave_TheGuardFailsOnAnExemptionWithNoReason holds every row to carrying its
// reason, which is the only thing the list says beyond the file name.
func TestNoWholeRowUserSave_TheGuardFailsOnAnExemptionWithNoReason(t *testing.T) {
	root := t.TempDir()
	writeUpdateUserFixture(t, root)
	writeLintFixture(t, root, "authserver/internal/handlers/still.go", `package handlers

type wholeRow interface{ UpdateUser(id int64) error }

func still(d wholeRow) error {
	return d.UpdateUser(1)
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoWholeRowUserSave(r, root, map[string]string{
			"authserver/internal/handlers/still.go": "  ",
		})
	})

	require.True(t, report.Failed(), "an exemption with no reason passed the guard")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/still.go")
	assert.Contains(t, report.Text(), "reason")
}

// TestNoWholeRowUserSave_TheGuardIsFatalOnAnEmptyWalk: a root holding no Go file reports nothing,
// which is indistinguishable from a tree that saves every user through a narrow write.
func TestNoWholeRowUserSave_TheGuardIsFatalOnAnEmptyWalk(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) {
		assertNoWholeRowUserSave(r, t.TempDir(), map[string]string{})
	})

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no Go files under")
}
