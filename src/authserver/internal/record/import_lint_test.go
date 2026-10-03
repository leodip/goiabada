package record

// The one place this package is held to "a persistence record imports nothing that does anything".
//
// record is the rows as they are stored, and every other package in the auth server names it: the
// data layer, the handlers, the services, the issuer. That makes it the cheapest place in the tree
// to put a capability and the worst -- whatever it imports, everything above it compiles against.
// Two methods had already been put there. User.SetOTPSecret and GetOTPSecret encrypted and
// decrypted a TOTP seed, so a cipher sat behind every package naming a stored user; KeyPair's
// ParsePrivateKey decrypted and parsed a signing key, so a JWT library did too. Neither is a fact
// about a row. Both were reachable only as methods on the record, which is why both were written
// there rather than beside the code that owns the capability (#387).
//
// The rule is therefore about the import list and not about any one method: a record that can name
// no cipher, no parser, no database and no service cannot grow a third such method without this
// going red first. Two paths are allowed beside the standard library.
//
// It reads and parses files and nothing else: no database, no git, no network.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordDir is the package the rule covers, relative to the source root, forward slashes.
const recordDir = "authserver/internal/record"

// recordAllowedImports is every non-standard-library path a production file here may name.
//
// core/builtin carries the permission identifiers Client and Resource name, and core/errs is
// this tree's one error constructor, which the four enumerations #385 moved in here -- AcrLevel,
// KeyState, PasswordPolicy and ThreeStateSetting -- raise their refusals through, and which
// CLAUDE.md pattern 7 requires of every error this tree constructs. Both are declarations and
// values rather than behaviour, which is the test for anything that would be added here: a path
// that makes this package able to *do* something belongs on the other side of the call, not in
// this list.
//
// The standard library is allowed and is not listed, because it is recognised by shape: an import
// path whose first element carries no dot is not a module path. database/sql is the load-bearing
// one -- sql.NullTime and sql.NullString are half the fields in this package -- and it is types
// only; the data layer holds the *sql.DB and every statement.
var recordAllowedImports = map[string]string{
	"github.com/leodip/goiabada/core/builtin": "the permission identifiers Client and Resource name",
	"github.com/leodip/goiabada/core/errs":    "the error constructor pattern 7 requires",
}

// foreignImport is one import a production file in the package names that the rule does not allow.
type foreignImport struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	path string
}

// findForeignImports walks root/dir for non-test Go files and reports every import path that is
// neither standard library nor in allowed. It returns the number of files it parsed, so the
// reporting half can tell "nothing to report" from "nothing was read".
//
// Only the directory itself, not its subtree: record has no subpackages, and a walk that
// descended would quietly start covering one the day somebody adds it, under a rule written for
// this package alone.
//
// Direct imports only, which is the rule as decision 8 states it and is also the rule worth
// having: both methods that provoked this named their library in this directory's own import
// block. A transitive rule would additionally hold core/errs and core/builtin to what they
// import, which is those packages' business and is already covered by ARCHITECTURE.md's tables.
func findForeignImports(root, dir string, allowed map[string]string) ([]foreignImport, int, error) {
	start := filepath.Join(root, filepath.FromSlash(dir))

	entries, err := os.ReadDir(start)
	if err != nil {
		return nil, 0, err
	}

	var found []foreignImport
	files := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(start, entry.Name())

		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and
			// reporting it here would send the reader to the wrong place.
			continue
		}
		files++

		rel := dir + "/" + entry.Name()
		for _, spec := range file.Imports {
			if spec.Path == nil {
				continue
			}
			imported, uErr := strconv.Unquote(spec.Path.Value)
			if uErr != nil {
				continue
			}
			if isStandardLibraryPath(imported) {
				continue
			}
			if _, ok := allowed[imported]; ok {
				continue
			}
			found = append(found, foreignImport{
				file: rel,
				line: fset.Position(spec.Pos()).Line,
				path: imported,
			})
		}
	}

	return found, files, nil
}

// isStandardLibraryPath reports whether an import path names the standard library, which is
// decidable from the path alone: the go command itself treats a first element with no dot in it as
// not a module path, which is why no module can be published under one.
func isStandardLibraryPath(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// TestRecord_ImportsNothingButValuesAndTheStandardLibrary holds the real tree to the rule. It is
// acceptance bullet 3 of #387 in its checkable form, which is stronger than the bullet as worded:
// the bullet names two methods, and an import list names every way back in.
func TestRecord_ImportsNothingButValuesAndTheStandardLibrary(t *testing.T) {
	assertNoForeignImports(t, guard.SourceRoot(t), recordDir, recordAllowedImports)
}

// assertNoForeignImports is the reporting half, taking the root and the scope as parameters and
// failing through a guard.Reporter so a rule test can drive it against a fixture tree. Without
// that seam these lines are reached only by the call above, which walks a tree that passes.
func assertNoForeignImports(r guard.Reporter, root, dir string, allowed map[string]string) {
	r.Helper()

	found, files, err := findForeignImports(root, dir, allowed)
	if err != nil {
		r.Fatalf("reading %s: %v", filepath.Join(root, filepath.FromSlash(dir)), err)
	}
	// A directory that somehow held no production Go files reads nothing and would otherwise
	// pass, which is the one way a guard like this fails silently in the direction that matters.
	if files == 0 {
		r.Fatalf("read no production Go files under %s", dir)
	}

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+f.path)
	}
	permitted := make([]string, 0, len(allowed))
	for path := range allowed {
		permitted = append(permitted, path)
	}
	sort.Strings(permitted)

	r.Errorf("%d import(s) under %s that a persistence record may not name:\n\t%s\n\n"+
		"This package is the rows as they are stored, and everything above it compiles against "+
		"whatever it imports. Allowed here: the standard library, plus %s. Everything else is a "+
		"capability, and a capability belongs in the package that owns it -- encrypting a TOTP "+
		"seed in otpcredential, decrypting and parsing a signing key in signingkeys, building an "+
		"OIDC claim in userclaims, all three of which were methods on a record until #387.",
		len(found), dir, strings.Join(lines, "\n\t"), strings.Join(permitted, ", "))
}

// TestRecord_ImportGuard_ReadsTheImportsAndNotTheSpelling is the synthetic half: a temp tree
// holding each shape the real tree contains, so a checker that has quietly stopped matching
// anything is caught here rather than trusted.
func TestRecord_ImportGuard_ReadsTheImportsAndNotTheSpelling(t *testing.T) {
	root := t.TempDir()

	// Accepted: the standard library, in both the grouped and the single-line form this package
	// writes, including a versionless multi-element path.
	writeImportFixture(t, root, recordDir+"/user.go", `package record

import (
	"database/sql"
	"strings"
)

type User struct{ Email sql.NullString }

func trim(s string) string { return strings.TrimSpace(s) }
`)
	writeImportFixture(t, root, recordDir+"/audit_log.go", `package record

import "time"

type AuditLog struct{ At time.Time }
`)
	// Accepted: the two allowed paths.
	writeImportFixture(t, root, recordDir+"/client.go", `package record

import (
	"database/sql"

	"github.com/leodip/goiabada/core/builtin"
)

var _ = builtin.PermissionManageAccount
var _ sql.NullTime
`)
	writeImportFixture(t, root, recordDir+"/acr_level.go", `package record

import "github.com/leodip/goiabada/core/errs"

var _ = errs.New
`)
	// Accepted: a test file naming anything it likes. The rule is about what the package
	// compiles into every consumer, and a _test.go compiles into nothing.
	writeImportFixture(t, root, recordDir+"/user_test.go", `package record

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/stretchr/testify/assert"
)

func TestSomething(t *testing.T) { assert.NotNil(t, encryption.NewDataCipher) }
`)
	// Accepted: the same import in another package. The scope is this directory.
	writeImportFixture(t, root, "authserver/internal/signingkeys/private_key.go", `package signingkeys

import "github.com/leodip/goiabada/authserver/internal/encryption"

var _ = encryption.DecryptText
`)
	// Accepted: a subdirectory, which the rule deliberately does not descend into.
	writeImportFixture(t, root, recordDir+"/sub/thing.go", `package sub

import "github.com/golang-jwt/jwt/v5"

var _ = jwt.ParseRSAPrivateKeyFromPEM
`)

	// Rejected: the two that provoked the rule, an aliased third-party import, and a path that
	// is neither -- an in-tree package that is not on the list.
	writeImportFixture(t, root, recordDir+"/key_pair.go", `package record

import (
	"crypto/rsa"
	"database/sql"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/encryption"
)

var _ sql.NullTime
var _ *rsa.PrivateKey
var _ = jwt.ParseRSAPrivateKeyFromPEM
var _ = encryption.DecryptText
`)
	writeImportFixture(t, root, recordDir+"/settings.go", `package record

import "github.com/leodip/goiabada/authserver/internal/data"

var _ data.Database
`)

	found, files, err := findForeignImports(root, recordDir, recordAllowedImports)
	require.NoError(t, err)
	require.NotZero(t, files)

	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, f.file+":"+strconv.Itoa(f.line)+": "+f.path)
	}
	assert.ElementsMatch(t, []string{
		recordDir + "/key_pair.go:7: github.com/golang-jwt/jwt/v5",
		recordDir + "/key_pair.go:8: github.com/leodip/goiabada/authserver/internal/encryption",
		recordDir + "/settings.go:3: github.com/leodip/goiabada/authserver/internal/data",
	}, got, "the checker matched the wrong set")
}

// TestRecord_ImportGuard_FailsOnACapability is the third half. The case above asserts on what
// findForeignImports returned; the lines that turn a finding into a failure are reached only by
// TestRecord_ImportsNothingButValuesAndTheStandardLibrary, which walks a tree that passes.
func TestRecord_ImportGuard_FailsOnACapability(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, recordDir+"/key_pair.go", `package record

import "github.com/leodip/goiabada/authserver/internal/encryption"

var _ = encryption.DecryptText
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoForeignImports(r, root, recordDir, recordAllowedImports)
	})

	require.True(t, report.Failed(), "a cipher imported by a persistence record passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), recordDir+"/key_pair.go:3")
	assert.Contains(t, report.Text(), "authserver/internal/encryption")
	assert.Contains(t, report.Text(), "#387")
	// The failure says what is allowed, so the reader can tell a genuine addition from a
	// capability that has to move instead.
	for path := range recordAllowedImports {
		assert.Contains(t, report.Text(), path)
	}
}

// TestRecord_ImportGuard_PassesTheAllowedSet is the other direction, over exactly what the package
// holds today.
func TestRecord_ImportGuard_PassesTheAllowedSet(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, recordDir+"/client.go", `package record

import (
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

var _ sql.NullTime
var _ = slices.Contains[[]string, string]
var _ = strings.TrimSpace
var _ = time.Now
var _ = builtin.PermissionManageAccount
var _ = errs.New
`)

	report := guard.Run(func(r guard.Reporter) {
		assertNoForeignImports(r, root, recordDir, recordAllowedImports)
	})

	assert.False(t, report.Failed(), "the allowed set failed the guard: %s", report.Text())
}

// TestRecord_ImportGuard_IsFatalOnAnEmptyRead pins the seam. This guard's scope is one directory,
// so the package moving takes the whole walk with it, and a guard that reported a clean pass on a
// directory it never read would be the quiet pass every rule here is written to avoid.
func TestRecord_ImportGuard_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, recordDir+"/notes.md", "the records moved out of here\n")
	writeImportFixture(t, root, recordDir+"/user_test.go", "package record\n")

	report := guard.Run(func(r guard.Reporter) {
		assertNoForeignImports(r, root, recordDir, recordAllowedImports)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under")
	assert.Contains(t, report.Fatal, recordDir)
}

// TestRecord_ImportGuard_IsFatalWhenTheDirectoryIsGone is the other way the scope disappears, and
// it is answered as a read error rather than as an empty directory. The two are worth telling
// apart: a package holding no production Go any more is a fact about the tree, and a directory
// that is not there at all is a scope constant nobody updated.
func TestRecord_ImportGuard_IsFatalWhenTheDirectoryIsGone(t *testing.T) {
	root := t.TempDir()
	writeImportFixture(t, root, "authserver/internal/elsewhere/user.go", "package elsewhere\n")

	report := guard.Run(func(r guard.Reporter) {
		assertNoForeignImports(r, root, recordDir, recordAllowedImports)
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading ")
	assert.NotContains(t, report.Fatal, "read no production Go files")
}

// writeImportFixture writes one file into a fixture tree, creating its directories.
func writeImportFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}
