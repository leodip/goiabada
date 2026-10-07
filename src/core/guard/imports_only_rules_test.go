package guard

// The rule table AssertImportsOnly enforces, over fixture trees written into a temp directory and
// walked through the same finder and reporting half the two real callers reach.
//
// The synthetic half exists because the real half cannot fail informatively: record and
// adminpassword import nothing they may not, so the calls over the real tree pass whether the rule
// still fires or has quietly stopped matching anything. The fixtures keep record's paths because
// those are the shapes the rule was written against (#387), and the guard itself names no package.

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureImportsOnlyDir, fixtureImportsOnlyAllowed and fixtureImportsOnlyWhy stand in for a
// caller's arguments.
const fixtureImportsOnlyDir = "authserver/internal/record"

var fixtureImportsOnlyAllowed = map[string]string{
	"github.com/leodip/goiabada/core/builtin": "the permission identifiers Client and Resource name",
	"github.com/leodip/goiabada/core/errs":    "the error constructor pattern 7 requires",
}

const fixtureImportsOnlyWhy = "This package is the rows as they are stored (#387)."

// renderDisallowedImports renders findings as "<file>:<line>: <path>" so a failure names what was
// missed or over-matched rather than printing a struct.
func renderDisallowedImports(found []disallowedImport) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.file+":"+strconv.Itoa(f.line)+": "+f.path)
	}
	return out
}

// TestImportsOnly_ReadsTheImportsAndNotTheSpelling holds each shape the real packages contain, so
// a finder that has quietly stopped matching anything is caught here rather than trusted.
func TestImportsOnly_ReadsTheImportsAndNotTheSpelling(t *testing.T) {
	root := t.TempDir()

	// Accepted: the standard library, in both the grouped and the single-line form, including a
	// versionless multi-element path.
	writeFixture(t, root, fixtureImportsOnlyDir+"/user.go", `package record

import (
	"database/sql"
	"strings"
)

type User struct{ Email sql.NullString }

func trim(s string) string { return strings.TrimSpace(s) }
`)
	writeFixture(t, root, fixtureImportsOnlyDir+"/audit_log.go", `package record

import "time"

type AuditLog struct{ At time.Time }
`)
	// Accepted: the allowed paths.
	writeFixture(t, root, fixtureImportsOnlyDir+"/client.go", `package record

import (
	"database/sql"

	"github.com/leodip/goiabada/core/builtin"
)

var _ = builtin.PermissionManageAccount
var _ sql.NullTime
`)
	writeFixture(t, root, fixtureImportsOnlyDir+"/acr_level.go", `package record

import "github.com/leodip/goiabada/core/errs"

var _ = errs.New
`)
	// Accepted: a test file naming anything it likes. The rule is about what the package
	// compiles into every consumer, and a _test.go compiles into nothing.
	writeFixture(t, root, fixtureImportsOnlyDir+"/user_test.go", `package record

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/stretchr/testify/assert"
)

func TestSomething(t *testing.T) { assert.NotNil(t, encryption.NewDataCipher) }
`)
	// Accepted: the same import in another package. The scope is the directory named.
	writeFixture(t, root, "authserver/internal/signingkeys/private_key.go", `package signingkeys

import "github.com/leodip/goiabada/authserver/internal/encryption"

var _ = encryption.DecryptText
`)
	// Accepted: a subdirectory, which the rule deliberately does not descend into.
	writeFixture(t, root, fixtureImportsOnlyDir+"/sub/thing.go", `package sub

import "github.com/golang-jwt/jwt/v5"

var _ = jwt.ParseRSAPrivateKeyFromPEM
`)

	// Rejected: the two that provoked the rule, an aliased third-party import, a blank import,
	// and an in-tree package that is not on the list.
	writeFixture(t, root, fixtureImportsOnlyDir+"/key_pair.go", `package record

import (
	"crypto/rsa"
	"database/sql"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	_ "modernc.org/sqlite"
)

var _ sql.NullTime
var _ *rsa.PrivateKey
var _ = jwt.ParseRSAPrivateKeyFromPEM
var _ = encryption.DecryptText
`)
	writeFixture(t, root, fixtureImportsOnlyDir+"/settings.go", `package record

import "github.com/leodip/goiabada/authserver/internal/data"

var _ data.Database
`)

	found, files, err := findDisallowedImports(root, fixtureImportsOnlyDir, fixtureImportsOnlyAllowed)
	require.NoError(t, err)
	assert.Equal(t, 6, files, "the finder read the wrong set of files")

	assert.ElementsMatch(t, []string{
		fixtureImportsOnlyDir + "/key_pair.go:7: github.com/golang-jwt/jwt/v5",
		fixtureImportsOnlyDir + "/key_pair.go:8: github.com/leodip/goiabada/authserver/internal/encryption",
		fixtureImportsOnlyDir + "/key_pair.go:9: modernc.org/sqlite",
		fixtureImportsOnlyDir + "/settings.go:3: github.com/leodip/goiabada/authserver/internal/data",
	}, renderDisallowedImports(found), "the finder matched the wrong set")
}

// TestImportsOnly_FailsOnACapability drives the reporting half: the case above asserts on what the
// finder returned, and the lines that turn a finding into a failure are reached only here.
func TestImportsOnly_FailsOnACapability(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, fixtureImportsOnlyDir+"/key_pair.go", `package record

import "github.com/leodip/goiabada/authserver/internal/encryption"

var _ = encryption.DecryptText
`)

	report := Run(func(r Reporter) {
		assertImportsOnly(r, root, fixtureImportsOnlyDir, fixtureImportsOnlyAllowed, fixtureImportsOnlyWhy)
	})

	require.True(t, report.Failed(), "a cipher imported by a persistence record passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), fixtureImportsOnlyDir+"/key_pair.go:3")
	assert.Contains(t, report.Text(), "authserver/internal/encryption")
	// The caller's account of the package reaches the reader, so the failure says why the rule
	// exists and not only that it fired.
	assert.Contains(t, report.Text(), fixtureImportsOnlyWhy)
	// The failure says what is allowed, so the reader can tell a genuine addition from a
	// capability that has to move instead.
	assert.Contains(t, report.Text(), "the standard library, plus ")
	for path := range fixtureImportsOnlyAllowed {
		assert.Contains(t, report.Text(), path)
	}
}

// TestImportsOnly_NamesTheStandardLibraryAloneForAnEmptyList pins the message for a caller that
// allows nothing beyond the standard library, which would otherwise end "plus ." and read as a
// truncated list.
func TestImportsOnly_NamesTheStandardLibraryAloneForAnEmptyList(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "core/leaf/leaf.go", `package leaf

import "github.com/leodip/goiabada/core/errs"

var _ = errs.New
`)

	report := Run(func(r Reporter) {
		assertImportsOnly(r, root, "core/leaf", nil, "A leaf.")
	})

	require.True(t, report.Failed(), "an import outside an empty allowlist passed the guard")
	assert.Contains(t, report.Text(), "core/leaf/leaf.go:3: github.com/leodip/goiabada/core/errs")
	assert.Contains(t, report.Text(), "Allowed here: the standard library alone.")
}

// TestImportsOnly_PassesTheAllowedSet is the other direction, over exactly what record holds
// today.
func TestImportsOnly_PassesTheAllowedSet(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, fixtureImportsOnlyDir+"/client.go", `package record

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

	report := Run(func(r Reporter) {
		assertImportsOnly(r, root, fixtureImportsOnlyDir, fixtureImportsOnlyAllowed, fixtureImportsOnlyWhy)
	})

	assert.False(t, report.Failed(), "the allowed set failed the guard: %s", report.Text())
}

// TestImportsOnly_IsFatalOnAnEmptyRead pins the walk that reached nothing. The scope is one
// directory, so the package moving takes the whole walk with it, and a guard that reported a clean
// pass on a directory it never read would be the quiet pass every rule here is written to avoid.
func TestImportsOnly_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, fixtureImportsOnlyDir+"/notes.md", "the records moved out of here\n")
	writeFixture(t, root, fixtureImportsOnlyDir+"/user_test.go", "package record\n")

	report := Run(func(r Reporter) {
		assertImportsOnly(r, root, fixtureImportsOnlyDir, fixtureImportsOnlyAllowed, fixtureImportsOnlyWhy)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under")
	assert.Contains(t, report.Fatal, fixtureImportsOnlyDir)
}

// TestImportsOnly_IsFatalWhenTheDirectoryIsGone is the other way the scope disappears, and it is
// answered as a read error rather than as an empty directory. The two are worth telling apart: a
// package holding no production Go any more is a fact about the tree, and a directory that is not
// there at all is a caller's argument nobody updated.
func TestImportsOnly_IsFatalWhenTheDirectoryIsGone(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "authserver/internal/elsewhere/user.go", "package elsewhere\n")

	report := Run(func(r Reporter) {
		assertImportsOnly(r, root, fixtureImportsOnlyDir, fixtureImportsOnlyAllowed, fixtureImportsOnlyWhy)
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading ")
	assert.NotContains(t, report.Fatal, "read no production Go files")
}
