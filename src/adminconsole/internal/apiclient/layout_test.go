package apiclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPackageFiles_OneFilePerResource holds the package to its layout: apiclient.go declares the
// client and its error, executor.go the one request path every method takes, and every other file
// is named for the resource its methods call. The files carried a _client.go suffix until #441,
// which every one of them shared and so said nothing, and which gave the client resource
// client_client.go. A new file is a new resource, so it is added here.
func TestPackageFiles_OneFilePerResource(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}

	assert.ElementsMatch(t, []string{
		"account.go",
		"apiclient.go",
		"audit_logs.go",
		"client_permissions.go",
		"clients.go",
		"executor.go",
		"group_attributes.go",
		"group_permissions.go",
		"groups.go",
		"permissions.go",
		"phone_countries.go",
		"resources.go",
		"sessions.go",
		"settings_email.go",
		"settings_general.go",
		"settings_keys.go",
		"settings_sessions.go",
		"settings_tokens.go",
		"settings_ui_theme.go",
		"user_attributes.go",
		"user_consents.go",
		"users.go",
	}, files)
}

// TestPackageFiles_MethodsSitWithTheirResource pins the four methods #441 found in another
// resource's file: a user's phone update beside the phone countries, a user's consents among the
// sessions, and the resource list among the permissions.
func TestPackageFiles_MethodsSitWithTheirResource(t *testing.T) {
	declaredIn := methodFiles(t)

	assert.Equal(t, "users.go", declaredIn["UpdateUserPhone"])
	assert.Equal(t, "user_consents.go", declaredIn["GetUserConsents"])
	assert.Equal(t, "user_consents.go", declaredIn["DeleteUserConsent"])
	assert.Equal(t, "resources.go", declaredIn["GetAllResources"])
}

// TestPackageFiles_TestsFollowTheirMethod holds every test named for a method of AuthServerClient
// to the test file of the file declaring that method, so a method that moves takes its tests with
// it. A test is named for a method when its name, past Test and an optional AuthServerClient_,
// starts with the method's name followed by a capital, an underscore or nothing; one naming two
// methods, or none, is not held. The characterization table and this file are the package's own and
// follow no resource.
func TestPackageFiles_TestsFollowTheirMethod(t *testing.T) {
	declaredIn := methodFiles(t)
	testsIn := testFiles(t)

	held := 0
	for testName, testFile := range testsIn {
		method := methodNamedBy(testName, declaredIn)
		if method == "" {
			continue
		}
		held++
		want := strings.TrimSuffix(declaredIn[method], ".go") + "_test.go"
		assert.Equal(t, want, testFile, "%s tests %s, which %s declares", testName, method, declaredIn[method])
	}
	require.Greater(t, held, 20, "the walk matched almost no test to a method, so it checked nothing")

	for _, file := range uniqueValues(testsIn) {
		switch file {
		case "layout_test.go", "wire_characterization_test.go", "wire_characterization_table_test.go":
			continue
		}
		_, err := os.Stat(strings.TrimSuffix(file, "_test.go") + ".go")
		assert.NoError(t, err, "%s follows no file of the package", file)
	}
}

// methodFiles maps each method of AuthServerClient to the file declaring it.
func methodFiles(t *testing.T) map[string]string {
	t.Helper()

	files := map[string]string{}
	for name, file := range parsePackage(t, false) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if ident, ok := star.X.(*ast.Ident); ok && ident.Name == "AuthServerClient" && fn.Name.IsExported() {
				files[fn.Name.Name] = name
			}
		}
	}
	require.Greater(t, len(files), 100, "the walk found almost no method of AuthServerClient")
	return files
}

// testFiles maps each Test function of the package to the file declaring it.
func testFiles(t *testing.T) map[string]string {
	t.Helper()

	files := map[string]string{}
	for name, file := range parsePackage(t, true) {
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				files[fn.Name.Name] = name
			}
		}
	}
	return files
}

func parsePackage(t *testing.T, tests bool) map[string]*ast.File {
	t.Helper()

	paths, err := filepath.Glob("*.go")
	require.NoError(t, err)

	files := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, path := range paths {
		if !tests && strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		files[path] = file
	}
	return files
}

// methodNamedBy answers the longest method name the test's name starts with, or "" for none.
func methodNamedBy(testName string, methods map[string]string) string {
	rest := strings.TrimPrefix(testName, "Test")
	rest = strings.TrimPrefix(rest, "AuthServerClient_")

	best := ""
	for method := range methods {
		if !strings.HasPrefix(rest, method) || len(method) <= len(best) {
			continue
		}
		after := rest[len(method):]
		if after == "" || after[0] == '_' || unicode.IsUpper(rune(after[0])) {
			best = method
		}
	}
	return best
}

func uniqueValues(m map[string]string) []string {
	seen := map[string]bool{}
	var values []string
	for _, v := range m {
		if !seen[v] {
			seen[v] = true
			values = append(values, v)
		}
	}
	return values
}
