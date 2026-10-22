package main

// src/.devcontainer/generate-env.sh writes the .env the dev stack's data key and database
// passwords come from, the ones schemadump reads (#501). These run it, with sh as the dev
// container's initializeCommand does, on copies of it in directories of their own, so the
// checkout's own .env is never touched.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/sourceroot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generatedValue is the form each variable is drawn in: the key 32 bytes of hex, the passwords 24,
// SQL Server's prefixed to meet its complexity policy.
var generatedValue = map[string]*regexp.Regexp{
	"GOIABADA_AES_ENCRYPTION_KEY": regexp.MustCompile(`^[0-9a-f]{64}$`),
	"MYSQL_ROOT_PASSWORD":         regexp.MustCompile(`^[0-9a-f]{48}$`),
	"POSTGRES_PASSWORD":           regexp.MustCompile(`^[0-9a-f]{48}$`),
	"MSSQL_SA_PASSWORD":           regexp.MustCompile(`^Aa1-[0-9a-f]{48}$`),
}

// generateEnvIn copies generate-env.sh into a new directory, writes existing there as .env when it
// is not nil, and returns the directory.
func generateEnvIn(t *testing.T, existing []byte) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	root, err := sourceroot.FindSourceRoot(cwd)
	require.NoError(t, err)
	script, err := os.ReadFile(filepath.Join(root, ".devcontainer", "generate-env.sh"))
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "generate-env.sh"), script, 0o600))
	if existing != nil {
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), existing, 0o600))
		require.NoError(t, os.Chmod(filepath.Join(dir, ".env"), 0o644))
	}
	return dir
}

// runGenerateEnv runs the copy in dir and returns the .env it leaves.
func runGenerateEnv(t *testing.T, dir string) []byte {
	t.Helper()
	out, err := exec.Command("sh", filepath.Join(dir, "generate-env.sh")).CombinedOutput()
	require.NoError(t, err, "generate-env.sh failed:\n%s", out)
	content, err := os.ReadFile(filepath.Join(dir, ".env"))
	require.NoError(t, err)
	return content
}

// envValues is the variables content assigns, in the order it assigns them.
func envValues(content []byte) ([]string, map[string]string) {
	var names []string
	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, name)
		values[name] = value
	}
	return names, values
}

func assertEnvMode(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, ".env"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the .env holds secrets, so only its owner reads it")
}

// TestGenerateEnv_AFreshDirectoryGetsAllFour: with no .env, the script writes the key and the three
// passwords, each in its form, readable by its owner alone.
func TestGenerateEnv_AFreshDirectoryGetsAllFour(t *testing.T) {
	dir := generateEnvIn(t, nil)

	names, values := envValues(runGenerateEnv(t, dir))

	assert.Equal(t, []string{"GOIABADA_AES_ENCRYPTION_KEY", "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "MSSQL_SA_PASSWORD"}, names)
	for name, form := range generatedValue {
		assert.Regexp(t, form, values[name], name)
	}
	assertEnvMode(t, dir)
}

// TestGenerateEnv_EachCheckoutDrawsItsOwn: two checkouts share no value, so none is a literal in
// disguise.
func TestGenerateEnv_EachCheckoutDrawsItsOwn(t *testing.T) {
	_, first := envValues(runGenerateEnv(t, generateEnvIn(t, nil)))
	_, second := envValues(runGenerateEnv(t, generateEnvIn(t, nil)))

	for name := range generatedValue {
		assert.NotEqual(t, first[name], second[name], name)
	}
}

// TestGenerateEnv_ASecondRunChangesNothing: a complete .env is left byte for byte as it was, since
// each database keeps the password its volume was initialised with.
func TestGenerateEnv_ASecondRunChangesNothing(t *testing.T) {
	dir := generateEnvIn(t, nil)
	first := runGenerateEnv(t, dir)

	second := runGenerateEnv(t, dir)

	assert.Equal(t, string(first), string(second))
}

// TestGenerateEnv_APartialEnvGainsOnlyWhatItLacks: a .env holding Compose's other variables, one of
// the four and another empty keeps every line it had but the empty one, gains a value for each of
// the other three, and is left at 0600 whatever its mode was.
func TestGenerateEnv_APartialEnvGainsOnlyWhatItLacks(t *testing.T) {
	dir := generateEnvIn(t, []byte("USER_UID=1000\nMYSQL_ROOT_PASSWORD=kept-from-before\nPOSTGRES_PASSWORD=\nUSER_GID=1000\n"))

	content := runGenerateEnv(t, dir)

	names, values := envValues(content)
	assert.True(t, strings.HasPrefix(string(content), "USER_UID=1000\nMYSQL_ROOT_PASSWORD=kept-from-before\nUSER_GID=1000\n"),
		"the lines already there are kept, in order:\n%s", content)
	assert.Equal(t, []string{"USER_UID", "MYSQL_ROOT_PASSWORD", "USER_GID",
		"GOIABADA_AES_ENCRYPTION_KEY", "POSTGRES_PASSWORD", "MSSQL_SA_PASSWORD"}, names)
	assert.Equal(t, "kept-from-before", values["MYSQL_ROOT_PASSWORD"])
	for _, name := range []string{"GOIABADA_AES_ENCRYPTION_KEY", "POSTGRES_PASSWORD", "MSSQL_SA_PASSWORD"} {
		assert.Regexp(t, generatedValue[name], values[name], name)
	}
	assertEnvMode(t, dir)
}
