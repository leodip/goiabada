package main

// run-tests.sh drops goiabada_data or goiabada_integration through this command, with the
// password the stack generated, and starts the data tier with the data key it generated. A
// container created before #627 carries neither, so the script refuses first, with one line naming
// the variable and the remedy (#501). These run it, with each variable unset in turn, against
// stubs first on PATH, so no database is dropped, no test runs, no listener is killed and no file
// under /tmp is removed.

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/sourceroot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stackVariables are the four values run-tests.sh takes from the stack's generated .env.
var stackVariables = []string{"GOIABADA_AES_ENCRYPTION_KEY", "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "MSSQL_SA_PASSWORD"}

// stubBin writes a directory of stubs: go and curl, which every tier's work goes through, each
// leaving a marker in markers when it runs, and the housekeeping the script does on its way in and
// on exit (netstat for the listeners it kills, rm for the SQLite files, mkdir for its log
// directory, sleep), which does nothing.
func stubBin(t *testing.T, markers string) string {
	t.Helper()
	bin := t.TempDir()
	stubs := map[string]string{
		"go":      "#!/bin/sh\ntouch \"" + markers + "/go\"\nexit 1\n",
		"curl":    "#!/bin/sh\ntouch \"" + markers + "/curl\"\nexit 1\n",
		"netstat": "#!/bin/sh\nexit 0\n",
		"rm":      "#!/bin/sh\nexit 0\n",
		"mkdir":   "#!/bin/sh\nexit 0\n",
		"sleep":   "#!/bin/sh\nexit 0\n",
	}
	for name, body := range stubs {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(body), 0o600))
		require.NoError(t, os.Chmod(filepath.Join(bin, name), 0o700))
	}
	return bin
}

// TestRunTests_AMissingStackVariableIsRefusedFirst: with one of the four unset, or set empty,
// run-tests.sh exits 1 naming it and pointing at the README's remedy, before droptestdb or a test
// is run.
func TestRunTests_AMissingStackVariableIsRefusedFirst(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	root, err := sourceroot.FindSourceRoot(cwd)
	require.NoError(t, err)

	for variable, db := range map[string]string{
		"GOIABADA_AES_ENCRYPTION_KEY": "sqlite",
		"MYSQL_ROOT_PASSWORD":         "mysql",
		"POSTGRES_PASSWORD":           "postgres",
		"MSSQL_SA_PASSWORD":           "mssql",
	} {
		for _, missing := range []string{"unset", "empty"} {
			t.Run(variable+"/"+missing, func(t *testing.T) {
				markers := t.TempDir()
				bin := stubBin(t, markers)
				env := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
				for _, kv := range os.Environ() {
					name, _, _ := strings.Cut(kv, "=")
					if name != "PATH" && name != "GITHUB_ACTIONS" && !slices.Contains(stackVariables, name) {
						env = append(env, kv)
					}
				}
				for _, other := range stackVariables {
					if other != variable {
						env = append(env, other+"=set-by-the-test")
					}
				}
				if missing == "empty" {
					env = append(env, variable+"=")
				}

				cmd := exec.Command("bash", filepath.Join(root, "authserver", "run-tests.sh"),
					"--type", "data", "--db", db, "--no-build")
				cmd.Dir = filepath.Join(root, "authserver")
				cmd.Env = env
				var stderr strings.Builder
				cmd.Stderr = &stderr
				err := cmd.Run()

				var exit *exec.ExitError
				require.ErrorAs(t, err, &exit, "run-tests.sh did not exit with a status")
				assert.Equal(t, 1, exit.ExitCode())
				assert.Contains(t, stderr.String(), "run-tests.sh: "+variable+" is not set")
				assert.Contains(t, stderr.String(), "src/.devcontainer/README.md")
				ran, err := os.ReadDir(markers)
				require.NoError(t, err)
				assert.Empty(t, ran, "a tier's command ran before the refusal")
			})
		}
	}
}
