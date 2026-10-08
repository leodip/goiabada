package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// usageCommand is a subcommand as the usage spells it, with its operand when it takes one.
var usageCommand = regexp.MustCompile(`(?m)^  goiabada-authserver migrate (?:\S+ <\S+>|\S+)`)

// TestUpgradePage_TheRollbackIsWhatMigrateDoes: the page an operator rolls back from names the two
// migrate subcommands as the usage spells them, and the floor below which `migrate to` refuses, so
// a reader planning a rollback learns before starting that it cannot go further back (#522
// decision 15).
func TestUpgradePage_TheRollbackIsWhatMigrateDoes(t *testing.T) {
	const page = "site/src/content/docs/deploy/upgrade-goiabada.mdx"
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), page))
	require.NoError(t, err)
	_, section, found := strings.Cut(string(body), "\n## Roll back to an earlier release\n")
	require.Truef(t, found, "%s has no section headed ## Roll back to an earlier release", page)
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}

	commands := usageCommand.FindAllString(migrateUsage, -1)
	require.Len(t, commands, 2, "the usage spells out the two subcommands")
	for _, command := range commands {
		command = strings.TrimSpace(command)
		assert.Containsf(t, section, "`"+command+"`", "%s: the rollback section names %q as the usage spells it", page, command)
	}

	assert.Containsf(t, section, fmt.Sprintf("`%06d`", rollbackFloor), "%s: the rollback section names the floor `migrate to` refuses below", page)
}

// TestUpgradePage_TheNativeRollbackRunsAsTheService: the rollback command the Native binaries tab
// shows runs as the user, from the working directory and with the environment file of the unit
// Native binaries installs, so a SQLite database named by a relative path, which the setup wizard
// writes, is the one the service uses, and a file that cannot be read runs nothing. The command is
// run against a stub standing in for the binary (#522 decision 15).
func TestUpgradePage_TheNativeRollbackRunsAsTheService(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	native, err := os.ReadFile(filepath.Join(root, "site/src/content/docs/deploy/native-binaries.mdx"))
	require.NoError(t, err)
	unit := map[string]string{}
	for _, key := range []string{"User", "WorkingDirectory", "EnvironmentFile", "ExecStart"} {
		match := regexp.MustCompile(`(?m)^\s*` + key + `=(\S+)$`).FindStringSubmatch(string(native))
		require.NotNilf(t, match, "native-binaries.mdx: the auth server's unit sets %s", key)
		unit[key] = match[1]
	}

	upgrade, err := os.ReadFile(filepath.Join(root, "site/src/content/docs/deploy/upgrade-goiabada.mdx"))
	require.NoError(t, err)
	_, section, found := strings.Cut(string(upgrade), "\n## Roll back to an earlier release\n")
	require.True(t, found, "upgrade-goiabada.mdx has no section headed ## Roll back to an earlier release")
	_, tab, found := strings.Cut(section, `<TabItem label="Native binaries">`)
	require.True(t, found, "upgrade-goiabada.mdx: the rollback has a Native binaries tab")
	tab, _, _ = strings.Cut(tab, "</TabItem>")
	command := regexp.MustCompile("(?s)```bash\\s*\\n\\s*(.*?)\\n\\s*```").FindStringSubmatch(tab)
	require.NotNil(t, command, "upgrade-goiabada.mdx: the Native binaries tab holds a bash block")
	prefix := "sudo -u " + unit["User"] + " sh -c '"
	require.Truef(t, strings.HasPrefix(command[1], prefix) && strings.HasSuffix(command[1], "'"),
		"upgrade-goiabada.mdx: the native rollback is one command, %s...', so it runs as the unit's user; it reads %q", prefix, command[1])
	script := strings.TrimSuffix(strings.TrimPrefix(command[1], prefix), "'")
	require.Contains(t, script, "migrate to <version>")

	// run runs the documented command over temporary paths and returns what the stub recorded,
	// empty when it did not run, and the command's output and error.
	run := func(t *testing.T, writeEnvironment bool) (string, string, error) {
		directory := t.TempDir()
		workingDirectory := filepath.Join(directory, "var")
		require.NoError(t, os.Mkdir(workingDirectory, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(workingDirectory, "goiabada.db"), nil, 0o600))
		environmentFile := filepath.Join(directory, "goiabada.env")
		if writeEnvironment {
			require.NoError(t, os.WriteFile(environmentFile, []byte("GOIABADA_DB_TYPE=sqlite\nGOIABADA_DB_DSN=\"./goiabada.db\"\n"), 0o600))
		}
		// The stub records what it was run with: the working directory, the DSN, whether the
		// DSN names a file there, and its arguments.
		binary := filepath.Join(directory, "goiabada-authserver")
		record := filepath.Join(directory, "record")
		stub := "#!/bin/sh\n" +
			`seen=no; [ -f "$GOIABADA_DB_DSN" ] && seen=yes` + "\n" +
			`echo "$(pwd) $GOIABADA_DB_DSN $seen $*" > ` + record + "\n"
		require.NoError(t, os.WriteFile(binary, []byte(stub), 0o700))

		replaced := strings.NewReplacer(
			unit["EnvironmentFile"], environmentFile,
			unit["WorkingDirectory"], workingDirectory,
			unit["ExecStart"], binary,
			"<version>", "000044",
		).Replace(script)
		cmd := exec.Command("sh", "-c", replaced)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		output, err := cmd.CombinedOutput()
		recorded, readErr := os.ReadFile(record)
		if readErr != nil && !os.IsNotExist(readErr) {
			require.NoError(t, readErr)
		}
		return strings.TrimSpace(strings.ReplaceAll(string(recorded), workingDirectory, "<working directory>")), string(output), err
	}

	t.Run("with the environment file, the migration runs in the service's directory and database", func(t *testing.T) {
		recorded, output, err := run(t, true)
		require.NoError(t, err, output)
		assert.Equal(t, "<working directory> ./goiabada.db yes migrate to 000044", recorded)
	})

	t.Run("without the environment file, nothing runs", func(t *testing.T) {
		recorded, output, err := run(t, false)
		require.Error(t, err, output)
		assert.Empty(t, recorded)
	})
}
