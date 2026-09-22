package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/config"
)

// migrateArgsBase stands for what the server's parse left in the configuration: the environment,
// then the --db-* flags given before `migrate`.
func migrateArgsBase() config.DatabaseConfig {
	return config.DatabaseConfig{
		Type:     "sqlite",
		Username: "root",
		Password: "",
		Host:     "h0",
		Port:     3306,
		Name:     "goiabada",
		DSN:      "file::memory:?cache=shared",
		Create:   true,
	}
}

// with returns the base with edit applied, so each row states only what it changes.
func with(edit func(*config.DatabaseConfig)) config.DatabaseConfig {
	c := migrateArgsBase()
	edit(&c)
	return c
}

// TestParseMigrateArgs is D1's grammar after `migrate`: the --db-* flags anywhere, interleaved
// with the subcommand and its operand, overriding what came before, read the way the flag package
// reads a command line.
func TestParseMigrateArgs(t *testing.T) {
	cases := []struct {
		name           string
		base           config.DatabaseConfig
		args           []string
		wantPositional []string
		wantDatabase   config.DatabaseConfig
	}{
		{"no flags", migrateArgsBase(), []string{"to", "44"},
			[]string{"to", "44"}, migrateArgsBase()},
		{"a flag after the operand", migrateArgsBase(), []string{"to", "44", "-db-type=mysql"},
			[]string{"to", "44"}, with(func(c *config.DatabaseConfig) { c.Type = "mysql" })},
		{"a flag before the subcommand", migrateArgsBase(), []string{"-db-type=mysql", "to", "44"},
			[]string{"to", "44"}, with(func(c *config.DatabaseConfig) { c.Type = "mysql" })},
		{"a separate value, interleaved", migrateArgsBase(), []string{"to", "-db-type", "mysql", "44"},
			[]string{"to", "44"}, with(func(c *config.DatabaseConfig) { c.Type = "mysql" })},
		{"two dashes, either side", migrateArgsBase(), []string{"--db-host=h1", "version", "--db-port=1433"},
			[]string{"version"}, with(func(c *config.DatabaseConfig) { c.Host = "h1"; c.Port = 1433 })},
		{"after overrides before", with(func(c *config.DatabaseConfig) { c.Type = "postgres" }),
			[]string{"-db-type=mysql", "version"},
			[]string{"version"}, with(func(c *config.DatabaseConfig) { c.Type = "mysql" })},
		{"the last of two wins", migrateArgsBase(), []string{"-db-port=1", "-db-port=2", "version"},
			[]string{"version"}, with(func(c *config.DatabaseConfig) { c.Port = 2 })},
		{"a boolean set false", migrateArgsBase(), []string{"-db-create=false", "version"},
			[]string{"version"}, with(func(c *config.DatabaseConfig) { c.Create = false })},
		{"a bare boolean sets true", with(func(c *config.DatabaseConfig) { c.Create = false }),
			[]string{"-db-create", "version"},
			[]string{"version"}, migrateArgsBase()},
		// flag never lets a boolean take the next argument, so `false` is positional here.
		{"a boolean takes no separate value", with(func(c *config.DatabaseConfig) { c.Create = false }),
			[]string{"-db-create", "false"},
			[]string{"false"}, migrateArgsBase()},
		{"a double dash first", migrateArgsBase(), []string{"--", "version"},
			[]string{"version"}, migrateArgsBase()},
		{"a double dash ends the flags", migrateArgsBase(), []string{"-db-type=mysql", "--", "-db-host=x"},
			[]string{"-db-host=x"}, with(func(c *config.DatabaseConfig) { c.Type = "mysql" })},
		// A non-boolean flag takes the next argument whatever it is, as flag itself does.
		{"a separate value that is a double dash", migrateArgsBase(), []string{"-db-password", "--", "version"},
			[]string{"version"}, with(func(c *config.DatabaseConfig) { c.Password = "--" })},
		{"a lone dash is positional", migrateArgsBase(), []string{"-"},
			[]string{"-"}, migrateArgsBase()},
		{"every database flag", migrateArgsBase(),
			[]string{"-db-type=mssql", "-db-username=u", "-db-password=p@ss", "version", "-db-host=h2",
				"-db-port=11433", "-db-name=n", "-db-dsn=d", "-db-create=false"},
			[]string{"version"}, config.DatabaseConfig{Type: "mssql", Username: "u", Password: "p@ss",
				Host: "h2", Port: 11433, Name: "n", DSN: "d", Create: false}},
		{"no arguments", migrateArgsBase(), nil, nil, migrateArgsBase()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := parseMigrateArgs(tc.args, tc.base)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPositional, inv.positional)
			assert.Equal(t, tc.wantDatabase, inv.database)
			assert.False(t, inv.help)
		})
	}

	t.Run("the caller's configuration is untouched", func(t *testing.T) {
		base := migrateArgsBase()
		_, err := parseMigrateArgs([]string{"-db-type=mysql", "-db-port=1", "version"}, base)
		require.NoError(t, err)
		assert.Equal(t, migrateArgsBase(), base)
	})
}

// TestParseMigrateArgs_Refusals pins each message D1 asks for: what was wrong, and what to type.
func TestParseMigrateArgs_Refusals(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"a server flag after migrate", []string{"to", "44", "--authserver-log-level=debug"},
			"--authserver-log-level is not a flag migrate accepts: only the --db-* flags can follow migrate, so give any other flag before it"},
		{"an unknown flag", []string{"-bogus", "version"},
			"-bogus is not a flag migrate accepts: only the --db-* flags can follow migrate, so give any other flag before it"},
		{"an empty name", []string{"-=x"},
			"-=x is not a flag migrate accepts: only the --db-* flags can follow migrate, so give any other flag before it"},
		{"three dashes", []string{"---db-type=mysql", "version"},
			"---db-type is not a flag migrate accepts: only the --db-* flags can follow migrate, so give any other flag before it"},
		{"a malformed number", []string{"-db-port=abc", "version"},
			`invalid value "abc" for --db-port: parse error`},
		{"a malformed boolean", []string{"-db-create=maybe", "version"},
			`invalid value "maybe" for --db-create: parse error`},
		{"a value missing at the end", []string{"version", "-db-port"},
			"--db-port needs a value: give it as --db-port=<value>"},
		// flag reads -1 as a flag, so a negative version never reaches parseTargetVersion.
		{"a negative operand", []string{"to", "-1"},
			"-1 is not a flag migrate accepts: only the --db-* flags can follow migrate, so give any other flag before it"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := parseMigrateArgs(tc.args, migrateArgsBase())
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
			assert.Equal(t, migrateInvocation{}, inv)
		})
	}
}

func TestParseMigrateArgs_Help(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--h"}, {"--help"}, {"version", "--help"}} {
		inv, err := parseMigrateArgs(args, migrateArgsBase())
		require.NoError(t, err, "%#v", args)
		assert.True(t, inv.help, "%#v", args)
	}
}

// sqliteBase is a base configuration naming the SQLite file path.
func sqliteBase(path string) config.DatabaseConfig {
	return with(func(c *config.DatabaseConfig) { c.DSN = "file:" + path })
}

// TestMigrateCommand_AFlagAfterMigrateChoosesTheDatabaseOpened is R1 through the real open: the
// base names file A, the flag after `migrate` names file B, and B is the database the command
// reads. A is never created, which is how "not opened" is observed: SQLite creates the file on the
// first connection.
func TestMigrateCommand_AFlagAfterMigrateChoosesTheDatabaseOpened(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.db"), filepath.Join(dir, "b.db")

	var stdout, stderr bytes.Buffer
	code := migrateCommand([]string{"version", "--db-dsn=file:" + b}, sqliteBase(a), &stdout, &stderr)

	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr.String())
	assert.Contains(t, stdout.String(), "engine: sqlite")
	assert.Contains(t, stdout.String(), "never been migrated")
	assert.FileExists(t, b)
	assert.NoFileExists(t, a)
	assert.Empty(t, stderr.String())
}

func TestMigrateCommand_RefusesAServerFlagAfterMigrateBeforeOpeningAnything(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.db")

	var stdout, stderr bytes.Buffer
	code := migrateCommand([]string{"to", "44", "--authserver-log-level=debug"}, sqliteBase(a), &stdout, &stderr)

	require.Equal(t, migrateExitUsage, code)
	assert.Equal(t, "--authserver-log-level is not a flag migrate accepts: only the --db-* flags "+
		"can follow migrate, so give any other flag before it\n\n"+migrateUsage+"\n", stderr.String())
	assert.Empty(t, stdout.String())
	assert.NoFileExists(t, a)
}

func TestMigrateCommand_HelpPrintsTheUsageAndOpensNothing(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.db")

	var stdout, stderr bytes.Buffer
	code := migrateCommand([]string{"--help"}, sqliteBase(a), &stdout, &stderr)

	require.Equal(t, migrateExitOK, code)
	assert.Equal(t, migrateUsage+"\n", stdout.String())
	assert.Empty(t, stderr.String())
	assert.NoFileExists(t, a)
}
