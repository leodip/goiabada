package main

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// targetFor is the target of one engine.
func targetFor(t *testing.T, dialect data.Dialect) target {
	t.Helper()
	for _, tg := range targets() {
		if tg.dialect == dialect {
			return tg
		}
	}
	t.Fatalf("no target for %s", dialect)
	return target{}
}

// TestTargets_ThePasswordIsTheStacksGeneratedOne: each server engine's password is read from the
// variable the dev container carries its stack's generated password in, and none is written down
// here (#501).
func TestTargets_ThePasswordIsTheStacksGeneratedOne(t *testing.T) {
	for dialect, variable := range map[data.Dialect]string{
		data.MySQL:    "MYSQL_ROOT_PASSWORD",
		data.Postgres: "POSTGRES_PASSWORD",
		data.MSSQL:    "MSSQL_SA_PASSWORD",
	} {
		t.Run(string(dialect), func(t *testing.T) {
			t.Setenv(variable, "generated-"+string(dialect))

			resolved, err := targetFor(t, dialect).withOverrides()

			require.NoError(t, err)
			assert.Equal(t, "generated-"+string(dialect), resolved.password)
		})
	}
}

// TestTargets_AnUnsetPasswordIsRefused: an engine whose variable is unset or empty stops the command
// with one line naming the variable and the remedy, rather than connecting with no password.
func TestTargets_AnUnsetPasswordIsRefused(t *testing.T) {
	t.Setenv("MYSQL_ROOT_PASSWORD", "")

	_, err := targetFor(t, data.MySQL).withOverrides()

	require.EqualError(t, err, "MYSQL_ROOT_PASSWORD is not set, so the mysql password is unknown: run schemadump inside "+
		"the dev container, whose environment carries the passwords its stack generated, or set GOIABADA_SCHEMADUMP_MYSQL_PASSWORD")
}

// TestTargets_ThePasswordOverrideWins: GOIABADA_SCHEMADUMP_<ENGINE>_PASSWORD still replaces the
// password, and with it set the stack's variable may be absent.
func TestTargets_ThePasswordOverrideWins(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "")
	t.Setenv("GOIABADA_SCHEMADUMP_POSTGRES_PASSWORD", "elsewhere")

	resolved, err := targetFor(t, data.Postgres).withOverrides()

	require.NoError(t, err)
	assert.Equal(t, "elsewhere", resolved.password)
}

// TestTargets_SQLiteNeedsNoPassword: the file engine reads no variable and is never refused.
func TestTargets_SQLiteNeedsNoPassword(t *testing.T) {
	resolved, err := targetFor(t, data.SQLite).withOverrides()

	require.NoError(t, err)
	assert.Empty(t, resolved.password)
}
