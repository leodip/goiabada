package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDispatch is #424's R1 at the function that chooses the command: it reads what the flag
// parse left, so a flag before `migrate` no longer hides it, and an argument that names no command
// is refused instead of starting the server.
func TestDispatch(t *testing.T) {
	t.Run("serves", func(t *testing.T) {
		for _, args := range [][]string{nil, {}} {
			migrateArgs, isMigrate, err := dispatch(args)
			require.NoError(t, err)
			assert.False(t, isMigrate, "%#v", args)
			assert.Nil(t, migrateArgs)
		}
	})

	accepted := []struct {
		name string
		args []string
		want []string
	}{
		{"migrate alone", []string{"migrate"}, []string{}},
		{"migrate to", []string{"migrate", "to", "44"}, []string{"to", "44"}},
		// The tail is handed on untouched: the flag after `to 44` is migrate's own parse to read.
		{"a flag in the tail", []string{"migrate", "to", "44", "-db-type=mysql"}, []string{"to", "44", "-db-type=mysql"}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			migrateArgs, isMigrate, err := dispatch(tc.args)
			require.NoError(t, err)
			assert.True(t, isMigrate)
			assert.Equal(t, tc.want, migrateArgs)
		})
	}

	// -x reaches dispatch only as `goiabada-authserver -- -x`, the one way past the server's parse.
	for _, first := range []string{"migrat", "serve", "version", "-x"} {
		t.Run("refuses "+first, func(t *testing.T) {
			migrateArgs, isMigrate, err := dispatch([]string{first, "to", "44"})
			require.Error(t, err)
			assert.False(t, isMigrate)
			assert.Nil(t, migrateArgs)

			msg := err.Error()
			assert.Contains(t, msg, `"`+first+`"`, "the refusal names the argument")
			assert.Contains(t, msg, "goiabada-authserver [flags] with no command to start the server")
			assert.Contains(t, msg, "goiabada-authserver [flags] migrate to <version>")
		})
	}

	t.Run("the refusal in full", func(t *testing.T) {
		_, _, err := dispatch([]string{"migrat", "to", "44"})
		require.Error(t, err)
		assert.Equal(t, `unknown command "migrat": run goiabada-authserver [flags] with no command `+
			`to start the server, or goiabada-authserver [flags] migrate version, or `+
			`goiabada-authserver [flags] migrate to <version>, to manage the schema; the server's `+
			`flags go before the command`, err.Error())
	})
}
