package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDispatch is #424's R1 at the function that chooses the command: it reads what the flag
// parse left, so a flag before `migrate` no longer hides it, and an argument that names no command
// is refused instead of starting the server. `recover` is handed on the same way (#498).
func TestDispatch(t *testing.T) {
	t.Run("serves", func(t *testing.T) {
		for _, args := range [][]string{nil, {}} {
			rest, command, err := dispatch(args)
			require.NoError(t, err)
			assert.Empty(t, command, "%#v", args)
			assert.Nil(t, rest)
		}
	})

	accepted := []struct {
		name    string
		args    []string
		command string
		want    []string
	}{
		{"migrate alone", []string{"migrate"}, "migrate", []string{}},
		{"migrate to", []string{"migrate", "to", "44"}, "migrate", []string{"to", "44"}},
		// The tail is handed on untouched: the flag after `to 44` is migrate's own parse to read.
		{"a flag in the migrate tail", []string{"migrate", "to", "44", "-db-type=mysql"}, "migrate", []string{"to", "44", "-db-type=mysql"}},
		{"recover", []string{"recover", "--email", "a@example.com", "--remove-otp"}, "recover", []string{"--email", "a@example.com", "--remove-otp"}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			rest, command, err := dispatch(tc.args)
			require.NoError(t, err)
			assert.Equal(t, tc.command, command)
			assert.Equal(t, tc.want, rest)
		})
	}

	// -x reaches dispatch only as `goiabada-authserver -- -x`, the one way past the server's parse.
	for _, first := range []string{"migrat", "serve", "version", "-x", "recovr"} {
		t.Run("refuses "+first, func(t *testing.T) {
			rest, command, err := dispatch([]string{first, "to", "44"})
			require.Error(t, err)
			assert.Empty(t, command)
			assert.Nil(t, rest)

			msg := err.Error()
			assert.Contains(t, msg, `"`+first+`"`, "the refusal names the argument")
			assert.Contains(t, msg, "goiabada-authserver [flags] with no command to start the server")
			assert.Contains(t, msg, "goiabada-authserver [flags] migrate to <version>")
			assert.Contains(t, msg, "goiabada-authserver [flags] recover --email <address>")
			assert.Contains(t, msg, "goiabada-authserver healthcheck, alone,")
		})
	}

	// `healthcheck` is recognized only as the first argument, before the parse, so dispatch meets
	// it only behind a flag or `--`: it takes none, and is refused as such (#808 decision 3).
	t.Run("refuses healthcheck behind a flag", func(t *testing.T) {
		rest, command, err := dispatch([]string{"healthcheck"})
		require.Error(t, err)
		assert.Empty(t, command)
		assert.Nil(t, rest)
		assert.Equal(t, "healthcheck takes no arguments: it reads the listener from the environment, "+
			"so run goiabada-authserver healthcheck alone", err.Error())
	})

	t.Run("the refusal in full", func(t *testing.T) {
		_, _, err := dispatch([]string{"migrat", "to", "44"})
		require.Error(t, err)
		assert.Equal(t, `unknown command "migrat": run goiabada-authserver [flags] with no command `+
			`to start the server, goiabada-authserver [flags] migrate version, or `+
			`goiabada-authserver [flags] migrate to <version>, to manage the schema, `+
			`goiabada-authserver [flags] recover --email <address> [flags], to restore sign-in for `+
			`one user, or goiabada-authserver healthcheck, alone, to check the running server's `+
			`health; the server's flags go before the command`, err.Error())
	})
}
