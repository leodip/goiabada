package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain_RefusesTheConnectionsTLSSettingsBeforeOpeningAnything: a malformed mode and a CA file
// the start cannot use stop main at the load with one line on stderr and exit 2, the channel and
// code of every malformed setting, under the server and under `migrate` alike, and a flag given
// after `migrate` is held to the same rules (#502).
//
// The engine is PostgreSQL on a port nothing listens on, so a child that got past the load exits
// 1 at the connection instead: the code and the exact line are what fail.
func TestMain_RefusesTheConnectionsTLSSettingsBeforeOpeningAnything(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	postgres := []string{
		"GOIABADA_DB_TYPE=postgres",
		"GOIABADA_DB_HOST=127.0.0.1",
		"GOIABADA_DB_PORT=1",
		"GOIABADA_DB_CREATE=false",
		// Present, so a child that got past the load would go on to dial the database.
		"GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
	}

	cases := []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{
			name: "a malformed mode, at the server",
			env:  []string{"GOIABADA_DB_TLS_MODE=verify"},
			want: `malformed configuration: GOIABADA_DB_TLS_MODE is "verify", not one of disable, prefer, require, verify-ca, verify-full` + "\n",
		},
		{
			name: "a CA file that is not there, under migrate version",
			env:  []string{"GOIABADA_DB_TLS_MODE=verify-full", "GOIABADA_DB_TLS_CA_FILE=" + missing},
			args: []string{"migrate", "version"},
			want: `malformed configuration: GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) is "` + missing +
				`", which cannot be read: no such file or directory` + "\n",
		},
		{
			name: "a CA file beside a mode that checks nothing, at the server",
			env:  []string{"GOIABADA_DB_TLS_MODE=require", "GOIABADA_DB_TLS_CA_FILE=" + missing},
			want: `malformed configuration: GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) is "` + missing +
				`" while GOIABADA_DB_TLS_MODE (--db-tls-mode) is require, which checks no certificate: only verify-ca and verify-full read a CA file` + "\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoy := filepath.Join(t.TempDir(), "d.db")

			code, stderr := runMainProcessWith(t, decoy, append(append([]string{}, postgres...), tc.env...), tc.args...)

			require.Equal(t, migrateExitUsage, code, "stderr: %s", stderr)
			assert.Equal(t, tc.want, stderr)
		})
	}

	t.Run("a malformed mode given after migrate", func(t *testing.T) {
		decoy := filepath.Join(t.TempDir(), "d.db")

		code, stderr := runMainProcessWith(t, decoy, postgres, "migrate", "--db-tls-mode=strict", "version")

		require.Equal(t, migrateExitUsage, code, "stderr: %s", stderr)
		// migrate prints its usage after the refusal, as for every flag it refuses.
		assert.Contains(t, stderr,
			"\n"+`malformed configuration: --db-tls-mode is "strict", not one of disable, prefer, require, verify-ca, verify-full`+"\n")
	})
}
