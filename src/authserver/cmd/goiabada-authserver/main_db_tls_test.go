package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain_RefusesTheConnectionsTLSSettingsBeforeOpeningAnything: a malformed mode and a CA file
// the start cannot use stop main before anything is opened, with one line on stderr and exit 2, the
// channel and code of every malformed setting, under the server and under `migrate` alike, and a
// flag given after `migrate` is held to the same rules (#502). Under `migrate` the CA file and
// libpq's variables are checked against the flags given after it, and still before the start's
// first record, with no usage beside them, since the invocation was typed correctly.
//
// The engine is PostgreSQL on a port nothing listens on, so a child that got past the load exits
// 1 at the connection instead: the code and the exact line are what fail.
func TestMain_RefusesTheConnectionsTLSSettingsBeforeOpeningAnything(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	clientCert, clientKey := writeTestClientPair(t)
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
		{
			name: "one of libpq's TLS variables on postgres, under migrate up",
			env:  []string{"PGSSLMODE=verify-full"},
			args: []string{"migrate", "up"},
			want: "malformed configuration: PGSSLMODE is set, which the auth server no longer reads: " +
				"unset it and set GOIABADA_DB_TLS_MODE (--db-tls-mode) instead\n",
		},
		{
			name: "one of libpq's TLS variables on postgres, at the server",
			env:  []string{"PGSSLROOTCERT=" + missing},
			want: "malformed configuration: PGSSLROOTCERT is set, which the auth server no longer reads: " +
				"unset it and set GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) instead\n",
		},
		{
			name: "a client certificate without its key, at the server",
			env:  []string{"GOIABADA_DB_TLS_MODE=verify-full", "GOIABADA_DB_TLS_CLIENT_CERT_FILE=" + clientCert},
			want: `malformed configuration: GOIABADA_DB_TLS_CLIENT_CERT_FILE (--db-tls-client-cert-file) is "` + clientCert +
				`" without GOIABADA_DB_TLS_CLIENT_KEY_FILE (--db-tls-client-key-file): name both or neither` + "\n",
		},
		{
			name: "a client certificate beside a mode that may send no TLS",
			env:  []string{"GOIABADA_DB_TLS_CLIENT_CERT_FILE=" + clientCert, "GOIABADA_DB_TLS_CLIENT_KEY_FILE=" + clientKey},
			want: `malformed configuration: GOIABADA_DB_TLS_CLIENT_CERT_FILE (--db-tls-client-cert-file) is "` + clientCert +
				`" while GOIABADA_DB_TLS_MODE (--db-tls-mode) is unset, so prefer, which may send no TLS: only require, verify-ca and verify-full carry a client certificate` + "\n",
		},
		{
			name: "a host name beside a mode that checks none, at the server",
			env:  []string{"GOIABADA_DB_TLS_MODE=require", "GOIABADA_DB_TLS_SERVER_NAME=db-1.internal.example"},
			want: `malformed configuration: GOIABADA_DB_TLS_SERVER_NAME (--db-tls-server-name) is "db-1.internal.example" while GOIABADA_DB_TLS_MODE (--db-tls-mode) is require, which checks no host name: only verify-full checks the certificate's host name` + "\n",
		},
		{
			name: "PGSSLCERT, which the client certificate setting replaces",
			env:  []string{"PGSSLCERT=" + clientCert},
			want: "malformed configuration: PGSSLCERT is set, which the auth server no longer reads: " +
				"unset it and set GOIABADA_DB_TLS_CLIENT_CERT_FILE (--db-tls-client-cert-file) instead\n",
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
		assert.Equal(t, `malformed configuration: --db-tls-mode is "strict", not one of disable, prefer, require, verify-ca, verify-full`+
			"\n\n"+migrateUsage+"\n", stderr)
	})

	t.Run("a client certificate on SQL Server, whose driver takes none", func(t *testing.T) {
		decoy := filepath.Join(t.TempDir(), "d.db")
		env := []string{"GOIABADA_DB_TYPE=mssql", "GOIABADA_DB_HOST=127.0.0.1", "GOIABADA_DB_PORT=1",
			"GOIABADA_DB_CREATE=false", "GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
			"GOIABADA_DB_TLS_MODE=verify-full",
			"GOIABADA_DB_TLS_CLIENT_CERT_FILE=" + clientCert, "GOIABADA_DB_TLS_CLIENT_KEY_FILE=" + clientKey}

		code, stderr := runMainProcessWith(t, decoy, env)

		require.Equal(t, migrateExitUsage, code, "stderr: %s", stderr)
		assert.Equal(t, `malformed configuration: GOIABADA_DB_TLS_CLIENT_CERT_FILE (--db-tls-client-cert-file) is "`+clientCert+
			`" while GOIABADA_DB_TYPE (--db-type) is mssql, whose driver takes no client certificate`+"\n", stderr)
	})

	t.Run("the pair, the override and verify-full reach the dial together", func(t *testing.T) {
		decoy := filepath.Join(t.TempDir(), "d.db")

		code, stderr := runMainProcessWith(t, decoy, append(append([]string{}, postgres...),
			"GOIABADA_DB_TLS_MODE=verify-full",
			"GOIABADA_DB_TLS_CLIENT_CERT_FILE="+clientCert, "GOIABADA_DB_TLS_CLIENT_KEY_FILE="+clientKey,
			"GOIABADA_DB_TLS_SERVER_NAME=db-1.internal.example"))

		require.Equal(t, migrateExitError, code, "stderr: %s", stderr)
		assert.Contains(t, stderr, "(tls mode verify-full)", "the load passed and the engine was reached: %s", stderr)
	})
}

// TestMain_MigrateHoldsTheConnectionsTLSRulesToItsOwnFlags: the CA file and libpq's variables are
// checked against the configuration `migrate` runs with, the --db-* flags given after it applied,
// so a flag there that settles what the environment left wrong is not refused for it (#502). Each
// case reaches the database: PostgreSQL's dial fails on a port nothing listens on, and SQLite's
// decoy answers `migrate version`.
func TestMain_MigrateHoldsTheConnectionsTLSRulesToItsOwnFlags(t *testing.T) {
	ca := writeTestAuthority(t)
	missing := filepath.Join(t.TempDir(), "absent.pem")
	postgres := []string{
		"GOIABADA_DB_TYPE=postgres",
		"GOIABADA_DB_HOST=127.0.0.1",
		"GOIABADA_DB_PORT=1",
		"GOIABADA_DB_CREATE=false",
	}

	cases := []struct {
		name     string
		env      []string
		args     []string
		wantCode int
	}{
		{
			name:     "a CA file from the environment, the verifying mode after migrate",
			env:      []string{"GOIABADA_DB_TLS_CA_FILE=" + ca},
			args:     []string{"migrate", "--db-tls-mode=verify-full", "version"},
			wantCode: migrateExitError,
		},
		{
			name:     "an unreadable CA file from the environment, replaced after migrate",
			env:      []string{"GOIABADA_DB_TLS_MODE=verify-full", "GOIABADA_DB_TLS_CA_FILE=" + missing},
			args:     []string{"migrate", "--db-tls-ca-file=" + ca, "version"},
			wantCode: migrateExitError,
		},
		{
			name:     "libpq's variable beside postgres, sqlite after migrate",
			env:      []string{"PGSSLMODE=verify-full"},
			args:     []string{"migrate", "--db-type=sqlite", "version"},
			wantCode: migrateExitOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoy := filepath.Join(t.TempDir(), "d.db")

			code, stderr := runMainProcessWith(t, decoy, append(append([]string{}, postgres...), tc.env...), tc.args...)

			require.Equal(t, tc.wantCode, code, "stderr: %s", stderr)
			assert.NotContains(t, stderr, "malformed configuration")
		})
	}

	t.Run("the merged configuration is still held to the rules", func(t *testing.T) {
		decoy := filepath.Join(t.TempDir(), "d.db")

		code, stderr := runMainProcessWith(t, decoy, append(append([]string{}, postgres...),
			"GOIABADA_DB_TLS_MODE=verify-full", "GOIABADA_DB_TLS_CA_FILE="+ca),
			"migrate", "--db-tls-mode=require", "version")

		require.Equal(t, migrateExitUsage, code, "stderr: %s", stderr)
		// One line, as from the environment alone: the CA file is a setting, not how migrate was typed.
		assert.Equal(t, `malformed configuration: GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) is "`+ca+
			`" while GOIABADA_DB_TLS_MODE (--db-tls-mode) is require, which checks no certificate: only verify-ca and verify-full read a CA file`+"\n", stderr)
	})
}

// writeTestAuthority writes a self-signed authority's certificate to a PEM file of the test's and
// answers its path.
func writeTestAuthority(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "main test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

// writeTestClientPair writes a client certificate and its key to files of the test's and answers
// their paths (#546).
func writeTestClientPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "main test client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "client.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	keyPath := filepath.Join(t.TempDir(), "client.key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}
