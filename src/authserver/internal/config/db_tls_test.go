package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The connection's TLS settings at the load: GOIABADA_DB_TLS_MODE and GOIABADA_DB_TLS_CA_FILE,
// their flags, and every refusal a start makes of them before anything is opened (#502).

// testAuthority is a certificate authority made for one test, and a server certificate it signed.
type testAuthority struct {
	pem    []byte
	server *x509.Certificate
}

// newTestAuthority makes an authority and a certificate it signs for host.
func newTestAuthority(t *testing.T, host string) testAuthority {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "config test authority " + host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	server, err := x509.ParseCertificate(serverDER)
	require.NoError(t, err)

	return testAuthority{
		pem:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		server: server,
	}
}

// writeFile writes content to a file of its own in a directory of the test's and answers its path.
func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

const wantTLSModes = "one of disable, prefer, require, verify-ca, verify-full"

// TestLoad_TheTLSModeIsOneOfTheFive: the five libpq names load as written, empty reads as unset,
// and anything else is refused, a case or an alias included, from the variable or the flag. A
// valid flag does not rescue a malformed variable, as with every other setting.
func TestLoad_TheTLSModeIsOneOfTheFive(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		args     []string
		wantMode string // the mode in effect
		wantSet  bool   // whether the variable or the flag set it
		refusal  string
	}{
		{name: "unset", wantMode: "prefer"},
		{name: "an empty variable is unset", env: map[string]string{"GOIABADA_DB_TLS_MODE": ""}, wantMode: "prefer"},
		{name: "an empty flag is unset", args: []string{"-db-tls-mode="}, wantMode: "prefer"},
		{name: "disable", env: map[string]string{"GOIABADA_DB_TLS_MODE": "disable"}, wantMode: "disable", wantSet: true},
		{name: "prefer written on purpose", env: map[string]string{"GOIABADA_DB_TLS_MODE": "prefer"}, wantMode: "prefer", wantSet: true},
		{name: "require", env: map[string]string{"GOIABADA_DB_TLS_MODE": "require"}, wantMode: "require", wantSet: true},
		{name: "verify-ca", env: map[string]string{"GOIABADA_DB_TLS_MODE": "verify-ca"}, wantMode: "verify-ca", wantSet: true},
		{name: "verify-full, trimmed as every variable is", env: map[string]string{"GOIABADA_DB_TLS_MODE": " verify-full "}, wantMode: "verify-full", wantSet: true},
		{name: "the flag alone", args: []string{"-db-tls-mode=require"}, wantMode: "require", wantSet: true},

		{name: "a name libpq does not have", env: map[string]string{"GOIABADA_DB_TLS_MODE": "verify"},
			refusal: `GOIABADA_DB_TLS_MODE is "verify", not ` + wantTLSModes},
		{name: "another case", env: map[string]string{"GOIABADA_DB_TLS_MODE": "VERIFY-FULL"},
			refusal: `GOIABADA_DB_TLS_MODE is "VERIFY-FULL", not ` + wantTLSModes},
		{name: "a driver's alias", env: map[string]string{"GOIABADA_DB_TLS_MODE": "VERIFY_IDENTITY"},
			refusal: `GOIABADA_DB_TLS_MODE is "VERIFY_IDENTITY", not ` + wantTLSModes},
		{name: "a malformed flag", args: []string{"-db-tls-mode=strict"},
			refusal: `--db-tls-mode is "strict", not ` + wantTLSModes},
		{name: "a valid flag does not rescue the variable",
			env: map[string]string{"GOIABADA_DB_TLS_MODE": "verify_full"}, args: []string{"-db-tls-mode=verify-full"},
			refusal: `GOIABADA_DB_TLS_MODE is "verify_full", not ` + wantTLSModes},
		{name: "a malformed mode is refused on SQLite too, as every malformed setting is",
			env:     map[string]string{"GOIABADA_DB_TYPE": "sqlite", "GOIABADA_DB_TLS_MODE": "on"},
			refusal: `GOIABADA_DB_TLS_MODE is "on", not ` + wantTLSModes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c, err := loadMatrixRefusing(t, tt.env, tt.args)

			if tt.refusal != "" {
				require.Error(t, err)
				assert.Equal(t, "malformed configuration: "+tt.refusal, err.Error())
				assert.Nil(t, c, "a refusal answers no configuration")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMode, string(c.Database.EffectiveTLSMode()))
			assert.Equal(t, tt.wantSet, c.Database.TLSMode != "",
				"the start warns exactly when neither the variable nor the flag set the mode")
		})
	}
}

// TestLoad_TheCAFileReplacesTheSystemRoots: beside a mode that checks the certificate, the load
// reads the file once and the authorities in it are the whole of what the connection trusts. A
// certificate the file's authority signed verifies against them; one another authority signed
// does not, whatever the system trusts.
func TestLoad_TheCAFileReplacesTheSystemRoots(t *testing.T) {
	ours := newTestAuthority(t, "db.example.com")
	theirs := newTestAuthority(t, "db.example.com")
	caFile := writeFile(t, "ca.pem", ours.pem)

	for _, mode := range []string{"verify-ca", "verify-full"} {
		for _, source := range []struct {
			name string
			env  map[string]string
			args []string
		}{
			{"the variables", map[string]string{"GOIABADA_DB_TLS_MODE": mode, "GOIABADA_DB_TLS_CA_FILE": caFile}, nil},
			{"the flags", nil, []string{"-db-tls-mode=" + mode, "-db-tls-ca-file=" + caFile}},
		} {
			t.Run(mode+" from "+source.name, func(t *testing.T) {
				env := map[string]string{"GOIABADA_DB_TYPE": "mysql"}
				for k, v := range source.env {
					env[k] = v
				}
				_, c := loadMatrix(t, env, source.args)

				require.NotNil(t, c.Database.TLSRoots, "the CA file's authorities are what the engines are handed")
				_, err := ours.server.Verify(x509.VerifyOptions{Roots: c.Database.TLSRoots, DNSName: "db.example.com"})
				require.NoError(t, err, "a certificate the file's authority signed verifies")
				_, err = theirs.server.Verify(x509.VerifyOptions{Roots: c.Database.TLSRoots, DNSName: "db.example.com"})
				require.Error(t, err, "a certificate another authority signed does not")
			})
		}
	}

	t.Run("no CA file means the system roots", func(t *testing.T) {
		_, c := loadMatrix(t, map[string]string{"GOIABADA_DB_TYPE": "postgres", "GOIABADA_DB_TLS_MODE": "verify-full"}, nil)
		assert.Nil(t, c.Database.TLSRoots)
	})
}

// TestLoad_RefusesACAFileItCannotUse: a CA file beside a mode that checks no certificate, one that
// cannot be read and one holding no PEM certificate each stop the load, on every engine with a
// connection to check, naming the file under both its variable and its flag.
func TestLoad_RefusesACAFileItCannotUse(t *testing.T) {
	good := writeFile(t, "ca.pem", newTestAuthority(t, "db").pem)
	missing := filepath.Join(t.TempDir(), "absent.pem")
	notPEM := writeFile(t, "ca.der", []byte("this is not a certificate\n"))
	keyOnly := writeFile(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}))
	directory := t.TempDir()

	const caSetting = "GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file)"
	beside := func(path, mode string) string {
		return caSetting + ` is "` + path + `" while GOIABADA_DB_TLS_MODE (--db-tls-mode) is ` + mode +
			`, which checks no certificate: only verify-ca and verify-full read a CA file`
	}

	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		refusal string
	}{
		{name: "beside disable", env: map[string]string{"GOIABADA_DB_TLS_MODE": "disable", "GOIABADA_DB_TLS_CA_FILE": good},
			refusal: beside(good, "disable")},
		{name: "beside prefer", env: map[string]string{"GOIABADA_DB_TLS_MODE": "prefer", "GOIABADA_DB_TLS_CA_FILE": good},
			refusal: beside(good, "prefer")},
		{name: "beside require", env: map[string]string{"GOIABADA_DB_TLS_MODE": "require", "GOIABADA_DB_TLS_CA_FILE": good},
			refusal: beside(good, "require")},
		{name: "beside an unset mode, which is prefer", env: map[string]string{"GOIABADA_DB_TLS_CA_FILE": good},
			refusal: beside(good, "unset, so prefer")},
		{name: "from the flag beside a mode from the variable",
			env: map[string]string{"GOIABADA_DB_TLS_MODE": "require"}, args: []string{"-db-tls-ca-file=" + good},
			refusal: beside(good, "require")},
		{name: "a file that is not there", env: map[string]string{"GOIABADA_DB_TLS_MODE": "verify-full", "GOIABADA_DB_TLS_CA_FILE": missing},
			refusal: caSetting + ` is "` + missing + `", which cannot be read: no such file or directory`},
		{name: "a directory", env: map[string]string{"GOIABADA_DB_TLS_MODE": "verify-ca", "GOIABADA_DB_TLS_CA_FILE": directory},
			refusal: caSetting + ` is "` + directory + `", which cannot be read: is a directory`},
		{name: "a file holding no PEM block", env: map[string]string{"GOIABADA_DB_TLS_MODE": "verify-full", "GOIABADA_DB_TLS_CA_FILE": notPEM},
			refusal: caSetting + ` is "` + notPEM + `", which holds no PEM certificate`},
		{name: "a PEM file holding a key and no certificate", env: map[string]string{"GOIABADA_DB_TLS_MODE": "verify-ca", "GOIABADA_DB_TLS_CA_FILE": keyOnly},
			refusal: caSetting + ` is "` + keyOnly + `", which holds no PEM certificate`},
	}
	for _, engine := range []string{"mysql", "postgres", "mssql"} {
		for _, tt := range tests {
			t.Run(engine+": "+tt.name, func(t *testing.T) {
				env := map[string]string{"GOIABADA_DB_TYPE": engine}
				for k, v := range tt.env {
					env[k] = v
				}
				_, c, err := loadMatrixRefusing(t, env, tt.args)

				require.Error(t, err)
				assert.Equal(t, "malformed configuration: "+tt.refusal, err.Error())
				assert.NotContains(t, err.Error(), "\n", "the refusal is one line on stderr")
				assert.Nil(t, c, "a refusal answers no configuration")
			})
		}
	}
}

// TestLoad_SQLiteIgnoresTheCAFile: SQLite has no connection to protect, so its start reads no CA
// file and refuses none, as it ignores GOIABADA_DB_CREATE and the pool settings.
func TestLoad_SQLiteIgnoresTheCAFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	for _, mode := range []string{"", "prefer", "verify-full"} {
		t.Run("mode "+mode, func(t *testing.T) {
			_, c := loadMatrix(t, map[string]string{
				"GOIABADA_DB_TYPE":        "sqlite",
				"GOIABADA_DB_TLS_MODE":    mode,
				"GOIABADA_DB_TLS_CA_FILE": missing,
			}, nil)
			assert.Nil(t, c.Database.TLSRoots, "SQLite reads no CA file")
		})
	}
}

// TestCheckDatabaseFlags_HoldsTheTLSFlagsGivenAfterMigrate is the two checks the `migrate`
// subcommand runs after its own parse, CheckDatabaseFlags and then CheckDatabaseTLS, over a copy of
// the loaded configuration: a mode or a CA file given after `migrate` is held to the rules one given
// before it is, and a CA file it names is read.
func TestCheckDatabaseFlags_HoldsTheTLSFlagsGivenAfterMigrate(t *testing.T) {
	authority := newTestAuthority(t, "db.example.com")
	good := writeFile(t, "ca.pem", authority.pem)
	missing := filepath.Join(t.TempDir(), "absent.pem")

	tests := []struct {
		name  string
		base  DatabaseConfig
		args  []string
		want  string
		roots bool
	}{
		{name: "no flags", base: DatabaseConfig{Type: "postgres"}},
		{name: "a malformed mode", base: DatabaseConfig{Type: "postgres"}, args: []string{"-db-tls-mode=verify"},
			want: `malformed configuration: --db-tls-mode is "verify", not ` + wantTLSModes},
		{name: "a CA file beside the loaded mode, which checks nothing", base: DatabaseConfig{Type: "postgres", TLSMode: "require"},
			args: []string{"-db-tls-ca-file=" + good},
			want: `malformed configuration: GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) is "` + good +
				`" while GOIABADA_DB_TLS_MODE (--db-tls-mode) is require, which checks no certificate: only verify-ca and verify-full read a CA file`},
		{name: "a CA file that is not there", base: DatabaseConfig{Type: "mssql", TLSMode: "verify-full"},
			args: []string{"-db-tls-ca-file=" + missing},
			want: `malformed configuration: GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) is "` + missing + `", which cannot be read: no such file or directory`},
		{name: "a mode that checks, beside the loaded CA file", base: DatabaseConfig{Type: "mysql", TLSCAFile: good},
			args: []string{"-db-tls-mode=verify-full"}, roots: true},
		{name: "a CA file that is read", base: DatabaseConfig{Type: "mysql", TLSMode: "verify-ca"},
			args: []string{"-db-tls-ca-file=" + good}, roots: true},
		{name: "a type changed to sqlite ignores the CA file", base: DatabaseConfig{Type: "postgres", TLSMode: "verify-ca", TLSCAFile: missing},
			args: []string{"-db-type=sqlite"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			local := tt.base
			local.MaxOpenConns = 20
			fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			RegisterDatabaseFlags(fs, &local)
			require.NoError(t, fs.Parse(tt.args))

			err := CheckDatabaseFlags(fs, &local)
			if err == nil {
				err = CheckDatabaseTLS(&local)
			}
			if tt.want != "" {
				require.Error(t, err)
				assert.Equal(t, tt.want, err.Error())
				return
			}
			require.NoError(t, err)
			if !tt.roots {
				assert.Nil(t, local.TLSRoots)
				return
			}
			require.NotNil(t, local.TLSRoots)
			_, verifyErr := authority.server.Verify(x509.VerifyOptions{Roots: local.TLSRoots, DNSName: "db.example.com"})
			assert.NoError(t, verifyErr, "the CA file named after migrate is what the connection trusts")
		})
	}
}

// TestRegisterDatabaseFlags_TheTLSHelpNamesEveryMode: the mode's help names the five values.
func TestRegisterDatabaseFlags_TheTLSHelpNamesEveryMode(t *testing.T) {
	var local DatabaseConfig
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	RegisterDatabaseFlags(fs, &local)

	f := fs.Lookup("db-tls-mode")
	require.NotNil(t, f, "db-tls-mode is not registered")
	for _, mode := range strings.Split("disable prefer require verify-ca verify-full", " ") {
		assert.Contains(t, f.Usage, mode)
	}
}

// libpqTLSRefusals are the line each of libpq's TLS variables stops a PostgreSQL start with: the
// variable, never its value, which for PGSSLPASSWORD is a secret, and what replaces it (#502
// decision 5).
var libpqTLSRefusals = map[string]string{
	"PGSSLMODE":     "PGSSLMODE is set, which the auth server no longer reads: unset it and set GOIABADA_DB_TLS_MODE (--db-tls-mode) instead",
	"PGSSLROOTCERT": "PGSSLROOTCERT is set, which the auth server no longer reads: unset it and set GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) instead",
	"PGSSLCERT": "PGSSLCERT is set, which the auth server no longer reads: unset it; the auth server presents no client certificate, " +
		"and GOIABADA_DB_TLS_MODE (--db-tls-mode) and GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) decide the connection's TLS",
	"PGSSLKEY": "PGSSLKEY is set, which the auth server no longer reads: unset it; the auth server presents no client certificate, " +
		"and GOIABADA_DB_TLS_MODE (--db-tls-mode) and GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) decide the connection's TLS",
	"PGSSLPASSWORD": "PGSSLPASSWORD is set, which the auth server no longer reads: unset it; the auth server presents no client certificate, " +
		"and GOIABADA_DB_TLS_MODE (--db-tls-mode) and GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) decide the connection's TLS",
	"PGSSLSNI": "PGSSLSNI is set, which the auth server no longer reads: unset it; " +
		"GOIABADA_DB_TLS_MODE (--db-tls-mode) and GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) decide the connection's TLS",
	"PGSSLNEGOTIATION": "PGSSLNEGOTIATION is set, which the auth server no longer reads: unset it; " +
		"GOIABADA_DB_TLS_MODE (--db-tls-mode) and GOIABADA_DB_TLS_CA_FILE (--db-tls-ca-file) decide the connection's TLS",
}

// TestLoad_RefusesLibpqsTLSVariablesOnPostgres: on PostgreSQL, any of the seven PGSSL* variables
// set and non-empty stops the start with one line naming it and its replacement, whatever its value,
// because Goiabada's two settings are the whole of the connection's TLS and an operator who followed
// the old PGSSLMODE advice must not drop to prefer in silence (#502 decision 5).
func TestLoad_RefusesLibpqsTLSVariablesOnPostgres(t *testing.T) {
	for name, refusal := range libpqTLSRefusals {
		t.Run(name, func(t *testing.T) {
			const value = "verify-full-s3cr3t"
			_, c, err := loadMatrixRefusing(t, map[string]string{"GOIABADA_DB_TYPE": "postgres", name: value}, nil)

			require.Error(t, err)
			assert.Equal(t, "malformed configuration: "+refusal, err.Error())
			assert.NotContains(t, err.Error(), value, "the value is never written, PGSSLPASSWORD's being a secret")
			assert.Nil(t, c, "a refusal answers no configuration")
		})
	}

	t.Run("every one set is named, in the order decision 5 lists them", func(t *testing.T) {
		_, _, err := loadMatrixRefusing(t, map[string]string{
			"GOIABADA_DB_TYPE": "postgres", "PGSSLNEGOTIATION": "direct", "PGSSLMODE": "require",
		}, nil)
		require.Error(t, err)
		assert.Equal(t, "malformed configuration: "+libpqTLSRefusals["PGSSLMODE"]+"; "+libpqTLSRefusals["PGSSLNEGOTIATION"], err.Error())
	})

	t.Run("postgres chosen by the flag", func(t *testing.T) {
		_, _, err := loadMatrixRefusing(t, map[string]string{"GOIABADA_DB_TYPE": "mysql", "PGSSLROOTCERT": "/ca.pem"},
			[]string{"-db-type=postgres"})
		require.Error(t, err)
		assert.Equal(t, "malformed configuration: "+libpqTLSRefusals["PGSSLROOTCERT"], err.Error())
	})
}

// TestLoad_LeavesLibpqsVariablesAloneOtherwise: the variables mean nothing to another engine, an
// empty one is unset, and libpq's other variables, PGSERVICE among them, are untouched.
func TestLoad_LeavesLibpqsVariablesAloneOtherwise(t *testing.T) {
	for _, engine := range []string{"mysql", "mssql", "sqlite"} {
		t.Run(engine, func(t *testing.T) {
			env := map[string]string{"GOIABADA_DB_TYPE": engine}
			for name := range libpqTLSRefusals {
				env[name] = "verify-full"
			}
			loadMatrix(t, env, nil)
		})
	}
	t.Run("postgres with each one empty", func(t *testing.T) {
		env := map[string]string{"GOIABADA_DB_TYPE": "postgres"}
		for name := range libpqTLSRefusals {
			env[name] = ""
		}
		loadMatrix(t, env, nil)
	})
	t.Run("postgres with libpq's other variables", func(t *testing.T) {
		loadMatrix(t, map[string]string{"GOIABADA_DB_TYPE": "postgres", "PGSERVICE": "goiabada", "PGHOST": "db", "PGAPPNAME": "x"}, nil)
	})
}

// TestCheckDatabaseTLS_RefusesLibpqsTLSVariablesUnderMigrate: a type changed to postgres after
// `migrate` is held to the refusal too, since migrate opens the same connection.
func TestCheckDatabaseTLS_RefusesLibpqsTLSVariablesUnderMigrate(t *testing.T) {
	for name := range libpqTLSRefusals {
		t.Setenv(name, "")
	}
	t.Setenv("PGSSLMODE", "verify-full")

	local := DatabaseConfig{Type: "mysql", MaxOpenConns: 20}
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	RegisterDatabaseFlags(fs, &local)
	require.NoError(t, fs.Parse([]string{"-db-type=postgres"}))
	require.NoError(t, CheckDatabaseFlags(fs, &local))

	err := CheckDatabaseTLS(&local)
	require.Error(t, err)
	assert.Equal(t, "malformed configuration: "+libpqTLSRefusals["PGSSLMODE"], err.Error())
}
