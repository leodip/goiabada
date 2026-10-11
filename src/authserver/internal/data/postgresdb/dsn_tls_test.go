package postgresdb

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/tlstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The connection's TLS is GOIABADA_DB_TLS_MODE and GOIABADA_DB_TLS_CA_FILE and nothing else (#502
// decision 5). Each mode is read back through pgx's own configuration, the one the connection is
// opened with, and every certificate check is observed as a TLS handshake against a server
// presenting a certificate made in the test, so what is pinned is what the driver does rather than
// how the string is spelled.

const tlsTestHost = "db.example.com"

// tlsCertificates are the server certificates every mode is shown against.
type tlsCertificates struct {
	ours      *x509.CertPool  // the authority the CA file holds
	oursForDB tls.Certificate // ours, naming the host dialled
	oursOther tls.Certificate // ours, naming another host
	theirs    tls.Certificate // another authority's, naming the host dialled
}

func newTLSCertificates(t *testing.T) tlsCertificates {
	t.Helper()
	ours := tlstest.NewAuthority(t, "ours")
	theirs := tlstest.NewAuthority(t, "theirs")
	return tlsCertificates{
		ours:      ours.Pool(),
		oursForDB: ours.Issue(t, tlsTestHost),
		oursOther: ours.Issue(t, "other.example.com"),
		theirs:    theirs.Issue(t, tlsTestHost),
	}
}

// assertEveryModeMaps holds each mode's configuration, for the application database and the
// maintenance one alike, to decision 2 of #502: what it encrypts, which certificates it accepts,
// and whether it falls back to plain text.
func assertEveryModeMaps(t *testing.T, certs tlsCertificates) {
	t.Helper()

	type accepts struct{ oursForDB, oursOther, theirs bool }
	tests := []struct {
		name  string
		mode  data.TLSMode
		roots *x509.CertPool
		// encrypted is whether the first attempt is TLS; fallback whether plain text follows it.
		encrypted, fallback bool
		accepts             accepts
	}{
		{name: "disable never encrypts", mode: data.TLSDisable},
		{name: "unset is prefer", mode: "", encrypted: true, fallback: true, accepts: accepts{true, true, true}},
		{name: "prefer encrypts, checks nothing and falls back", mode: data.TLSPrefer, encrypted: true, fallback: true,
			accepts: accepts{true, true, true}},
		{name: "require encrypts and checks nothing", mode: data.TLSRequire, encrypted: true, accepts: accepts{true, true, true}},
		{name: "verify-ca checks the chain against the CA file, not the host", mode: data.TLSVerifyCA, roots: certs.ours,
			encrypted: true, accepts: accepts{oursForDB: true, oursOther: true}},
		{name: "verify-full checks the chain against the CA file, and the host", mode: data.TLSVerifyFull, roots: certs.ours,
			encrypted: true, accepts: accepts{oursForDB: true}},
		{name: "verify-ca with no CA file trusts the system's roots", mode: data.TLSVerifyCA, encrypted: true},
		{name: "verify-full with no CA file trusts the system's roots", mode: data.TLSVerifyFull, encrypted: true},
	}
	for _, tt := range tests {
		cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: tlsTestHost, Port: 5432, Name: "goiabada",
			TLSMode: tt.mode, TLSRoots: tt.roots}
		for _, conn := range []struct {
			which string
			build func(*DatabaseConfig) (*pgx.ConnConfig, error)
		}{{"ConnConfig", ConnConfig}, {"MaintenanceConnConfig", MaintenanceConnConfig}} {
			t.Run(tt.name+"/"+conn.which, func(t *testing.T) {
				parsed, err := conn.build(cfg)
				require.NoError(t, err)

				if !tt.encrypted {
					assert.Nil(t, parsed.TLSConfig, "the connection is plain text")
					assert.Empty(t, parsed.Fallbacks, "with nothing tried after it")
					return
				}
				require.NotNil(t, parsed.TLSConfig, "the connection is TLS first")
				if tt.fallback {
					require.Len(t, parsed.Fallbacks, 1)
					assert.Nil(t, parsed.Fallbacks[0].TLSConfig, "and plain text after it")
				} else {
					assert.Empty(t, parsed.Fallbacks, "with no plain-text fallback")
				}
				assert.Empty(t, parsed.TLSConfig.Certificates, "no client certificate is presented")
				assert.NotEqual(t, "direct", parsed.SSLNegotiation, "TLS is negotiated as libpq does by default")
				assert.Empty(t, parsed.TLSConfig.NextProtos)

				for _, server := range []struct {
					name   string
					cert   tls.Certificate
					accept bool
				}{
					{"our authority's certificate for the host dialled", certs.oursForDB, tt.accepts.oursForDB},
					{"our authority's certificate for another host", certs.oursOther, tt.accepts.oursOther},
					{"another authority's certificate for the host dialled", certs.theirs, tt.accepts.theirs},
				} {
					err := tlstest.Handshake(t, parsed.TLSConfig, server.cert)
					if server.accept {
						assert.NoErrorf(t, err, "%s is accepted", server.name)
					} else {
						assert.Errorf(t, err, "%s is refused", server.name)
					}
				}
			})
		}
	}
}

// TestConnConfig_EveryModeMaps: in a clean environment, each of the five modes and the unset one is
// the connection decision 2 describes.
func TestConnConfig_EveryModeMaps(t *testing.T) {
	cleanLibpqEnvironment(t)
	assertEveryModeMaps(t, newTLSCertificates(t))
}

// TestConnConfig_TheEnvironmentNoLongerReachesTheConnection inverts what this file pinned before
// #502, when the URL carried no sslmode and libpq's environment decided the connection's TLS.
// Every PGSSL* variable, a service file PGSERVICE names and the files libpq reads from
// ~/.postgresql are each set to undo the mode: plain text, another authority's root, a client
// certificate, no SNI and direct negotiation. Every mode still maps as it does with none of them.
func TestConnConfig_TheEnvironmentNoLongerReachesTheConnection(t *testing.T) {
	certs := newTLSCertificates(t)
	theirs := tlstest.NewAuthority(t, "the environment's authority")
	clientCert := theirs.IssueClient(t, "goiabada")
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	require.NoError(t, err)
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Certificate[0]})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})

	dir := t.TempDir()
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, content, 0o600))
		return path
	}

	t.Run("each variable naming a file that exists", func(t *testing.T) {
		cleanLibpqEnvironment(t)
		home := filepath.Join(dir, "home")
		write("home/.postgresql/root.crt", theirs.PEM)
		write("home/.postgresql/postgresql.crt", clientCertPEM)
		write("home/.postgresql/postgresql.key", clientKeyPEM)
		t.Setenv("HOME", home)

		t.Setenv("PGSSLMODE", "disable")
		t.Setenv("PGSSLROOTCERT", write("root.pem", theirs.PEM))
		t.Setenv("PGSSLCERT", write("client.pem", clientCertPEM))
		t.Setenv("PGSSLKEY", write("client.key", clientKeyPEM))
		t.Setenv("PGSSLPASSWORD", "unused")
		t.Setenv("PGSSLSNI", "0")
		t.Setenv("PGSSLNEGOTIATION", "direct")
		t.Setenv("PGSERVICEFILE", write("pg_service.conf", []byte("[goiabada]\nsslmode=allow\nsslrootcert="+
			filepath.Join(dir, "root.pem")+"\nsslnegotiation=direct\n")))
		t.Setenv("PGSERVICE", "goiabada")

		assertEveryModeMaps(t, certs)
	})

	t.Run("each variable naming a file that is not there", func(t *testing.T) {
		cleanLibpqEnvironment(t)
		missing := filepath.Join(dir, "absent")
		t.Setenv("PGSSLROOTCERT", missing+".crt")
		t.Setenv("PGSSLCERT", missing+".pem")
		t.Setenv("PGSSLKEY", missing+".key")

		assertEveryModeMaps(t, certs)
	})
}

// cleanLibpqEnvironment clears every variable libpq reads a TLS setting from, and points HOME at an
// empty directory, so no developer's own ~/.postgresql decides what a case observes.
func cleanLibpqEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGSSLPASSWORD",
		"PGSSLSNI", "PGSSLNEGOTIATION", "PGSERVICE", "PGSERVICEFILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("HOME", t.TempDir())
}
