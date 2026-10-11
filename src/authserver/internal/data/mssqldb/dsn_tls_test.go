package mssqldb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/tlstest"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The connection's TLS is GOIABADA_DB_TLS_MODE and GOIABADA_DB_TLS_CA_FILE (#502). Each mode is read
// back as the driver's own configuration, the one the connection is opened with, and every
// certificate check is observed as a TLS handshake against a server presenting a certificate made
// in the test, so what is pinned is what go-mssqldb does rather than how the string is spelled.

// TestConnConfig_EveryModeMaps holds each mode's configuration, for the application database and
// master alike, to decision 2 of #502: what it encrypts and which certificates it accepts. The
// encryption is go-mssqldb's own reading: EncryptionOff encrypts the login, and the whole session
// only when the server forces it; EncryptionRequired encrypts the whole session and refuses a
// server that offers no encryption, so it has no plain-text fallback; EncryptionDisabled sends even
// the login in the clear. No mode is EncryptionStrict, TDS 8.0, which a SQL Server 2022 not
// configured for it refuses.
func TestConnConfig_EveryModeMaps(t *testing.T) {
	const host = "db.example.com"
	ours := tlstest.NewAuthority(t, "ours")
	theirs := tlstest.NewAuthority(t, "theirs")

	oursForDB := ours.Issue(t, host)
	oursOther := ours.Issue(t, "other.example.com")
	theirsForDB := theirs.Issue(t, host)

	type accepts struct{ oursForDB, oursOther, theirs bool }
	all := accepts{true, true, true}
	tests := []struct {
		name       string
		mode       data.TLSMode
		roots      *x509.CertPool
		encryption msdsn.Encryption
		accepts    accepts
	}{
		{name: "disable sends even the login in the clear", mode: data.TLSDisable, encryption: msdsn.EncryptionDisabled},
		{name: "unset is prefer", mode: "", encryption: msdsn.EncryptionOff, accepts: all},
		{name: "prefer encrypts the login and checks nothing", mode: data.TLSPrefer, encryption: msdsn.EncryptionOff,
			accepts: all},
		{name: "require encrypts the session and checks nothing", mode: data.TLSRequire, encryption: msdsn.EncryptionRequired,
			accepts: all},
		{name: "verify-ca checks the chain against the CA file, not the host", mode: data.TLSVerifyCA, roots: ours.Pool(),
			encryption: msdsn.EncryptionRequired, accepts: accepts{oursForDB: true, oursOther: true}},
		{name: "verify-full checks the chain against the CA file, and the host", mode: data.TLSVerifyFull, roots: ours.Pool(),
			encryption: msdsn.EncryptionRequired, accepts: accepts{oursForDB: true}},
		{name: "verify-ca with no CA file trusts the system's roots", mode: data.TLSVerifyCA,
			encryption: msdsn.EncryptionRequired},
		{name: "verify-full with no CA file trusts the system's roots", mode: data.TLSVerifyFull,
			encryption: msdsn.EncryptionRequired},
	}
	for _, tt := range tests {
		cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: host, Port: 1433, Name: "goiabada",
			TLSMode: tt.mode, TLSRoots: tt.roots}
		for _, conn := range []struct {
			which    string
			build    func(*DatabaseConfig) (msdsn.Config, error)
			database string
		}{{"ConnConfig", ConnConfig, "goiabada"}, {"MaintenanceConnConfig", MaintenanceConnConfig, "master"}} {
			t.Run(tt.name+"/"+conn.which, func(t *testing.T) {
				parsed, err := conn.build(cfg)
				require.NoError(t, err)
				assert.Equal(t, conn.database, parsed.Database)
				assert.Equal(t, tt.encryption, parsed.Encryption)

				if tt.encryption == msdsn.EncryptionDisabled {
					assert.Nil(t, parsed.TLSConfig, "no TLS at all")
					return
				}
				require.NotNil(t, parsed.TLSConfig)
				assert.Empty(t, parsed.TLSConfig.Certificates, "no client certificate is presented")
				for _, server := range []struct {
					name   string
					cert   tls.Certificate
					accept bool
				}{
					{"our authority's certificate for the host dialled", oursForDB, tt.accepts.oursForDB},
					{"our authority's certificate for another host", oursOther, tt.accepts.oursOther},
					{"another authority's certificate for the host dialled", theirsForDB, tt.accepts.theirs},
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

// TestConnConfig_VerifyFullChecksAnIPLiteralAgainstTheIPAddresses: dialled by an IP address,
// verify-full accepts a certificate naming that address and refuses one naming only a host name,
// whatever its common name says, as PostgreSQL and MySQL check it. go-mssqldb's own path for a host
// containing `:` reads only the common name, so an IPv6 literal is the case that shows it is not
// the path taken. verify-ca, which checks no host name, accepts both (#502).
func TestConnConfig_VerifyFullChecksAnIPLiteralAgainstTheIPAddresses(t *testing.T) {
	ours := tlstest.NewAuthority(t, "ours")
	for _, tc := range []struct{ host, ip string }{
		{"192.0.2.10", "192.0.2.10"},
		{"::1", "::1"},
		{"[::1]", "::1"},
	} {
		forIP := ours.Issue(t, tc.ip)
		forName := ours.Issue(t, "db.example.com")
		commonNameOnly := ours.IssueWithCommonName(t, tc.ip, "db.example.com")

		for _, mode := range []data.TLSMode{data.TLSVerifyCA, data.TLSVerifyFull} {
			t.Run(string(mode)+" "+tc.host, func(t *testing.T) {
				cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: tc.host, Port: 1433, Name: "goiabada",
					TLSMode: mode, TLSRoots: ours.Pool()}
				parsed, err := ConnConfig(cfg)
				require.NoError(t, err)
				require.NotNil(t, parsed.TLSConfig)

				require.NoError(t, tlstest.Handshake(t, parsed.TLSConfig, forIP), "a certificate naming the address is accepted")
				for _, other := range []struct {
					name string
					cert tls.Certificate
				}{
					{"a certificate naming only a host name", forName},
					{"a certificate whose common name alone is the address", commonNameOnly},
				} {
					err := tlstest.Handshake(t, parsed.TLSConfig, other.cert)
					if mode == data.TLSVerifyCA {
						require.NoErrorf(t, err, "verify-ca accepts %s", other.name)
						continue
					}
					var hostname x509.HostnameError
					require.ErrorAsf(t, err, &hostname, "verify-full refuses %s", other.name)
				}
			})
		}
	}
}

// TestNew_RefusesAModeOutsideTheFive: the configuration's load refuses any other value, so only a
// configuration built directly carries one, and it stops before anything is dialled rather than
// connecting as prefer under another name (#502).
func TestNew_RefusesAModeOutsideTheFive(t *testing.T) {
	cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "127.0.0.1", Port: 1, Name: "goiabada",
		Create: true, TLSMode: "verify-identity"}

	database, err := New(context.Background(), cfg, false)

	require.Error(t, err)
	assert.Nil(t, database)
	assert.Equal(t, `GOIABADA_DB_TLS_MODE "verify-identity" is not one of the five modes`, err.Error())
}
