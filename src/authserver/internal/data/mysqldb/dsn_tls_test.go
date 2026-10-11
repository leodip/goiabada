package mysqldb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/tlstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The connection's TLS is GOIABADA_DB_TLS_MODE and GOIABADA_DB_TLS_CA_FILE (#502). Each mode is read
// back as the TLS configuration the driver connects with, and every certificate check is observed
// as a TLS handshake against a server presenting a certificate made in the test, so what is pinned
// is what go-sql-driver/mysql does rather than how the configuration is spelled.

// TestConnConfig_EveryModeMaps holds each mode's configuration, for the application database and
// the maintenance connection alike, to decision 2 of #502: whether it encrypts, whether it falls
// back to plain text when the server offers no TLS, and which certificates it accepts. Only prefer
// falls back.
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
		name      string
		mode      data.TLSMode
		roots     *x509.CertPool
		encrypted bool
		fallback  bool
		accepts   accepts
	}{
		{name: "disable never encrypts", mode: data.TLSDisable},
		{name: "unset is prefer", mode: "", encrypted: true, fallback: true, accepts: all},
		{name: "prefer encrypts when offered and checks nothing", mode: data.TLSPrefer, encrypted: true, fallback: true,
			accepts: all},
		{name: "require always encrypts and checks nothing", mode: data.TLSRequire, encrypted: true, accepts: all},
		{name: "verify-ca checks the chain against the CA file, not the host", mode: data.TLSVerifyCA, roots: ours.Pool(),
			encrypted: true, accepts: accepts{oursForDB: true, oursOther: true}},
		{name: "verify-full checks the chain against the CA file, and the host", mode: data.TLSVerifyFull, roots: ours.Pool(),
			encrypted: true, accepts: accepts{oursForDB: true}},
		{name: "verify-ca with no CA file trusts the system's roots", mode: data.TLSVerifyCA, encrypted: true},
		{name: "verify-full with no CA file trusts the system's roots", mode: data.TLSVerifyFull, encrypted: true},
	}
	for _, tt := range tests {
		cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: host, Port: 3306, Name: "goiabada",
			TLSMode: tt.mode, TLSRoots: tt.roots}
		for _, conn := range []struct {
			which string
			build func(*DatabaseConfig) (*mysqldriver.Config, error)
		}{{"ConnConfig", ConnConfig}, {"MaintenanceConnConfig", MaintenanceConnConfig}} {
			t.Run(tt.name+"/"+conn.which, func(t *testing.T) {
				c, err := conn.build(cfg)
				require.NoError(t, err)
				_, err = mysqldriver.NewConnector(c)
				require.NoError(t, err, "the driver must accept the configuration")

				tlsConfig, fallback := driverTLS(t, c)
				if !tt.encrypted {
					assert.Nil(t, tlsConfig, "no TLS at all")
					return
				}
				require.NotNil(t, tlsConfig)
				assert.Equal(t, tt.fallback, fallback, "whether a server offering no TLS is reached in plain text")
				assert.Empty(t, tlsConfig.Certificates, "no client certificate is presented")
				for _, server := range []struct {
					name   string
					cert   tls.Certificate
					accept bool
				}{
					{"our authority's certificate for the host dialled", oursForDB, tt.accepts.oursForDB},
					{"our authority's certificate for another host", oursOther, tt.accepts.oursOther},
					{"another authority's certificate for the host dialled", theirsForDB, tt.accepts.theirs},
				} {
					err := tlstest.Handshake(t, tlsConfig, server.cert)
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
// whatever its common name says, as PostgreSQL and SQL Server check it. verify-ca, which checks no
// host name, accepts both (#502).
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
				cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: tc.host, Port: 3306, Name: "goiabada",
					TLSMode: mode, TLSRoots: ours.Pool()}
				c, err := ConnConfig(cfg)
				require.NoError(t, err)
				tlsConfig, _ := driverTLS(t, c)
				require.NotNil(t, tlsConfig)

				require.NoError(t, tlstest.Handshake(t, tlsConfig, forIP), "a certificate naming the address is accepted")
				for _, other := range []struct {
					name string
					cert tls.Certificate
				}{
					{"a certificate naming only a host name", forName},
					{"a certificate whose common name alone is the address", commonNameOnly},
				} {
					err := tlstest.Handshake(t, tlsConfig, other.cert)
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

// TestConnConfig_RefusesAModeOutsideTheFive: a configuration built directly can carry any string,
// and one the builder does not know is refused rather than connecting as prefer under another
// name (#502).
func TestConnConfig_RefusesAModeOutsideTheFive(t *testing.T) {
	cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "db", Port: 3306, Name: "goiabada",
		TLSMode: "VERIFY_IDENTITY"}
	for _, build := range []func(*DatabaseConfig) (*mysqldriver.Config, error){ConnConfig, MaintenanceConnConfig} {
		c, err := build(cfg)
		require.Error(t, err)
		assert.Nil(t, c)
		assert.Equal(t, `GOIABADA_DB_TLS_MODE "VERIFY_IDENTITY" is not one of the five modes`, err.Error())
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
