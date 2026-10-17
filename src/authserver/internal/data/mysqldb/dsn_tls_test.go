package mysqldb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

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

// TestOpen_PreferAsksForTLSOnEveryConnection: in prefer, a connection that met a server offering no
// TLS and went on in plain text leaves the next connection asking for TLS again, so a database that
// turns TLS on is reached over it without the auth server restarting. The driver's fallback clears
// the TLS of the configuration the connection was handed, and without a copy per connection that
// was the connector's own, shared by the whole pool (#502).
func TestOpen_PreferAsksForTLSOnEveryConnection(t *testing.T) {
	server := newGreetingServer(t)
	cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "127.0.0.1", Port: server.port, Name: "goiabada",
		TLSMode: data.TLSPrefer}
	for _, conn := range []struct {
		which string
		build func(*DatabaseConfig) (*mysqldriver.Config, error)
	}{{"ConnConfig", ConnConfig}, {"MaintenanceConnConfig", MaintenanceConnConfig}} {
		t.Run(conn.which, func(t *testing.T) {
			db, err := open(conn.build(cfg))
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			server.offerTLS.Store(false)
			require.Error(t, db.PingContext(ctx), "the server hangs up after the client's first answer")
			asked := server.answers()
			require.NotEmpty(t, asked)
			assert.NotContains(t, asked, true, "a server offering no TLS is answered in plain text")

			server.offerTLS.Store(true)
			require.Error(t, db.PingContext(ctx), "the server hangs up after the client's first answer")
			asked = server.answers()
			require.NotEmpty(t, asked)
			assert.NotContains(t, asked, false, "the next connection asks for TLS again")
		})
	}
}

// The capability flags of the MySQL protocol the greeting below offers, and the one a client's
// first answer is read for.
const (
	clientMySQL      = 1 << 0
	clientProtocol41 = 1 << 9
	clientSSL        = 1 << 11
	clientSecureConn = 1 << 15
	clientPluginAuth = 1 << 19
)

// greetingServer is as much of a MySQL server as a connection's first two packets: it greets each
// connection, offering TLS when offerTLS says so as the connection arrives, reads the client's first
// answer, records whether it asks for TLS, and hangs up.
type greetingServer struct {
	port     int
	offerTLS atomic.Bool
	asked    chan bool
}

func newGreetingServer(t *testing.T) *greetingServer {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	s := &greetingServer{port: tcpAddr.Port, asked: make(chan bool, 16)}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			s.serve(conn)
		}
	}()
	return s
}

// serve records the answer before it hangs up, so by the time a client's ping has failed every
// connection it made is recorded.
func (s *greetingServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(greeting(s.offerTLS.Load())); err != nil {
		return
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	answer := make([]byte, int(header[0])|int(header[1])<<8|int(header[2])<<16)
	if _, err := io.ReadFull(conn, answer); err != nil || len(answer) < 4 {
		return
	}
	s.asked <- binary.LittleEndian.Uint32(answer)&clientSSL != 0
}

// answers is whether each connection made since the last call asked for TLS.
func (s *greetingServer) answers() []bool {
	var asked []bool
	for {
		select {
		case a := <-s.asked:
			asked = append(asked, a)
		default:
			return asked
		}
	}
}

// greeting is a protocol 10 handshake packet, the first a MySQL server sends, offering TLS or not.
func greeting(offerTLS bool) []byte {
	capabilities := uint32(clientMySQL | clientProtocol41 | clientSecureConn | clientPluginAuth)
	if offerTLS {
		capabilities |= clientSSL
	}
	p := []byte{10}
	p = append(p, "8.0.36\x00"...)
	p = binary.LittleEndian.AppendUint32(p, 1) // connection id
	p = append(p, "12345678\x00"...)           // the scramble's first part, and a filler
	p = binary.LittleEndian.AppendUint16(p, uint16(capabilities))
	p = append(p, 255)                         // utf8mb4_0900_ai_ci
	p = binary.LittleEndian.AppendUint16(p, 2) // autocommit
	p = binary.LittleEndian.AppendUint16(p, uint16(capabilities>>16))
	p = append(p, 21)                    // the scramble's length
	p = append(p, make([]byte, 10)...)   // reserved
	p = append(p, "123456789012\x00"...) // the scramble's second part
	p = append(p, "mysql_native_password\x00"...)
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}, p...)
}

// TestConnConfig_PresentsTheClientPairAndChecksTheNamedHost: the pair the configuration carries is
// presented by the configuration of the builder's own, in require as in the verifying modes — the
// driver's skip-verify string carrying no certificate — and the host name override replaces the
// host dialled in what verify-full checks, on the application database's connection and the
// maintenance one alike (#546).
func TestConnConfig_PresentsTheClientPairAndChecksTheNamedHost(t *testing.T) {
	const host = "db.example.com"
	ours := tlstest.NewAuthority(t, "ours")
	pair := ours.IssueClient(t, "goiabada")
	const override = "db-1.internal.example"
	forDialled := ours.Issue(t, host)
	forOverride := ours.Issue(t, override)

	for _, tt := range []struct {
		name  string
		mode  data.TLSMode
		roots *x509.CertPool
	}{
		{"require, which checks nothing", data.TLSRequire, nil},
		{"verify-ca, which checks the chain", data.TLSVerifyCA, ours.Pool()},
		{"verify-full, which checks the chain and the name", data.TLSVerifyFull, ours.Pool()},
	} {
		for _, conn := range []struct {
			which string
			build func(*DatabaseConfig) (*mysqldriver.Config, error)
		}{{"ConnConfig", ConnConfig}, {"MaintenanceConnConfig", MaintenanceConnConfig}} {
			t.Run(tt.name+"/"+conn.which, func(t *testing.T) {
				cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: host, Port: 3306, Name: "goiabada",
					TLSMode: tt.mode, TLSRoots: tt.roots, TLSClientCertificate: &pair, TLSServerName: override}
				c, err := conn.build(cfg)
				require.NoError(t, err)
				_, err = mysqldriver.NewConnector(c)
				require.NoError(t, err, "the driver must accept the configuration")

				tlsConfig, _ := driverTLS(t, c)
				require.NotNil(t, tlsConfig, "the connection is TLS")
				assert.Equal(t, []tls.Certificate{pair}, tlsConfig.Certificates, "the connection presents the pair")
				assert.Equal(t, override, tlsConfig.ServerName, "the TLS configuration names the override")

				if tt.mode == data.TLSVerifyFull {
					require.NoError(t, tlstest.Handshake(t, tlsConfig, forOverride),
						"a certificate naming the override is accepted")
					require.Error(t, tlstest.Handshake(t, tlsConfig, forDialled),
						"a certificate naming the host dialled is refused")
				}
			})
		}
	}
}
