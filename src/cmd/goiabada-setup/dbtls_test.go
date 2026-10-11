package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The wizard's MySQL connection carries a TLS configuration of its own for the two verifying modes,
// as the auth server's does (#502), so what each mode accepts is observed here as a TLS handshake
// against a server presenting a certificate made in the test.

// TestMysqlConnection_EveryModeChecksWhatItSays holds each mode's configuration, for both of the
// check's connections, to decision 2 of #502: which certificates it accepts, and whether a server
// offering no TLS is reached in plain text, which only prefer does.
func TestMysqlConnection_EveryModeChecksWhatItSays(t *testing.T) {
	const host = "db.example.com"
	ours := newTestAuthority(t, "ours")
	theirs := newTestAuthority(t, "theirs")

	oursForDB := ours.issue(t, host)
	oursOther := ours.issue(t, "other.example.com")
	theirsForDB := theirs.issue(t, host)

	type accepts struct{ oursForDB, oursOther, theirs bool }
	all := accepts{true, true, true}
	tests := []struct {
		mode      string
		roots     *x509.CertPool
		encrypted bool
		fallback  bool
		accepts   accepts
	}{
		{mode: "disable"},
		{mode: "", encrypted: true, fallback: true, accepts: all},
		{mode: "prefer", encrypted: true, fallback: true, accepts: all},
		{mode: "require", encrypted: true, accepts: all},
		{mode: "verify-ca", roots: ours.pool(), encrypted: true, accepts: accepts{oursForDB: true, oursOther: true}},
		{mode: "verify-full", roots: ours.pool(), encrypted: true, accepts: accepts{oursForDB: true}},
		{mode: "verify-ca", encrypted: true},
		{mode: "verify-full", encrypted: true},
	}
	for _, tt := range tests {
		target := dbTarget{Host: host, Port: 3306, Username: "goiabada", Password: "pw", Name: "goiabada",
			TLSMode: tt.mode, TLSRoots: tt.roots}
		for which, connection := range map[string]func(dbTarget) (dbConnection, error){
			"connection": mysqlConnection, "maintenance connection": mysqlMaintenanceConnection,
		} {
			name := "mode " + tt.mode + "/" + which
			if tt.roots == nil && (tt.mode == "verify-ca" || tt.mode == "verify-full") {
				name += " with the system's roots"
			}
			t.Run(name, func(t *testing.T) {
				tlsConfig, fallback := mysqlDriverTLS(t, build(t, which, connection, target).mysql)
				if !tt.encrypted {
					if tlsConfig != nil {
						t.Fatal("disable carries a TLS configuration")
					}
					return
				}
				if tlsConfig == nil {
					t.Fatal("no TLS configuration")
				}
				if fallback != tt.fallback {
					t.Errorf("falls back to plain text: %v, want %v", fallback, tt.fallback)
				}
				for _, server := range []struct {
					name   string
					cert   tls.Certificate
					accept bool
				}{
					{"our authority's certificate for the host dialled", oursForDB, tt.accepts.oursForDB},
					{"our authority's certificate for another host", oursOther, tt.accepts.oursOther},
					{"another authority's certificate for the host dialled", theirsForDB, tt.accepts.theirs},
				} {
					err := testHandshake(t, tlsConfig, server.cert)
					if server.accept && err != nil {
						t.Errorf("%s is refused: %v", server.name, err)
					}
					if !server.accept && err == nil {
						t.Errorf("%s is accepted", server.name)
					}
				}
			})
		}
	}
}

// TestVerifyChainOnly_ChecksTheChainAndNotTheHost holds verify-ca's check, the copy of the auth
// server's data.VerifyChainOnly, to #502 decision 2: the server's certificate chain must lead to
// the roots, and the host name is not checked.
func TestVerifyChainOnly_ChecksTheChainAndNotTheHost(t *testing.T) {
	const host = "db.example.com"
	ours := newTestAuthority(t, "ours")
	theirs := newTestAuthority(t, "theirs")

	tests := []struct {
		name   string
		roots  *x509.CertPool
		server tls.Certificate
		accept bool
	}{
		{"our authority's certificate for the host dialled", ours.pool(), ours.issue(t, host), true},
		{"our authority's certificate for another host", ours.pool(), ours.issue(t, "other.example.com"), true},
		{"our authority's certificate for an IP address", ours.pool(), ours.issue(t, "192.0.2.10"), true},
		{"another authority's certificate for the host dialled", ours.pool(), theirs.issue(t, host), false},
		{"our authority's certificate, with the system's roots", nil, ours.issue(t, host), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
				// The library's own verification off, which the check under test replaces.
				InsecureSkipVerify: true,
				VerifyConnection:   verifyChainOnly(tt.roots),
			}

			err := testHandshake(t, client, tt.server)

			if tt.accept {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var unknown x509.UnknownAuthorityError
			if !errors.As(err, &unknown) {
				t.Fatalf("want the certificate's authority refused, got %v", err)
			}
		})
	}
	if verifyChainOnly(ours.pool())(tls.ConnectionState{}) == nil {
		t.Error("a handshake reaching the check with no certificate is accepted")
	}
}

// testAuthority is a certificate authority made for one test.
type testAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestAuthority(t *testing.T, name string) testAuthority {
	t.Helper()
	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testAuthority{cert: cert, key: key}
}

func (a testAuthority) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.cert)
	return p
}

// issue signs a server certificate naming host, as an IP address when host is an IP literal and
// as a DNS name otherwise.
func (a testAuthority) issue(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testHandshake runs a TLS handshake from client to a server presenting serverCert over loopback
// TCP, and answers the client's error, nil when the client accepted the server.
func testHandshake(t *testing.T, client *tls.Config, serverCert tls.Certificate) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12})
		_ = server.HandshakeContext(ctx)
		_ = conn.Close()
	}()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	err = tls.Client(conn, client).HandshakeContext(ctx)
	_ = conn.Close()
	<-served
	return err
}

// TestPreferDescription_SaysWhatSQLServerEncrypts: what the wizard says prefer encrypts, in the
// menu and the files it writes, holds on SQL Server too, where prefer encrypts the login, and the
// rest of the session only when the database forces encryption (#502 decision 2). Each is written
// for the one engine chosen, so only SQL Server's says so, and the other engines' keep saying what
// prefer encrypts for them.
func TestPreferDescription_SaysWhatSQLServerEncrypts(t *testing.T) {
	for _, word := range []string{"login", "forces encryption"} {
		if described := tlsModeDescription("prefer", "mssql"); !strings.Contains(described, word) {
			t.Errorf("SQL Server's prefer does not say %q: %s", word, described)
		}
	}
	for _, engine := range []string{"postgres", "mysql"} {
		if described := tlsModeDescription("prefer", engine); !strings.Contains(described, "when the database offers TLS") {
			t.Errorf("%s's prefer no longer says what it encrypts: %s", engine, described)
		}
	}

	composeComment := func(engine string) string {
		t.Helper()
		service := generateAuthServerService(goldenConfig(deploymentLocal, engine))
		start := strings.Index(service, "      # The database is a service")
		end := strings.Index(service, "GOIABADA_DB_TLS_MODE=")
		if start < 0 || end < start {
			t.Fatalf("no database TLS comment in the %s Compose service:\n%s", engine, service)
		}
		return service[start:end]
	}
	for _, word := range []string{"login", "forces"} {
		if comment := composeComment("mssql"); !strings.Contains(comment, word) {
			t.Errorf("SQL Server's Compose comment does not say %q:\n%s", word, comment)
		}
	}
	for _, engine := range []string{"postgres", "mysql"} {
		if comment := composeComment(engine); !strings.Contains(comment, "when the database offers TLS") {
			t.Errorf("%s's Compose comment no longer says what prefer encrypts:\n%s", engine, comment)
		}
	}
}

// TestOpenSQL_PreferAsksForTLSOnEveryConnection: in prefer, a connection that met a server offering
// no TLS and went on in plain text leaves the next connection asking for TLS again, as the auth
// server's does, for both of the check's connections. The driver's fallback clears the TLS of the
// configuration the connection was handed, and without a copy per connection that was the
// connector's own (#502).
func TestOpenSQL_PreferAsksForTLSOnEveryConnection(t *testing.T) {
	server := newGreetingServer(t)
	target := dbTarget{Host: "127.0.0.1", Port: server.port, Username: "goiabada", Password: "pw", Name: "goiabada",
		TLSMode: "prefer"}
	for which, connection := range map[string]func(dbTarget) (dbConnection, error){
		"connection": mysqlConnection, "maintenance connection": mysqlMaintenanceConnection,
	} {
		t.Run(which, func(t *testing.T) {
			db, err := openSQL(build(t, which, connection, target))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			for _, phase := range []struct {
				offerTLS bool
				what     string
			}{
				{false, "a server offering no TLS is answered in plain text"},
				{true, "the next connection asks for TLS again"},
			} {
				server.offerTLS.Store(phase.offerTLS)
				if db.PingContext(ctx) == nil {
					t.Fatal("the server hangs up after the client's first answer, yet the ping succeeded")
				}
				asked := server.answers()
				if len(asked) == 0 {
					t.Fatal("no connection reached the server")
				}
				if slices.Contains(asked, !phase.offerTLS) {
					t.Errorf("%s: asked for TLS %v", phase.what, asked)
				}
			}
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
// answer, records whether it asks for TLS, and hangs up. A copy of the auth server's in mysqldb's
// dsn_tls_test.go, which this module may not import.
type greetingServer struct {
	port     int
	offerTLS atomic.Bool
	asked    chan bool
}

func newGreetingServer(t *testing.T) *greetingServer {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listening on %v, not TCP", listener.Addr())
	}
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
