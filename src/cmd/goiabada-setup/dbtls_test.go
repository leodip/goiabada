package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
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
