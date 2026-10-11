// Package tlstest makes the certificate authorities and server certificates the engines' TLS tests
// observe a connection's configuration against, and runs the handshake that observes it. Test
// support, compiled into no binary (#502).
package tlstest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Authority is a certificate authority made for one test.
type Authority struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// PEM is Cert as a CA file holds it.
	PEM []byte
}

// NewAuthority makes a self-signed root authority called name.
func NewAuthority(t *testing.T, name string) Authority {
	t.Helper()
	return newAuthority(t, name, nil)
}

// Intermediate makes an authority called name that a signs, so a server certificate it issues
// verifies against a only with the intermediate presented beside it.
func (a Authority) Intermediate(t *testing.T, name string) Authority {
	t.Helper()
	return newAuthority(t, name, &a)
}

func newAuthority(t *testing.T, name string, parent *Authority) Authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.Cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return Authority{Cert: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Pool is a pool holding a alone, which is what a CA file naming it is read into.
func (a Authority) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.Cert)
	return p
}

// Issue signs a server certificate naming host, as an IP address when host is an IP literal and as
// a DNS name otherwise.
func (a Authority) Issue(t *testing.T, host string) tls.Certificate {
	t.Helper()
	return a.issue(t, host, x509.ExtKeyUsageServerAuth)
}

// IssueWithCommonName signs a server certificate naming host, as Issue does, whose subject's common
// name is commonName: a name only a check reading the legacy common name would accept.
func (a Authority) IssueWithCommonName(t *testing.T, commonName, host string) tls.Certificate {
	t.Helper()
	return a.issueNamed(t, commonName, host, x509.ExtKeyUsageServerAuth)
}

// IssueClient signs a client certificate naming user.
func (a Authority) IssueClient(t *testing.T, user string) tls.Certificate {
	t.Helper()
	return a.issue(t, user, x509.ExtKeyUsageClientAuth)
}

func (a Authority) issue(t *testing.T, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	return a.issueNamed(t, name, name, usage)
}

func (a Authority) issueNamed(t *testing.T, commonName, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.Cert, &key.PublicKey, a.key)
	require.NoError(t, err)
	chain := [][]byte{der}
	// An intermediate presents itself beside what it issues, as a server configured with it does.
	if a.Cert.Subject.String() != a.Cert.Issuer.String() {
		chain = append(chain, a.Cert.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key}
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)
	return n
}

// Handshake runs a TLS handshake from client to a server presenting serverCert, and answers the
// client's error, nil when the client accepted the server. Over loopback TCP rather than net.Pipe:
// a client refusing the certificate writes its alert while the server is still writing its flight,
// which an unbuffered pipe holds until the deadline.
func Handshake(t *testing.T, client *tls.Config, serverCert tls.Certificate) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
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
	require.NoError(t, err)
	err = tls.Client(conn, client).HandshakeContext(ctx)
	_ = conn.Close()
	<-served
	return err
}
