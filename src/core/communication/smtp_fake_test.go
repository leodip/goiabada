package communication

// An in-process SMTP server for the EmailSender table. It exists because the dev container's
// mailpit offers exactly one shape -- no encryption, no authentication -- so the three encryption
// modes, the three authentication mechanisms, the fail-closed refusals and the bytes on the wire
// are unreachable without it. Grown from docs/issue-274-retire-go-simple-mail/probe/wire_probe_test.go.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The CRAM-MD5 challenge the fake always issues. Fixed so a failed digest is a failed digest and
// not a flake.
const fakeCRAMChallenge = "<1234.5678@fake.example.com>"

type fakeSMTP struct {
	// ext is the EHLO extension list before any TLS handshake, tlsExt the one after it. Each
	// entry is a whole extension line, e.g. "AUTH PLAIN LOGIN".
	ext    []string
	tlsExt []string

	// tlsFromStart makes the listener speak TLS immediately, which is the ssltls mode.
	tlsFromStart bool
	// stallAfterData swallows the DATA block and never answers its terminator, so the client has
	// to reach its own deadline.
	stallAfterData bool

	// expectPassword is the password CRAM-MD5 digests are verified against; the other mechanisms
	// send it and it is recorded in authPass instead.
	expectPassword string

	cert *fakeCert

	mu        sync.Mutex
	log       []string
	dataRaw   string
	authUser  string
	authPass  string
	connected bool
	conn      net.Conn
}

func (f *fakeSMTP) record(line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, line)
}

// lines returns every line the client sent, including the authentication responses.
func (f *fakeSMTP) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

// data returns the DATA block exactly as it arrived, dot-stuffing included.
func (f *fakeSMTP) data() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dataRaw
}

func (f *fakeSMTP) credentials() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authUser, f.authPass
}

func (f *fakeSMTP) sawConnection() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connected
}

// hasLinePrefix reports whether any recorded line starts with the given SMTP verb.
func (f *fakeSMTP) hasLinePrefix(prefix string) bool {
	for _, l := range f.lines() {
		if strings.HasPrefix(strings.ToUpper(l), strings.ToUpper(prefix)) {
			return true
		}
	}
	return false
}

// indexOfLinePrefix returns the position of the first line starting with the given verb, or -1.
// The order assertions for decision 2 read AUTH and MAIL against STARTTLS through this.
func (f *fakeSMTP) indexOfLinePrefix(prefix string) int {
	for i, l := range f.lines() {
		if strings.HasPrefix(strings.ToUpper(l), strings.ToUpper(prefix)) {
			return i
		}
	}
	return -1
}

func (f *fakeSMTP) serverTLSConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{f.cert.cert}}
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	ext := f.ext
	if f.tlsFromStart {
		tc := tls.Server(conn, f.serverTLSConfig())
		if err := tc.Handshake(); err != nil {
			return
		}
		conn = tc
		ext = f.tlsExt
	}

	r := bufio.NewReader(conn)
	var w io.Writer = conn
	say := func(s string) { _, _ = fmt.Fprint(w, s+"\r\n") }

	say("220 fake ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.record(line)
		up := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			if len(ext) == 0 {
				say("250 fake greets you")
				continue
			}
			say("250-fake greets you")
			for i, e := range ext {
				if i == len(ext)-1 {
					say("250 " + e)
				} else {
					say("250-" + e)
				}
			}

		case up == "STARTTLS":
			if !extensionOffered(ext, "STARTTLS") {
				say("502 command not implemented")
				continue
			}
			say("220 ready to start TLS")
			tc := tls.Server(conn, f.serverTLSConfig())
			if err := tc.Handshake(); err != nil {
				return
			}
			// RFC 3207 section 4.2: the client re-issues EHLO and everything it learned before
			// the handshake is discarded, so the post-TLS list takes over here.
			r = bufio.NewReader(tc)
			w = tc
			ext = f.tlsExt

		case strings.HasPrefix(up, "AUTH PLAIN"):
			payload := strings.TrimSpace(line[len("AUTH PLAIN"):])
			if payload == "" {
				// The challenge form. net/smtp.PlainAuth sends the inline form, so this arm is
				// here for completeness rather than for a row.
				say("334 ")
				next, err := r.ReadString('\n')
				if err != nil {
					return
				}
				payload = strings.TrimRight(next, "\r\n")
				f.record(payload)
			}
			raw, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				say("535 malformed PLAIN response")
				continue
			}
			// RFC 4616: authzid NUL authcid NUL passwd.
			parts := strings.Split(string(raw), "\x00")
			if len(parts) != 3 {
				say("535 malformed PLAIN response")
				continue
			}
			f.mu.Lock()
			f.authUser, f.authPass = parts[1], parts[2]
			f.mu.Unlock()
			say("235 2.7.0 authentication succeeded")

		case up == "AUTH LOGIN":
			say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			user, err := f.readBase64Line(r)
			if err != nil {
				return
			}
			say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			pass, err := f.readBase64Line(r)
			if err != nil {
				return
			}
			f.mu.Lock()
			f.authUser, f.authPass = user, pass
			f.mu.Unlock()
			say("235 2.7.0 authentication succeeded")

		case up == "AUTH CRAM-MD5":
			say("334 " + base64.StdEncoding.EncodeToString([]byte(fakeCRAMChallenge)))
			answer, err := f.readBase64Line(r)
			if err != nil {
				return
			}
			user, digest, found := strings.Cut(answer, " ")
			mac := hmac.New(md5.New, []byte(f.expectPassword))
			mac.Write([]byte(fakeCRAMChallenge))
			want := hex.EncodeToString(mac.Sum(nil))
			if !found || digest != want {
				say("535 5.7.8 authentication failed")
				continue
			}
			f.mu.Lock()
			f.authUser = user
			f.mu.Unlock()
			say("235 2.7.0 authentication succeeded")

		case strings.HasPrefix(up, "DATA"):
			say("354 end data with <CR><LF>.<CR><LF>")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.dataRaw = b.String()
			f.mu.Unlock()
			if f.stallAfterData {
				// Never answer the terminator. The client blocks on the reply until its
				// conversation deadline expires and closes the connection, which ends this read.
				_, _ = io.Copy(io.Discard, r)
				return
			}
			say("250 2.0.0 queued")

		case strings.HasPrefix(up, "QUIT"):
			say("221 2.0.0 bye")
			return

		default:
			say("250 2.0.0 ok")
		}
	}
}

func (f *fakeSMTP) readBase64Line(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	f.record(line)
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func extensionOffered(ext []string, name string) bool {
	for _, e := range ext {
		fields := strings.Fields(e)
		if len(fields) > 0 && strings.EqualFold(fields[0], name) {
			return true
		}
	}
	return false
}

// start binds the fake to an ephemeral port on every interface, because the rows for decision 1
// reach it through os.Hostname(), which inside a container is the non-loopback address
// (probe/hostname.out). It serves exactly one connection.
func (f *fakeSMTP) start(t *testing.T) int {
	t.Helper()

	// Only the TLS rows need a certificate, and generating one reaches for this machine's
	// hostname, which a cleartext row has no business depending on.
	if f.cert == nil && (f.tlsFromStart || extensionOffered(f.ext, "STARTTLS")) {
		f.cert = newFakeCert(t)
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("unable to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.connected = true
		f.conn = conn
		f.mu.Unlock()
		f.serve(conn)
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		f.mu.Lock()
		conn := f.conn
		f.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		<-done
	})

	return ln.Addr().(*net.TCPAddr).Port
}

// fakeCert is a self-signed certificate that is its own root, so a test can hand its pool to
// EmailSender.rootCAs and leave verification on.
type fakeCert struct {
	cert tls.Certificate
	pool *x509.CertPool
}

// newFakeCert generates one at test time. The SANs are 127.0.0.1, ::1 and this machine's
// hostname, and deliberately not "localhost": a row that addresses the fake as localhost then
// reaches a trusted chain whose names do not match, which is the only way to tell hostname
// verification apart from chain verification.
func newFakeCert(t *testing.T) *fakeCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate a key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("unable to generate a serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "goiabada fake SMTP"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{fakeHostname(t)},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("unable to create the certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("unable to parse the certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return &fakeCert{
		cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		pool: pool,
	}
}

// fakeHostname is this machine's name, which the decision 1 rows use as a host that is not
// loopback. In the dev container and in CI's job containers it is the container id and resolves to
// the container's own non-loopback address (probe/hostname.out).
func fakeHostname(t *testing.T) string {
	t.Helper()
	name, err := os.Hostname()
	if err != nil || name == "" || strings.EqualFold(name, "localhost") {
		t.Skipf("this machine's hostname is %q, so it cannot stand in for a non-loopback SMTP host", name)
	}
	return name
}
