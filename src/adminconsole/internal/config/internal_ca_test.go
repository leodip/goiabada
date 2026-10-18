package config

// The internal CA file's reading by Load, held to the auth server's database CA file's rules
// (#502): read once, refused at once as a malformed value, and the authorities it holds trusted
// beside the system's roots rather than in their place (#525). The console's clients, not this
// package, hold the beside-not-in-place-of half over the wire, in cmd/goiabada-adminconsole's
// internal_ca_test.

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
	"testing"
	"time"
)

// newInternalTestAuthority is a self-signed CA certificate and its key, for a file the setting
// can name and a leaf the pool it builds must verify.
func newInternalTestAuthority(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the authority's key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the authority's certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the authority's certificate: %v", err)
	}
	return cert, key
}

// newInternalTestLeaf is a certificate the authority signs, with no name of its own, so
// Verify checks the chain alone.
func newInternalTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the leaf's key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating the leaf's certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the leaf's certificate: %v", err)
	}
	return cert
}

// writeInternalTestCA writes ca as the PEM file the setting names.
func writeInternalTestCA(t *testing.T, ca *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "internal-ca.pem")
	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("writing the CA file: %v", err)
	}
	return path
}

func TestLoad_InternalCAFileUnsetReadsNoPool(t *testing.T) {
	_, c := loadMatrix(t, nil, nil)

	if c.AdminConsole.InternalRoots != nil {
		t.Errorf("Load() with no CA file read a pool, want none, so every client keeps the system roots")
	}
}

// TestLoad_ReadsTheInternalCAFileAndTrustsTheCAItNames is the file read by Load, whichever of the
// variable and the flag names it: the flag is parsed before the file is read, so the file the flag
// names is the one trusted.
func TestLoad_ReadsTheInternalCAFileAndTrustsTheCAItNames(t *testing.T) {
	ca, caKey := newInternalTestAuthority(t, "the CA the file names")
	leaf := newInternalTestLeaf(t, ca, caKey)
	caFile := writeInternalTestCA(t, ca)

	tests := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"named by the variable", map[string]string{"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE": caFile}, nil},
		{"named by the flag", nil, []string{"-adminconsole-internal-ca-file=" + caFile}},
		{"named by the flag over a variable naming another file",
			map[string]string{"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE": "testdata/internal-ca-env.pem"},
			[]string{"-adminconsole-internal-ca-file=" + caFile}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := loadMatrix(t, tt.env, tt.args)

			roots := c.AdminConsole.InternalRoots
			if roots == nil {
				t.Fatal("Load() read no pool, so no client can verify against it")
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
				t.Errorf("the CA the file names does not verify its leaf against the pool: %v", err)
			}
		})
	}
}

// TestLoad_RefusesAnInternalCAFileItCannotBuildAPoolFrom is the auth server's database CA file's
// refusals, under this process's own variable names (#502): a file that is not there, a
// directory, a file holding no PEM block, and a PEM file holding a key and no certificate. Each is
// a malformed value, so Load answers it as one line and no configuration, which main writes to
// stderr and exits 2 on, as it does for every other malformed setting (#525).
func TestLoad_RefusesAnInternalCAFileItCannotBuildAPoolFrom(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	notPEM := filepath.Join(t.TempDir(), "ca.der")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatalf("writing the file holding no PEM block: %v", err)
	}
	keyOnly := filepath.Join(t.TempDir(), "key.pem")
	keyContents := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if err := os.WriteFile(keyOnly, keyContents, 0o600); err != nil {
		t.Fatalf("writing the file holding a key and no certificate: %v", err)
	}
	directory := t.TempDir()

	const setting = "GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE (--adminconsole-internal-ca-file) is "
	tests := []struct {
		name string
		path string
		want string
	}{
		{"a file that is not there", missing, setting + `"` + missing + `", which cannot be read: no such file or directory`},
		{"a directory", directory, setting + `"` + directory + `", which cannot be read: is a directory`},
		{"a file holding no PEM block", notPEM, setting + `"` + notPEM + `", which holds no PEM certificate`},
		{"a PEM file holding a key and no certificate", keyOnly, setting + `"` + keyOnly + `", which holds no PEM certificate`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, source := range []struct {
				name string
				env  map[string]string
				args []string
			}{
				{"the variable", map[string]string{"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE": tt.path}, nil},
				{"the flag", nil, []string{"-adminconsole-internal-ca-file=" + tt.path}},
			} {
				t.Run(source.name, func(t *testing.T) {
					_, c, err := loadMatrixRefusing(t, source.env, source.args)

					want := "malformed configuration: " + tt.want
					if err == nil || err.Error() != want {
						t.Errorf("Load() = %v, want %q", err, want)
					}
					if c != nil {
						t.Errorf("Load() refused and still answered a configuration: %+v", c)
					}
				})
			}
		})
	}
}

// TestLoad_NamesTheInternalCAFileBesideEveryMalformedVariable: the file is refused on the same
// line as a malformed number, so an operator with both wrong hears about both on one start.
func TestLoad_NamesTheInternalCAFileBesideEveryMalformedVariable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	_, _, err := loadMatrixRefusing(t, map[string]string{
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP": "90 91",
		"GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE": missing,
	}, nil)

	want := `malformed configuration: GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP is "90 91", not an integer; ` +
		`GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE (--adminconsole-internal-ca-file) is "` + missing +
		`", which cannot be read: no such file or directory`
	if err == nil || err.Error() != want {
		t.Errorf("Load() = %v, want %q", err, want)
	}
}
