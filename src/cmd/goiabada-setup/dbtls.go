package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// tlsMode is one of the five values of GOIABADA_DB_TLS_MODE, which the auth server reads as libpq
// reads sslmode, the same on PostgreSQL, MySQL and SQL Server (#502 decision 2), with the line the
// menu and the generated files say it in.
type tlsMode struct {
	name        string
	description string
}

// tlsModes is the TLS mode menu, in its order, from the mode that protects least to the one that
// protects most; the auth server's own list, data.TLSModes, which this module may not import.
var tlsModes = []tlsMode{
	{"disable", "never encrypted, even when the database offers TLS; on SQL Server the login travels in the clear too"},
	{"prefer", "encrypted when the database offers TLS, plain text when it offers none; no certificate is checked"},
	{"require", "always encrypted, and a database offering no TLS is refused; no certificate is checked"},
	{"verify-ca", "require, and the certificate must chain to an authority you trust; its host name is not checked"},
	{"verify-full", "verify-ca, and the certificate must name the host the auth server connects to"},
}

// verifyFullOverrideMenuNote is what the menu adds to verify-full's line, which is asked before the
// host name override: the certificate may name the override instead of the host dialled (#546).
const verifyFullOverrideMenuNote = ", or the host name you give after it"

// verifyFullOverrideDescription is verify-full's line in a generated file that also writes
// GOIABADA_DB_TLS_SERVER_NAME, whose name the certificate must carry instead of the host dialled
// (#546).
const verifyFullOverrideDescription = "verify-ca, and the certificate must name GOIABADA_DB_TLS_SERVER_NAME rather than GOIABADA_DB_HOST"

// defaultTLSMode is the mode the auth server takes when none is set, and the one the wizard offers
// and writes on Compose: what it did before the setting existed (#502 decision 1).
const defaultTLSMode = "prefer"

func tlsModeNames() []string {
	names := make([]string, 0, len(tlsModes))
	for _, m := range tlsModes {
		names = append(names, m.name)
	}
	return names
}

// knownTLSMode reports whether name is one of the five, spelled exactly, as the auth server
// accepts it: no case folding and no driver's alias.
func knownTLSMode(name string) bool {
	return slices.Contains(tlsModeNames(), name)
}

// checksCertificate reports whether the mode checks the database's certificate, which is what a
// CA file is read for: verify-ca and verify-full.
func checksCertificate(mode string) bool {
	return mode == "verify-ca" || mode == "verify-full"
}

// mssqlPreferDescription is prefer on SQL Server, where it encrypts the login and leaves the rest of
// the session to the database, rather than following the database's offer of TLS (#502 decision 2).
const mssqlPreferDescription = "the login encrypted, and the rest only when the database forces encryption; no certificate is checked"

// describedFor is the line the mode is described by to an operator of the engine named.
func (m tlsMode) describedFor(engineName string) string {
	if m.name == "prefer" && engineName == "mssql" {
		return mssqlPreferDescription
	}
	return m.description
}

// tlsModeDescription is the line the mode is described by to an operator of the engine named.
func tlsModeDescription(name, engineName string) string {
	for _, m := range tlsModes {
		if m.name == name {
			return m.describedFor(engineName)
		}
	}
	return ""
}

// readCAFile reads the CA file at path as the auth server reads GOIABADA_DB_TLS_CA_FILE, and
// refuses it as the server would, a file that cannot be read and one that holds no PEM certificate
// (#502 decision 4). It returns the path made absolute, since the auth server starts from wherever
// its service runs, and the certificates the file holds, as PEM, and nothing else: a private key
// beside them in a bundle never reaches the ConfigMap the Kubernetes manifest carries them in.
func readCAFile(path string) (absolute, certificates string, err error) {
	absolute, err = filepath.Abs(path)
	if err != nil {
		return "", "", errs.Wrapf(err, "unable to resolve the CA file %s", strconv.Quote(path))
	}
	if unwritable := checkWritable(absolute); unwritable != nil {
		return "", "", errs.Wrapf(unwritable, "the CA file %s cannot be written to the configuration", strconv.Quote(absolute))
	}
	content, err := os.ReadFile(absolute) //nolint:gosec // G304: the operator names the CA file their database's certificate chains to
	if err != nil {
		// The cause alone: the path is quoted beside it, and the error repeats it unquoted.
		reason := err.Error()
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			reason = pathErr.Err.Error()
		}
		return "", "", errs.Errorf("the CA file %s cannot be read: %s", strconv.Quote(absolute), reason)
	}
	var sb strings.Builder
	for block, rest := pem.Decode(content); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		if _, unparsable := x509.ParseCertificate(block.Bytes); unparsable != nil {
			continue
		}
		sb.Write(pem.EncodeToMemory(block))
	}
	if sb.Len() == 0 {
		return "", "", errs.Errorf("the CA file %s holds no PEM certificate", strconv.Quote(absolute))
	}
	return absolute, sb.String(), nil
}

// tlsRoots is the pool of the certificates a CA file held, nil for none, which is the system's
// roots.
func tlsRoots(certificates string) *x509.CertPool {
	if certificates == "" {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(certificates))
	return roots
}

// carriesClientCertificate reports whether the mode presents a client certificate pair to the
// database: the three modes that always ask for TLS, require, verify-ca and verify-full. The auth
// server refuses the pair beside disable and prefer, which may send none (#546).
func carriesClientCertificate(mode string) bool {
	return mode == "require" || checksCertificate(mode)
}

// checksHostName reports whether the mode checks the certificate's host name: verify-full alone.
// The auth server refuses a host name override beside any other mode (#546).
func checksHostName(mode string) bool {
	return mode == "verify-full"
}

// cannotBeRead is os.ReadFile's error with the path stripped out of it, the path being quoted
// beside it in the refusal: the cause alone, as the auth server takes it (#546).
func cannotBeRead(err error) string {
	reason := err.Error()
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		reason = pathErr.Err.Error()
	}
	return reason
}

// clientCertificate is the pair the operator named, as the wizard carries it: the two absolute
// paths, which native binaries write into the env file and the summary prints, and the two files'
// contents, as PEM, which the Kubernetes Secret is written from. The pair is not parsed here: the
// connection check parses it again, as the auth server's load does (#546).
type clientCertificate struct {
	certFile string
	keyFile  string
	certPEM  string
	keyPEM   string
}

// readClientCertificate reads the certificate and key files as the auth server reads
// GOIABADA_DB_TLS_CLIENT_CERT_FILE and GOIABADA_DB_TLS_CLIENT_KEY_FILE, and refuses a pair as the
// server would, in the server's own words: one file named without the other, either that cannot
// be read, a key encrypted with a passphrase, and two that do not pair (#546). It returns both paths made absolute, since the auth
// server starts from wherever its service runs.
func readClientCertificate(certPath, keyPath string) (clientCertificate, error) {
	if certPath == "" || keyPath == "" {
		half, other := "GOIABADA_DB_TLS_CLIENT_CERT_FILE (--db-tls-client-cert-file)",
			"GOIABADA_DB_TLS_CLIENT_KEY_FILE (--db-tls-client-key-file)"
		named := certPath
		if named == "" {
			half, other = other, half
			named = keyPath
		}
		return clientCertificate{}, errs.Errorf("%s is %s without %s: name both or neither",
			half, strconv.Quote(named), other)
	}
	certFile, err := filepath.Abs(certPath)
	if err != nil {
		return clientCertificate{}, errs.Wrapf(err, "unable to resolve the client certificate %s", strconv.Quote(certPath))
	}
	keyFile, err := filepath.Abs(keyPath)
	if err != nil {
		return clientCertificate{}, errs.Wrapf(err, "unable to resolve the client key %s", strconv.Quote(keyPath))
	}
	if err = checkWritable(certFile); err != nil {
		return clientCertificate{}, errs.Wrapf(err, "the client certificate %s cannot be written to the configuration",
			strconv.Quote(certFile))
	}
	if err = checkWritable(keyFile); err != nil {
		return clientCertificate{}, errs.Wrapf(err, "the client key %s cannot be written to the configuration",
			strconv.Quote(keyFile))
	}
	certPEM, err := os.ReadFile(certFile) //nolint:gosec // G304: the operator names the certificate their database reads
	if err != nil {
		return clientCertificate{}, errs.Errorf("GOIABADA_DB_TLS_CLIENT_CERT_FILE (--db-tls-client-cert-file) is %s, which cannot be read: %s",
			strconv.Quote(certFile), cannotBeRead(err))
	}
	keyPEM, err := os.ReadFile(keyFile) //nolint:gosec // G304: the operator names the key their database reads
	if err != nil {
		return clientCertificate{}, errs.Errorf("GOIABADA_DB_TLS_CLIENT_KEY_FILE (--db-tls-client-key-file) is %s, which cannot be read: %s",
			strconv.Quote(keyFile), cannotBeRead(err))
	}
	if keyIsEncrypted(keyPEM) {
		return clientCertificate{}, errs.Errorf("GOIABADA_DB_TLS_CLIENT_KEY_FILE (--db-tls-client-key-file) is %s, "+
			"which is encrypted with a passphrase the auth server cannot read: write a copy without one", strconv.Quote(keyFile))
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return clientCertificate{}, errs.Errorf("GOIABADA_DB_TLS_CLIENT_CERT_FILE (--db-tls-client-cert-file) is %s and "+
			"GOIABADA_DB_TLS_CLIENT_KEY_FILE (--db-tls-client-key-file) is %s, which do not pair: %s",
			strconv.Quote(certFile), strconv.Quote(keyFile), err.Error())
	}
	return clientCertificate{certFile: certFile, keyFile: keyFile, certPEM: string(certPEM), keyPEM: string(keyPEM)}, nil
}

// keyIsEncrypted is the auth server's check of the same name, which this module may not import
// (ARCHITECTURE.md rule 3): an encrypted private key, PKCS #8's ENCRYPTED PRIVATE KEY block or a
// legacy block whose Proc-Type header says ENCRYPTED, which tls.X509KeyPair refuses only as a key
// it cannot parse.
func keyIsEncrypted(keyPEM []byte) bool {
	for rest := keyPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return false
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			return true
		}
	}
}

// verifyChainOnly is the auth server's data.VerifyChainOnly, which this module may not import
// (ARCHITECTURE.md rule 3): verify-ca's check for a driver that has none of its own. The server's
// certificate chain must lead to roots, nil meaning the system's roots, and the host name is not
// checked (#502 decision 2). It is installed as the TLS configuration's VerifyConnection beside
// InsecureSkipVerify, which turns off the library's own check, host name included.
func verifyChainOnly(roots *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errs.New("the database server presented no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		// No DNSName, so no host name is checked; KeyUsages left empty means a server certificate.
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
		if err != nil {
			return errs.Wrap(err, "unable to verify the database server's certificate chain")
		}
		return nil
	}
}
