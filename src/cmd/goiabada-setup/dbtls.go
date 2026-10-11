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

// tlsModeDescription is the line the mode is described by.
func tlsModeDescription(name string) string {
	for _, m := range tlsModes {
		if m.name == name {
			return m.description
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
