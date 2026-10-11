package main

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/leodip/goiabada/core/errs"
)

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
