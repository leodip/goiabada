package data_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/tlstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyChainOnly_ChecksTheChainAndNotTheHost holds verify-ca's check, for the drivers that
// have none of their own, to #502 decision 2: the server's certificate chain must lead to the roots,
// and the host name is not checked. Each case is a real handshake against a chain made in the test,
// with the driver's own verification off, as the check is installed.
func TestVerifyChainOnly_ChecksTheChainAndNotTheHost(t *testing.T) {
	const host = "db.example.com"
	ours := tlstest.NewAuthority(t, "ours")
	theirs := tlstest.NewAuthority(t, "theirs")
	oursIntermediate := ours.Intermediate(t, "ours, intermediate")

	tests := []struct {
		name   string
		roots  *x509.CertPool
		server tls.Certificate
		accept bool
	}{
		{"our authority's certificate for the host dialled", ours.Pool(), ours.Issue(t, host), true},
		{"our authority's certificate for another host", ours.Pool(), ours.Issue(t, "other.example.com"), true},
		{"our authority's certificate for an IP address", ours.Pool(), ours.Issue(t, "192.0.2.10"), true},
		{"our intermediate's certificate, the intermediate presented", ours.Pool(), oursIntermediate.Issue(t, host), true},
		{"another authority's certificate for the host dialled", ours.Pool(), theirs.Issue(t, host), false},
		{"our authority's client certificate", ours.Pool(), ours.IssueClient(t, host), false},
		{"our authority's certificate, with the system's roots", nil, ours.Issue(t, host), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
				// The driver's own verification off, which the check under test replaces.
				InsecureSkipVerify: true,
				VerifyConnection:   data.VerifyChainOnly(tt.roots),
			}

			err := tlstest.Handshake(t, client, tt.server)

			if tt.accept {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var unknown x509.UnknownAuthorityError
			var invalid x509.CertificateInvalidError
			assert.True(t, errors.As(err, &unknown) || errors.As(err, &invalid),
				"the refusal is the certificate's own, not some other failure: %v", err)
		})
	}
}

// TestVerifyChainOnly_RefusesAServerPresentingNothing: a handshake that somehow reaches the check
// with no certificate is refused rather than passed.
func TestVerifyChainOnly_RefusesAServerPresentingNothing(t *testing.T) {
	err := data.VerifyChainOnly(tlstest.NewAuthority(t, "ours").Pool())(tls.ConnectionState{})
	require.Error(t, err)
}
