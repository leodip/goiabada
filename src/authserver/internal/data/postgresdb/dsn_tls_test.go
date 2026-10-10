package postgresdb

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

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The connection string carries no sslmode, so the auth server's environment decides it: pgx reads
// PostgreSQL's own PGSSLMODE and PGSSLROOTCERT there, and Database tells an operator to set
// PGSSLMODE=verify-full to have the server's certificate checked (#542). These pin both halves: the
// default, prefer, encrypts without checking and falls back to plain text, and verify-full checks
// the certificate against the named CA and the host, with no fallback. A DSN that came to carry an
// sslmode of its own would override the variable and fail here.
func TestDSN_TheEnvironmentDecidesTLS(t *testing.T) {
	cfg := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "db.example.com", Port: 5432, Name: "goiabada"}

	t.Run("prefer, unless the environment says otherwise", func(t *testing.T) {
		t.Setenv("PGSSLMODE", "")
		t.Setenv("PGSSLROOTCERT", "")

		parsed, err := pgx.ParseConfig(DSN(cfg))
		require.NoError(t, err)
		require.NotNil(t, parsed.TLSConfig, "TLS is tried first")
		assert.True(t, parsed.TLSConfig.InsecureSkipVerify, "without checking the certificate")
		require.NotEmpty(t, parsed.Fallbacks)
		assert.Nil(t, parsed.Fallbacks[len(parsed.Fallbacks)-1].TLSConfig, "and plain text after it")
	})

	t.Run("verify-full from the environment", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(caFile, testCAPEM(t), 0o600))
		t.Setenv("PGSSLMODE", "verify-full")
		t.Setenv("PGSSLROOTCERT", caFile)

		parsed, err := pgx.ParseConfig(DSN(cfg))
		require.NoError(t, err)
		require.NotNil(t, parsed.TLSConfig)
		assert.False(t, parsed.TLSConfig.InsecureSkipVerify, "the certificate is checked")
		assert.NotNil(t, parsed.TLSConfig.RootCAs, "against the CA PGSSLROOTCERT names")
		assert.Equal(t, "db.example.com", parsed.TLSConfig.ServerName, "and the host")
		assert.Empty(t, parsed.Fallbacks, "with no plain text fallback")
	})
}

// testCAPEM is a self-signed CA certificate, PEM-encoded.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
