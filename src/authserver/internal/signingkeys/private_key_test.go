package signingkeys

import (
	"crypto/rsa"
	"crypto/x509"
	encodingpem "encoding/pem"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/rsakey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storedKeyPair builds the private half of the row NewKeyPair builds: a real RSA key, PEM
// encoded, then encrypted at rest with the test data cipher (#83). The reference key is parsed
// from the plaintext PEM here, independently of ParsePrivateKey, so the round trip below compares
// against something the function under test did not produce.
func storedKeyPair(t *testing.T) (*record.KeyPair, *rsa.PrivateKey, []byte) {
	t.Helper()

	material, err := rsakey.Generate(1024, "kid")
	require.NoError(t, err)

	block, _ := encodingpem.Decode(material.PrivateKeyPEM)
	require.NotNil(t, block)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	pem := material.PrivateKeyPEM
	encrypted, err := testDataCipher.Encrypt(string(pem))
	require.NoError(t, err)

	return &record.KeyPair{PrivateKeyPEM: encrypted}, privateKey, pem
}

// TestParsePrivateKey_ReturnsTheStoredKey is the round trip: what the rotator stored is what the
// issuer signs with. The assertion is on the modulus and the private exponent rather than on the
// call merely succeeding, because a parser handed a different key of the same shape would also
// succeed and every token it signed would fail verification against the published JWK.
func TestParsePrivateKey_ReturnsTheStoredKey(t *testing.T) {
	keyPair, generated, pem := storedKeyPair(t)

	// The row really is encrypted, which is the thing the decrypt half exists for: the PEM
	// header does not survive into the column.
	assert.NotContains(t, string(keyPair.PrivateKeyPEM), "PRIVATE KEY")
	assert.Contains(t, string(pem), "PRIVATE KEY")

	parsed, err := ParsePrivateKey(testDataCipher, keyPair)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	assert.Equal(t, 0, generated.N.Cmp(parsed.N), "a different modulus came back")
	assert.Equal(t, 0, generated.D.Cmp(parsed.D), "a different private exponent came back")
	assert.NoError(t, parsed.Validate())
}

// TestParsePrivateKey_RefusesACiphertextItCannotDecrypt is the first failure arm: a column holding
// bytes this process's cipher did not write, which is what a key pair sealed under a different
// GOIABADA_AES_ENCRYPTION_KEY looks like. It must refuse rather than hand back a nil key with no
// error, and say that the key did not decrypt, keeping the cipher's cause, rather than send the
// operator to a key that would parse.
func TestParsePrivateKey_RefusesACiphertextItCannotDecrypt(t *testing.T) {
	otherCipher, err := encryption.NewDataCipher([]byte("fedcba9876543210fedcba9876543210"))
	require.NoError(t, err)
	sealedElsewhere, err := otherCipher.Encrypt("a PEM this cipher did not seal")
	require.NoError(t, err)

	parsed, err := ParsePrivateKey(testDataCipher, &record.KeyPair{KeyIdentifier: "kid-a", PrivateKeyPEM: sealedElsewhere})

	require.EqualError(t, err, "unable to decrypt signing key kid-a: cipher: message authentication failed")
	assert.Nil(t, parsed)
}

// TestParsePrivateKey_RefusesPlaintextThatIsNotAPEM is the second arm, and it is the one the first
// cannot reach: the cipher is happy and the parser is not. Both halves are needed because the two
// errors come from different libraries and only one of them is ours, and they read differently,
// because one is the configured data keys and the other the stored key itself.
func TestParsePrivateKey_RefusesPlaintextThatIsNotAPEM(t *testing.T) {
	encrypted, err := testDataCipher.Encrypt("-----BEGIN RSA PRIVATE KEY-----\nnot base64 at all\n-----END RSA PRIVATE KEY-----\n")
	require.NoError(t, err)

	parsed, err := ParsePrivateKey(testDataCipher, &record.KeyPair{KeyIdentifier: "kid-b", PrivateKeyPEM: encrypted})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key kid-b decrypts, but it is not an RSA private key PEM: ")
	assert.NotContains(t, err.Error(), "decrypt signing key")
	assert.Nil(t, parsed)
}
