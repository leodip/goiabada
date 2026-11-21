package issuance

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadSigningKey owns the prologue every grant's issuance runs before it signs anything, which
// was six copies until #437 and is one function now. The grants' own tests reach it once each on
// the success path and, for the password grant, on a read failure; the table here is where each
// outcome is pinned, the parse failure included, which no copy was ever tested for.
func TestLoadSigningKey(t *testing.T) {
	otherCipher, err := encryption.NewDataCipher([]byte("fedcba9876543210fedcba9876543210"))
	require.NoError(t, err)
	sealedElsewhere, err := otherCipher.Encrypt(string(getTestPrivateKey(t)))
	require.NoError(t, err)

	readFailure := errors.New("the signing key read failed")

	testCases := []struct {
		name    string
		keyPair *record.KeyPair
		readErr error
		// wantErr is empty for success; otherwise the returned error's whole text.
		wantErr string
		// wantCause is the error the returned one must still wrap, when it has one of its own.
		wantCause error
	}{
		{
			name:    "the current key, parsed, with its identifier",
			keyPair: &record.KeyPair{KeyIdentifier: "kid-current", PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t))},
		},
		{
			name:      "a read failure is returned as the database reported it",
			readErr:   readFailure,
			wantErr:   readFailure.Error(),
			wantCause: readFailure,
		},
		{
			// The cause is GCM's own refusal, which no message of Goiabada's writes.
			name:    "a key sealed under another cipher is reported as not decrypting",
			keyPair: &record.KeyPair{KeyIdentifier: "kid-current", PrivateKeyPEM: sealedElsewhere},
			wantErr: "unable to decrypt signing key kid-current: cipher: message authentication failed",
		},
		{
			name:    "a key that decrypts to something other than a PEM is reported as not parsing",
			keyPair: &record.KeyPair{KeyIdentifier: "kid-current", PrivateKeyPEM: encryptPEM(t, []byte("not a pem"))},
			wantErr: "signing key kid-current decrypts, but it is not an RSA private key PEM: " +
				jwt.ErrKeyMustBePEMEncoded.Error(),
			wantCause: jwt.ErrKeyMustBePEMEncoded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
			// Still on no transaction, as every grant read it before the split: none of them runs
			// its issuance inside one yet.
			mockDB.On("GetCurrentSigningKey", context.Background(), (*sql.Tx)(nil)).Return(tc.keyPair, tc.readErr).Once()

			privKey, keyIdentifier, err := tokenIssuer.loadSigningKey(context.Background(), nil)

			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				if tc.wantCause != nil {
					require.ErrorIs(t, err, tc.wantCause)
				}
				assert.Nil(t, privKey)
				assert.Empty(t, keyIdentifier, "no identifier is handed out beside a key that failed")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, "kid-current", keyIdentifier)
			publicKey, err := jwt.ParseRSAPublicKeyFromPEM(getTestPublicKey(t))
			require.NoError(t, err)
			assert.True(t, privKey.PublicKey.Equal(publicKey), "the parsed key is the stored key's private half")
		})
	}
}
