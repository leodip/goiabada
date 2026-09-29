package issuance

import (
	"context"
	"crypto/rsa"

	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/errs"
)

// loadSigningKey reads the current signing key and parses its private half, once per issuance:
// every token one grant mints is signed with the key it returns and names its identifier as kid,
// so the access, ID and refresh tokens of one response can never be signed by two keys. A read
// failure is returned as the database reported it.
func (t *TokenIssuer) loadSigningKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	keyPair, err := t.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, "", err
	}

	privKey, err := signingkeys.ParsePrivateKey(t.dataCipher, keyPair)
	if err != nil {
		return nil, "", errs.Wrap(err, "unable to parse private key from PEM")
	}
	return privKey, keyPair.KeyIdentifier, nil
}
