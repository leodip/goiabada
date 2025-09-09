package oauth

import (
    "crypto/rsa"

    "github.com/golang-jwt/jwt/v5"
    "github.com/leodip/goiabada/core/data"
)

type TokenParser struct {
	database data.Database
}

func NewTokenParser(database data.Database) *TokenParser {
	return &TokenParser{
		database: database,
	}
}

func (tp *TokenParser) DecodeAndValidateTokenResponse(tokenResponse *TokenResponse) (*JwtInfo, error) {

	pubKey, err := tp.getPublicKey()
	if err != nil {
		return nil, err
	}

	result := &JwtInfo{
		TokenResponse: *tokenResponse,
	}

	if len(tokenResponse.AccessToken) > 0 {
		result.AccessToken, err = tp.DecodeAndValidateTokenString(tokenResponse.AccessToken, pubKey, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		result.IdToken, err = tp.DecodeAndValidateTokenString(tokenResponse.IdToken, pubKey, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		result.RefreshToken, err = tp.DecodeAndValidateTokenString(tokenResponse.RefreshToken, pubKey, false)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (tp *TokenParser) getPublicKey() (*rsa.PublicKey, error) {
	keyPair, err := tp.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func (tp *TokenParser) DecodeAndValidateTokenString(token string,
    pubKey *rsa.PublicKey, withExpirationCheck bool) (*JwtToken, error) {

    result := &JwtToken{
        TokenBase64: token,
    }

    if len(token) > 0 {
        claims := jwt.MapClaims{}

        opts := []jwt.ParserOption{}
        if withExpirationCheck {
            opts = append(opts, jwt.WithExpirationRequired())
        } else {
            opts = append(opts, jwt.WithoutClaimsValidation())
        }

        // Try with provided/current key first
        tryParse := func(pk *rsa.PublicKey) error {
            _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
                return pk, nil
            }, opts...)
            return err
        }

        // Ensure we have at least the current key
        if pubKey == nil {
            var err error
            pubKey, err = tp.getPublicKey()
            if err != nil {
                return nil, err
            }
        }

        if err := tryParse(pubKey); err != nil {
            // Fallback: try all signing keys (e.g., previous) to allow tokens signed by old key
            allKeys, derr := tp.database.GetAllSigningKeys(nil)
            if derr != nil {
                return nil, err
            }
            var lastErr error = err
            for _, kp := range allKeys {
                // Skip if this is same as current key
                parsedPk, perr := jwt.ParseRSAPublicKeyFromPEM(kp.PublicKeyPEM)
                if perr != nil {
                    lastErr = perr
                    continue
                }
                if parsedPk.Equal(pubKey) {
                    continue
                }
                if perr2 := tryParse(parsedPk); perr2 == nil {
                    // success with a fallback key
                    result.Claims = claims
                    return result, nil
                } else {
                    lastErr = perr2
                }
            }
            return nil, lastErr
        }
        result.Claims = claims
    }

    return result, nil
}
