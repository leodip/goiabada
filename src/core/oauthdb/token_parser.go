package oauthdb

import (
	"crypto/rsa"
	"errors"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/data"
	oauth "github.com/leodip/goiabada/core/oauth"
)

// TokenParser validates tokens using keys loaded from the database.
// This is used by the auth server. Admin console should use the JWKS parser.
type TokenParser struct {
	database data.Database
}

func NewTokenParser(database data.Database) *TokenParser {
	return &TokenParser{
		database: database,
	}
}

func (tp *TokenParser) DecodeAndValidateTokenResponse(tokenResponse *oauth.TokenResponse) (*oauth.JwtInfo, error) {

	pubKey, err := tp.getPublicKey()
	if err != nil {
		return nil, err
	}

	result := &oauth.JwtInfo{
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
	pubKey *rsa.PublicKey, withExpirationCheck bool) (*oauth.JwtToken, error) {

	result := &oauth.JwtToken{
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
			// DEBUG: Log the initial parse error
			slog.Debug("TokenParser: Initial parse failed", "error", err)

			// Check if this is a claims validation error (not a signature error)
			// If the token has valid signature but invalid claims (e.g., expired),
			// we should return that error immediately without trying fallback keys
			// Use errors.Is() for robust error type checking instead of string matching
			isClaimsError := errors.Is(err, jwt.ErrTokenExpired) ||
				errors.Is(err, jwt.ErrTokenNotValidYet) ||
				errors.Is(err, jwt.ErrTokenInvalidAudience) ||
				errors.Is(err, jwt.ErrTokenInvalidIssuer) ||
				errors.Is(err, jwt.ErrTokenInvalidSubject) ||
				errors.Is(err, jwt.ErrTokenUsedBeforeIssued) ||
				errors.Is(err, jwt.ErrTokenRequiredClaimMissing) ||
				errors.Is(err, jwt.ErrTokenInvalidId)

			if isClaimsError {
				slog.Debug("TokenParser: Error is claims-related, not trying fallback keys")
				return nil, err
			}

			// Only try fallback keys for signature-related errors
			// This handles tokens signed with rotated/old keys

			// Fallback: try all signing keys (e.g., previous) to allow tokens signed by old key
			allKeys, derr := tp.database.GetAllSigningKeys(nil)
			if derr != nil {
				return nil, err
			}
			slog.Debug("TokenParser: Trying fallback keys", "count", len(allKeys))

			var lastErr = err
			for i, kp := range allKeys {
				// Skip if this is same as current key
				parsedPk, perr := jwt.ParseRSAPublicKeyFromPEM(kp.PublicKeyPEM)
				if perr != nil {
					lastErr = perr
					continue
				}
				if parsedPk.Equal(pubKey) {
					slog.Debug("TokenParser: Skipping key - same as current", "index", i, "keyId", kp.Id)
					continue
				}
				slog.Debug("TokenParser: Trying fallback key", "index", i, "keyId", kp.Id, "state", kp.State, "keyIdentifier", kp.KeyIdentifier)
				if perr2 := tryParse(parsedPk); perr2 == nil {
					// success with a fallback key
					slog.Debug("TokenParser: Success with fallback key", "index", i, "keyId", kp.Id)
					result.Claims = claims
					return result, nil
				} else {
					slog.Debug("TokenParser: Failed with fallback key", "index", i, "keyId", kp.Id, "error", perr2)
					lastErr = perr2
				}
			}
			slog.Debug("TokenParser: All keys exhausted. Returning last error", "error", lastErr)
			return nil, lastErr
		}
		result.Claims = claims
	}

	return result, nil
}
