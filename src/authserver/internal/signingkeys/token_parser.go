package signingkeys

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	oauth "github.com/leodip/goiabada/core/oauth"
)

// tokenParserDatabase is what token parsing needs: the keys a signature may have been made with.
type tokenParserDatabase interface {
	GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]models.KeyPair, error)
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*models.KeyPair, error)
}

// TokenParser validates tokens using keys loaded from the database.
// This is used by the auth server. Admin console should use the JWKS parser.
type TokenParser struct {
	database tokenParserDatabase
}

// NewTokenParser returns a parser reading its keys from database.
func NewTokenParser(database tokenParserDatabase) *TokenParser {
	return &TokenParser{
		database: database,
	}
}

func (tp *TokenParser) getPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	keyPair, err := tp.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// DecodeAndValidateTokenString verifies an RS256 token against the current signing key, then, when
// the signature is what failed, against every other stored key, so a token signed before a rotation
// still verifies. withExpirationCheck requires an unexpired exp claim; without it no claim is
// validated, which is how an id_token_hint is read. An empty token returns an empty result and reads
// no key.
//
// The key always comes from the database. It used to be a parameter every caller passed as nil, so
// the one branch that used it was never reached in production (#424).
func (tp *TokenParser) DecodeAndValidateTokenString(ctx context.Context, token string,
	withExpirationCheck bool) (*oauth.JwtToken, error) {

	result := &oauth.JwtToken{
		TokenBase64: token,
	}

	if len(token) > 0 {
		claims := jwt.MapClaims{}

		opts := []jwt.ParserOption{jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()})}
		if withExpirationCheck {
			opts = append(opts, jwt.WithExpirationRequired())
		} else {
			opts = append(opts, jwt.WithoutClaimsValidation())
		}

		// Tried with the current key first, then with each fallback key
		tryParse := func(pk *rsa.PublicKey) error {
			_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
				return pk, nil
			}, opts...)
			return err
		}

		pubKey, err := tp.getPublicKey(ctx)
		if err != nil {
			return nil, err
		}

		if err = tryParse(pubKey); err != nil {
			slog.DebugContext(ctx, "unable to parse the token with the current key", "error", err)

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
				slog.DebugContext(ctx, "the error is claims-related, so no fallback key is tried")
				return nil, err
			}

			// Only try fallback keys for signature-related errors
			// This handles tokens signed with rotated/old keys

			// Fallback: try all signing keys (e.g., previous) to allow tokens signed by old key.
			// A failed lookup returns both errors: the parse error says why the token was
			// refused, the lookup error that no other key could be tried, which returning the
			// first alone hid (#424).
			allKeys, derr := tp.database.GetAllSigningKeys(ctx, nil)
			if derr != nil {
				return nil, errs.Join(err, errs.Wrap(derr, "unable to read the signing keys to try"))
			}
			slog.DebugContext(ctx, "trying the fallback keys", "count", len(allKeys))

			var lastErr = err
			for i, kp := range allKeys {
				// Skip if this is same as current key
				parsedPk, perr := jwt.ParseRSAPublicKeyFromPEM(kp.PublicKeyPEM)
				if perr != nil {
					lastErr = perr
					continue
				}
				if parsedPk.Equal(pubKey) {
					slog.DebugContext(ctx, "skipping a fallback key that is the current one",
						"index", i, "key_id", kp.Id)
					continue
				}
				slog.DebugContext(ctx, "trying a fallback key", "index", i, "key_id", kp.Id,
					"state", kp.State, "key_identifier", kp.KeyIdentifier)
				if perr2 := tryParse(parsedPk); perr2 == nil {
					// success with a fallback key
					slog.DebugContext(ctx, "parsed the token with a fallback key", "index", i, "key_id", kp.Id)
					result.Claims = claims
					return result, nil
				} else {
					slog.DebugContext(ctx, "unable to parse the token with a fallback key",
						"index", i, "key_id", kp.Id, "error", perr2)
					lastErr = perr2
				}
			}
			slog.DebugContext(ctx, "every key is exhausted, returning the last error", "error", lastErr)
			return nil, lastErr
		}
		result.Claims = claims
	}

	return result, nil
}
