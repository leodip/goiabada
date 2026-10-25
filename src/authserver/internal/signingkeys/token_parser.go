package signingkeys

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

var (
	// ErrTokenRefused marks a token the parser refused: malformed, signed with a method other than
	// RS256, verified by none of the stored keys, or failing a claim check.
	ErrTokenRefused = errors.New("the token is refused")
	// ErrTokenExpired marks a refused token whose exp has passed. An error carrying it carries
	// ErrTokenRefused too.
	ErrTokenExpired = errors.New("the token has expired")
)

// tokenParserDatabase is what token parsing needs: the keys a signature may have been made with.
type tokenParserDatabase interface {
	GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]record.KeyPair, error)
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*record.KeyPair, error)
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

// refusal marks a failure of the token itself with ErrTokenRefused, and with ErrTokenExpired when the
// library found it expired. Its text is the library's, which stays in the chain for the log.
type refusal struct {
	err error
}

func (r *refusal) Error() string { return r.err.Error() }

func (r *refusal) Unwrap() error { return r.err }

func (r *refusal) Is(target error) bool {
	return target == ErrTokenRefused ||
		(target == ErrTokenExpired && errors.Is(r.err, jwt.ErrTokenExpired))
}

func refused(err error) error {
	return errs.WithStack(&refusal{err: err})
}

// DecodeAndValidateTokenString verifies an RS256 token against the current signing key, then, when
// the signature is what failed, against every other stored key, so a token signed before a rotation
// still verifies. withExpirationCheck requires an unexpired exp claim; without it no claim is
// validated, which is how an id_token_hint is read. An empty token returns an empty result and reads
// no key.
//
// A failure of the token itself carries ErrTokenRefused, and an expired token ErrTokenExpired too.
// A token that is malformed or not RS256 is refused before any key is read. A key that could not be
// read or decoded leaves the token unchecked, and that error carries neither mark (#680).
//
// The key always comes from the database. It used to be a parameter every caller passed as nil, so
// the one branch that used it was never reached in production (#424).
func (tp *TokenParser) DecodeAndValidateTokenString(ctx context.Context, token string,
	withExpirationCheck bool) (*oauth.JwtToken, error) {

	result := &oauth.JwtToken{
		TokenBase64: token,
	}

	if len(token) == 0 {
		return result, nil
	}

	claims := jwt.MapClaims{}

	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()})}
	if withExpirationCheck {
		opts = append(opts, jwt.WithExpirationRequired())
	} else {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}

	// The library calls the key function only once the token is well formed and RS256, so the
	// current key is read for no token that cannot be valid.
	var pubKey *rsa.PublicKey
	var keyErr error
	_, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (interface{}, error) {
		pubKey, keyErr = tp.getPublicKey(ctx)
		if keyErr != nil {
			return nil, keyErr
		}
		return pubKey, nil
	}, opts...)
	if keyErr != nil {
		return nil, keyErr
	}
	if err == nil {
		result.Claims = claims
		return result, nil
	}
	slog.DebugContext(ctx, "unable to parse the token with the current key", "error", err)

	// Only a signature the current key did not verify sends the parser to the other keys; any
	// other failure, such as an expired token whose signature verified, is the token's own.
	if pubKey == nil {
		return nil, refused(err)
	}
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		slog.DebugContext(ctx, "the error is claims-related, so no fallback key is tried")
		return nil, refused(err)
	}

	// Tried with each fallback key
	tryParse := func(pk *rsa.PublicKey) error {
		_, perr := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (interface{}, error) {
			return pk, nil
		}, opts...)
		return perr
	}

	// Fallback: try all signing keys (e.g., previous) to allow tokens signed by old key.
	// A failed lookup returns both errors: the parse error says why the current key did not
	// verify the token, the lookup error that no other key could be tried, which returning the
	// first alone hid (#424).
	allKeys, derr := tp.database.GetAllSigningKeys(ctx, nil)
	if derr != nil {
		return nil, errs.Join(err, errs.Wrap(derr, "unable to read the signing keys to try"))
	}
	slog.DebugContext(ctx, "trying the fallback keys", "count", len(allKeys))

	var lastErr = err
	var decodeErr error
	for i, kp := range allKeys {
		parsedPk, perr := jwt.ParseRSAPublicKeyFromPEM(kp.PublicKeyPEM)
		if perr != nil {
			decodeErr = perr
			continue
		}
		// Skip if this is same as current key
		if parsedPk.Equal(pubKey) {
			slog.DebugContext(ctx, "skipping a fallback key that is the current one",
				"index", i, "key_id", kp.Id)
			continue
		}
		slog.DebugContext(ctx, "trying a fallback key", "index", i, "key_id", kp.Id,
			"state", kp.State, "key_identifier", kp.KeyIdentifier)
		perr2 := tryParse(parsedPk)
		if perr2 == nil {
			// success with a fallback key
			slog.DebugContext(ctx, "parsed the token with a fallback key", "index", i, "key_id", kp.Id)
			result.Claims = claims
			return result, nil
		}
		slog.DebugContext(ctx, "unable to parse the token with a fallback key",
			"index", i, "key_id", kp.Id, "error", perr2)
		if !errors.Is(perr2, jwt.ErrTokenSignatureInvalid) {
			// This key verified the signature, so the failure is the token's own
			return nil, refused(perr2)
		}
		lastErr = perr2
	}

	// A key that could not be decoded may be the one the token was signed with
	if decodeErr != nil {
		return nil, errs.Join(lastErr, errs.Wrap(decodeErr, "unable to decode a signing key to try"))
	}
	slog.DebugContext(ctx, "every key is exhausted, returning the last error", "error", lastErr)
	return nil, refused(lastErr)
}
