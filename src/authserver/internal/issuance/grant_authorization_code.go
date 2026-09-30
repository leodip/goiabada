package issuance

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/oauth"
)

// ErrCodeNotClaimed is a redemption that lost the claim on its code: no row changed when it was
// marked used. Usually another request redeemed the same code concurrently and won, and since #129
// it can also mean the code was revoked between validation and the claim because its session was
// terminated. The two are not distinguishable here and need not be: both are refused generically.
var ErrCodeNotClaimed = errors.New("the authorization code was no longer unused when it was claimed")

// IssueAuthorizationCodeGrant redeems a validated authorization code: it claims the code, then
// mints the access token, the ID token when openid was granted, and the first refresh token.
//
// The claim is a compare-and-set on `used`, made BEFORE anything is minted. Redemption spans a read
// in the validator and this mark, so a plain read then unconditional update leaves a window in which
// two concurrent requests both observe used=false and both mint tokens. MarkCodeAsUsed returns true
// only for the request that flips the flag, which is the one winner allowed to proceed (#77).
//
// A failed mint after a successful claim consumes the code, and the client must authenticate again.
// That is acceptable, since codes are one-time and 60 seconds lived, and it is the price of never
// issuing two token sets from one code.
//
// A lost claim is ErrCodeNotClaimed, and it runs no session-wide reuse cascade. In the race the
// winner is a legitimate redemption in flight (a concurrent duplicate still had to carry the right
// PKCE verifier), and tearing the session down would fight its mint on the same rows; in the revoked
// case the session is already gone and its grants already swept. Reuse protection is not weakened:
// a genuine LATER replay of a used code is detected by the validator and cascaded by the token
// handler (#77).
func (t *TokenIssuer) IssueAuthorizationCodeGrant(ctx context.Context, settings *models.Settings,
	code *models.Code) (*oauth.TokenResponse, error) {

	claimed, err := t.database.MarkCodeAsUsed(ctx, nil, code.Id)
	if err != nil {
		return nil, err
	}
	if !claimed {
		slog.DebugContext(ctx, "code could not be claimed, rejecting the redemption",
			"grant_type", oidc.GrantTypeAuthorizationCode.String(),
			"code_id", code.Id)
		return nil, ErrCodeNotClaimed
	}

	return t.mintAuthorizationCodeTokens(ctx, settings, code)
}

// mintAuthorizationCodeTokens mints a claimed code's tokens and inserts its first refresh token.
func (t *TokenIssuer) mintAuthorizationCodeTokens(ctx context.Context, settings *models.Settings,
	code *models.Code) (*oauth.TokenResponse, error) {

	err := t.database.CodeLoadClient(ctx, nil, code)
	if err != nil {
		return nil, err
	}

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, &code.Client)

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	err = t.database.CodeLoadUser(ctx, nil, code)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadGroups(ctx, nil, &code.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, code.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, &code.User)
	if err != nil {
		return nil, err
	}

	// nil parent: this is the initial code exchange, so the code is the authorizing credential.
	accessTokenStr, err := t.generateAccessToken(ctx, nil, settings, code, code.Scope, now, privKey, keyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = code.Scope

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(code.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateIdToken(ctx, nil, settings, code, code.Scope, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(ctx, nil, settings, code, code.Scope, now, privKey, keyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}
