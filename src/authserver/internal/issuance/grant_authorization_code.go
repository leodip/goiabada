package issuance

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/oauth"
)

func (t *TokenIssuer) GenerateTokenResponseForAuthCode(ctx context.Context, settings *models.Settings,
	code *models.Code) (*oauth.TokenResponse, error) {

	err := t.database.CodeLoadClient(ctx, nil, code)
	if err != nil {
		return nil, err
	}

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = code.Client.TokenExpirationInSeconds
	}

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx)
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
	accessTokenStr, err := t.generateAccessToken(ctx, settings, code, code.Scope, now, privKey, keyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = code.Scope

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(code.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateIdToken(ctx, settings, code, code.Scope, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(ctx, settings, code, code.Scope, now, privKey, keyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}
