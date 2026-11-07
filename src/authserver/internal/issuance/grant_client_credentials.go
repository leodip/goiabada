package issuance

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// IssueClientCredentialsGrant issues the client credentials grant's access token, RFC 6749 section
// 4.4.3. dpopThumbprint binds it to the request's proof key, empty for a bearer token.
func (t *TokenIssuer) IssueClientCredentialsGrant(ctx context.Context, settings *record.Settings,
	client *record.Client, scope string, dpopThumbprint string) (*oauth.TokenResponse, error) {

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, client)

	var tokenResponse = oauth.TokenResponse{
		TokenType: ResponseTokenType(dpopThumbprint),
		ExpiresIn: int64(tokenExpirationInSeconds),
		Scope:     scope,
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	claims := make(jwt.MapClaims)
	scopes := strings.Split(scope, " ")

	// access_token ---------------------------------------------------------------------------

	// The client is the token's subject. No grant_id: the grant issues no refresh token, so there
	// is no family to name (#676 decisions 1 and 2). The claims every access token carries,
	// client_id among them, are finishAccessToken's.
	claims["sub"] = client.ClientIdentifier

	audCollection := []string{}
	for _, scope := range scopes {
		if oidc.IsClaimScope(scope) || oidc.IsOfflineAccessScope(scope) {
			continue
		}
		parts := strings.Split(scope, ":")
		if len(parts) != 2 {
			return nil, errs.Errorf("invalid scope: %v", scope)
		}
		if !slices.Contains(audCollection, parts[0]) {
			audCollection = append(audCollection, parts[0])
		}
	}
	switch {
	case len(audCollection) == 0:
		return nil, errs.Errorf("unable to generate an access token without an audience. scope: '%v'", scope)
	case len(audCollection) == 1:
		claims["aud"] = audCollection[0]
	default:
		claims["aud"] = audCollection
	}

	accessToken, err := finishAccessToken(claims, settings, client, scope, dpopThumbprint, now, privKey, keyIdentifier)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessToken
	return &tokenResponse, nil
}
