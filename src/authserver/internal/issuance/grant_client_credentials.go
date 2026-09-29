package issuance

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

func (t *TokenIssuer) IssueClientCredentialsGrant(ctx context.Context, settings *models.Settings,
	client *models.Client, scope string) (*oauth.TokenResponse, error) {

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(settings.TokenExpirationInSeconds),
		Scope:     scope,
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	claims := make(jwt.MapClaims)
	scopes := strings.Split(scope, " ")

	// access_token ---------------------------------------------------------------------------

	claims["iss"] = settings.Issuer
	claims["sub"] = client.ClientIdentifier
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = uuidutil.New()

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
	claims["typ"] = TokenTypeBearer.String()
	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds))).Unix()
	claims["scope"] = scope

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	accessToken, err := token.SignedString(privKey)
	if err != nil {
		return nil, errs.Wrap(err, "unable to sign access_token")
	}
	tokenResponse.AccessToken = accessToken
	return &tokenResponse, nil
}
