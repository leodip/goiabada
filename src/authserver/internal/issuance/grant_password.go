package issuance

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/oauth"
)

// ROPCGrantInput contains the parameters needed to generate tokens for ROPC flow.
// RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
// ROPCGrantInput carries the parameters for a password grant.
//
// There is deliberately NO session identifier here. ROPC has no browser session: the
// grant is a direct credential exchange. A field used to exist, populated from whatever
// session cookie happened to accompany the request, and it reached the ID token, so a
// password grant for one user could be handed an ID token carrying a DIFFERENT user's
// session identifier whenever the browser was logged in as somebody else. Nothing needed
// it: ROPC refresh tokens are always Offline type and store a max lifetime rather than a
// session identifier, and the refresh path already hard-coded it empty. Removed rather
// than defaulted, so it cannot be reintroduced by an eager caller (#106).
type ROPCGrantInput struct {
	Client *models.Client
	User   *models.User
	Scope  string
	// AuthenticatedAt is when the password was checked, and so what every token of the grant
	// issues as auth_time. The issuer writes it, not the caller: IssuePasswordGrant
	// stamps the moment of the password grant, and a refresh copies the instant its parent
	// token recorded (#125).
	AuthenticatedAt time.Time
}

// IssuePasswordGrant creates tokens for Resource Owner Password Credentials flow.
// RFC 6749 Section 4.3
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
//
// Unlike implicit flow, ROPC issues refresh tokens.
// ROPC refresh tokens store UserId and ClientId directly (no Code entity needed).
//
// The response is the token endpoint's one wire shape, as every other grant's is. A struct of
// its own used to differ only in three omitempty tags, on the access token, token type and
// expires_in, none of which is ever empty here: the settings refuse a lifetime of 0 or less, and
// a client's 0 means it inherits that setting (#437).
func (t *TokenIssuer) IssuePasswordGrant(ctx context.Context, settings *models.Settings,
	input *ROPCGrantInput) (*oauth.TokenResponse, error) {

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, input.Client)

	response := &oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(ctx, nil, input.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, input.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, input.User)
	if err != nil {
		return nil, err
	}

	// The password was checked for this request, so this is the authentication instant. The first
	// refresh token records it, and every refresh carries it forward (#125). A copy, so the
	// caller's input is not written through.
	grant := *input
	grant.AuthenticatedAt = now
	input = &grant

	// Generate access token
	// nil parent: initial password grant, so the validated User snapshot is the source.
	accessTokenStr, err := t.generateROPCAccessToken(ctx, settings, input, input.Scope, now, privKey, keyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	response.AccessToken = accessTokenStr
	response.Scope = input.Scope

	// Generate id_token if openid scope is present
	scopes := strings.Split(input.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateROPCIdToken(ctx, settings, input, input.Scope, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		response.IdToken = idTokenStr
	}

	// Generate refresh token with direct UserId/ClientId (no Code entity needed)
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(ctx, settings, input, input.Scope, now, privKey, keyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	response.RefreshToken = refreshToken
	response.RefreshExpiresIn = refreshExpiresIn

	return response, nil
}
