package issuance

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/userclaims"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"

	"slices"
)

// tokenIssuerDatabase is what the token issuer needs: the signing key, the code or refresh token
// being redeemed, and the claims that go into the tokens.
type tokenIssuerDatabase interface {
	CodeLoadClient(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*models.KeyPair, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	GroupsLoadAttributes(ctx context.Context, tx *sql.Tx, groups []models.Group) error
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)
	UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *models.User) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
}

type TokenIssuer struct {
	database tokenIssuerDatabase
	baseURL  string
}

func NewTokenIssuer(database tokenIssuerDatabase, baseURL string) *TokenIssuer {
	return &TokenIssuer{
		database: database,
		baseURL:  baseURL,
	}
}

type GenerateTokenForRefreshInput struct {
	Code             *models.Code
	ScopeRequested   string
	RefreshToken     *models.RefreshToken
	RefreshTokenInfo *oauth.JwtToken
}

// TokenGenerationInput contains all data needed to generate access/id tokens
// regardless of the OAuth flow being used (auth code, implicit, ROPC).
// Refresh token types, as stored in refresh_tokens.refresh_token_type and emitted as the
// refresh token's typ claim. Named so the branch that chooses the type and the branches
// that later read it cannot drift apart.
const (
	offlineRefreshTokenType = "Offline"
	sessionRefreshTokenType = "Refresh"
)

type TokenGenerationInput struct {
	// User and Client (always required)
	User   *models.User
	Client *models.Client

	// Scope
	Scope string

	// Authentication context
	AcrLevel        string   // e.g., "urn:goiabada:pwd", "urn:goiabada:level1", etc.
	AuthMethods     []string // e.g., ["pwd"], ["pwd", "otp"]
	AuthenticatedAt time.Time

	// Optional claims
	SessionIdentifier string // Empty means don't include "sid" claim
	Nonce             string // Empty means don't include "nonce" claim
	AccessToken       string // For id_token: if non-empty, include "at_hash" claim (implicit flow)

	// AuthStateGeneration is the generation of the credential that authorized THIS
	// issuance, never the user's current value. Callers set it explicitly, because the
	// correct source differs per flow and reading the convenient one is the bug decision
	// 13 of #106 exists to prevent.
	AuthStateGeneration int64
	// GrantIsOffline suppresses the sid claim on ACCESS tokens only. An offline grant
	// outlives the browser session by design, so binding its access tokens to a session
	// identifier the middleware will later fail to resolve breaks exactly the use case
	// offline_access exists for (#106 decision 9). ID tokens keep sid regardless, because
	// RP-initiated logout matches on it.
	GrantIsOffline bool
}

// GenerateTokenForRefreshROPCInput is the input for refreshing ROPC tokens.
// Unlike auth code flow, ROPC tokens have UserId and ClientId directly on the RefreshToken.
type GenerateTokenForRefreshROPCInput struct {
	RefreshToken     *models.RefreshToken
	ScopeRequested   string
	RefreshTokenInfo *oauth.JwtToken
}

func (t *TokenIssuer) GenerateTokenResponseForAuthCode(ctx context.Context,
	code *models.Code) (*oauth.TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

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

	keyPair, err := t.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	privKey, err := signingkeys.ParsePrivateKey(keyPair)
	if err != nil {
		return nil, errs.Wrap(err, "unable to parse private key from PEM")
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
	accessTokenStr, err := t.generateAccessToken(ctx, settings, code, code.Scope, now, privKey, keyPair.KeyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = code.Scope

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(code.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateIdToken(ctx, settings, code, code.Scope, now, privKey, keyPair.KeyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(ctx, settings, code, code.Scope, now, privKey, keyPair.KeyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

// generateAccessToken builds an access token for the authorization code flow.
//
// parentRefreshToken is nil on the initial code exchange and set when refreshing. It
// decides both the generation and whether the grant is offline, and it has to: on a
// refresh the code is the wrong source for either. Its generation can lag the token's
// (the token may have been promoted while the code was not), and its scope can differ
// from the request's, since a caller may down-scope offline_access away without the
// grant ceasing to be offline (#106 decisions 9 and 13).
func (t *TokenIssuer) generateAccessToken(ctx context.Context, settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string,
	parentRefreshToken *models.RefreshToken) (string, error) {

	input := t.createTokenInputFromCode(code)
	input.Scope = scope // Use the provided scope (may differ from code.Scope for refresh)

	if parentRefreshToken == nil {
		input.AuthStateGeneration = code.AuthStateGeneration
		input.GrantIsOffline = grantIsOffline(code.Scope, code.SessionIdentifier)
	} else {
		input.AuthStateGeneration = parentRefreshToken.AuthStateGeneration
		input.GrantIsOffline = parentRefreshToken.RefreshTokenType == offlineRefreshTokenType
	}

	return t.generateAccessTokenCore(ctx, settings, input, now, signingKey, keyIdentifier)
}

// grantIsOffline reports whether an authorization-code grant is offline, from the
// AUTHORIZED scope rather than whatever a later request asked for. Mirrors the branch
// generateRefreshToken uses to choose the token type, so the two cannot disagree.
func grantIsOffline(authorizedScope string, sessionIdentifier string) bool {
	return oidc.HasOfflineAccessScope(authorizedScope) ||
		sessionIdentifier == ""
}

func (t *TokenIssuer) generateIdToken(ctx context.Context, settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	input := t.createTokenInputFromCode(code)
	input.Scope = scope // Use the provided scope (may differ from code.Scope for refresh)
	return t.generateIdTokenCore(ctx, settings, input, now, signingKey, keyIdentifier)
}

func (t *TokenIssuer) generateRefreshToken(ctx context.Context, settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, refreshToken *models.RefreshToken) (string, int64, error) {

	claims := make(jwt.MapClaims)

	jti := uuidutil.New()
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["sub"] = code.User.Subject

	// Use Offline type if the offline_access scope was granted, or if no session identifier
	// exists (e.g. ROPC, which creates no browser session). In both cases the refresh token
	// cannot be bound to a user session. Shared with the access token's sid decision through
	// grantIsOffline, so the two cannot disagree about what "offline" means.
	if grantIsOffline(scope, code.SessionIdentifier) {
		// offline refresh token (not related to user session)
		claims["typ"] = offlineRefreshTokenType

		exp, err := t.getRefreshTokenExpiration("Offline", now, settings, &code.Client)
		if err != nil {
			return "", 0, err
		}

		maxLifetime, err := t.getRefreshTokenMaxLifetime(ctx, "Offline", now, settings,
			&code.Client, code.SessionIdentifier)
		if err != nil {
			return "", 0, err
		}
		if refreshToken != nil {
			// if we are refreshing a refresh token, we need to use the max lifetime of the original refresh token
			maxLifetime = refreshToken.MaxLifetime.Time.Unix()
		}
		claims["offline_access_max_lifetime"] = maxLifetime

		if exp < maxLifetime {
			claims["exp"] = exp
		} else {
			claims["exp"] = maxLifetime
		}

	} else {
		// normal refresh token (associated with user session)
		claims["typ"] = sessionRefreshTokenType
		claims["sid"] = code.SessionIdentifier

		exp, err := t.getRefreshTokenExpiration("Refresh", now, settings, &code.Client)
		if err != nil {
			return "", 0, err
		}

		maxLifetime, err := t.getRefreshTokenMaxLifetime(ctx, "Refresh", now, settings, &code.Client, code.SessionIdentifier)
		if err != nil {
			return "", 0, err
		}

		if exp < maxLifetime {
			claims["exp"] = exp
		} else {
			claims["exp"] = maxLifetime
		}
	}
	claims["scope"] = scope

	// save 1st refresh token
	refreshTokenEntity := &models.RefreshToken{
		RefreshTokenJti:  jti,
		IssuedAt:         sql.NullTime{Time: now, Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Unix(claims["exp"].(int64), 0), Valid: true},
		CodeId:           sql.NullInt64{Int64: code.Id, Valid: true},
		RefreshTokenType: claims["typ"].(string),
		Scope:            claims["scope"].(string),
		Revoked:          false,
	}

	if refreshToken != nil {
		refreshTokenEntity.PreviousRefreshTokenJti = refreshToken.RefreshTokenJti
		refreshTokenEntity.FirstRefreshTokenJti = refreshToken.FirstRefreshTokenJti
		// Copied from the PARENT, never re-read from the code or the user. The parent may
		// have been promoted while the code was not, and reading the user's current value
		// would let an old grant launder itself into a new generation (#106 rule 5).
		refreshTokenEntity.AuthStateGeneration = refreshToken.AuthStateGeneration
	} else {
		// first refresh token issued
		refreshTokenEntity.FirstRefreshTokenJti = jti
		refreshTokenEntity.AuthStateGeneration = code.AuthStateGeneration
	}

	// Store either max lifetime (for Offline type) or session identifier (for Refresh type)
	if claims["typ"].(string) == "Offline" {
		t := time.Unix(claims["offline_access_max_lifetime"].(int64), 0)
		refreshTokenEntity.MaxLifetime = sql.NullTime{Time: t, Valid: true}
	} else {
		refreshTokenEntity.SessionIdentifier = claims["sid"].(string)
	}
	err := t.database.CreateRefreshToken(ctx, nil, refreshTokenEntity)
	if err != nil {
		return "", 0, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	rt, err := token.SignedString(signingKey)
	if err != nil {
		return "", 0, errs.Wrap(err, "unable to sign refresh_token")
	}
	refreshExpiresIn := claims["exp"].(int64) - now.Unix()

	return rt, refreshExpiresIn, nil
}

func (t *TokenIssuer) getRefreshTokenExpiration(refreshTokenType string, now time.Time, settings *models.Settings,
	client *models.Client) (int64, error) {
	switch refreshTokenType {
	case "Offline":
		refreshTokenExpirationInSeconds := settings.RefreshTokenOfflineIdleTimeoutInSeconds
		if client.RefreshTokenOfflineIdleTimeoutInSeconds > 0 {
			refreshTokenExpirationInSeconds = client.RefreshTokenOfflineIdleTimeoutInSeconds
		}
		exp := now.Add(time.Duration(time.Second * time.Duration(refreshTokenExpirationInSeconds))).Unix()
		return exp, nil
	case "Refresh":
		refreshTokenExpirationInSeconds := settings.UserSessionIdleTimeoutInSeconds
		exp := now.Add(time.Duration(time.Second * time.Duration(refreshTokenExpirationInSeconds))).Unix()
		return exp, nil
	}
	return 0, errs.Errorf("invalid refresh token type: %v", refreshTokenType)
}

func (t *TokenIssuer) getRefreshTokenMaxLifetime(ctx context.Context, refreshTokenType string, now time.Time, settings *models.Settings,
	client *models.Client, sessionIdentifier string) (int64, error) {
	switch refreshTokenType {
	case "Offline":
		maxLifetimeInSeconds := settings.RefreshTokenOfflineMaxLifetimeInSeconds
		if client.RefreshTokenOfflineMaxLifetimeInSeconds > 0 {
			maxLifetimeInSeconds = client.RefreshTokenOfflineMaxLifetimeInSeconds
		}
		maxLifetime := now.Add(time.Duration(time.Second * time.Duration(maxLifetimeInSeconds))).Unix()
		return maxLifetime, nil
	case "Refresh":
		userSession, err := t.database.GetUserSessionBySessionIdentifier(ctx, nil, sessionIdentifier)
		if err != nil {
			return 0, err
		}
		if userSession == nil {
			// The session backing this Refresh token no longer exists (e.g. it was
			// concurrently torn down). Fail cleanly instead of dereferencing nil.
			return 0, errs.Errorf("user session %q not found while computing refresh token max lifetime", sessionIdentifier)
		}
		maxLifetime := userSession.Started.Add(
			time.Duration(time.Second * time.Duration(settings.UserSessionMaxLifetimeInSeconds))).Unix()
		return maxLifetime, nil
	}
	return 0, errs.Errorf("invalid refresh token type: %v", refreshTokenType)
}

func (t *TokenIssuer) GenerateTokenResponseForClientCred(ctx context.Context, client *models.Client,
	scope string) (*oauth.TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	var tokenResponse = oauth.TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: int64(settings.TokenExpirationInSeconds),
		Scope:     scope,
	}

	keyPair, err := t.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	privKey, err := signingkeys.ParsePrivateKey(keyPair)
	if err != nil {
		return nil, errs.Wrap(err, "unable to parse private key from PEM")
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
	token.Header["kid"] = keyPair.KeyIdentifier
	accessToken, err := token.SignedString(privKey)
	if err != nil {
		return nil, errs.Wrap(err, "unable to sign access_token")
	}
	tokenResponse.AccessToken = accessToken
	return &tokenResponse, nil
}

func (t *TokenIssuer) GenerateTokenResponseForRefresh(ctx context.Context, input *GenerateTokenForRefreshInput) (*oauth.TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	err := t.database.CodeLoadClient(ctx, nil, input.Code)
	if err != nil {
		return nil, err
	}

	scopeToUse := input.Code.Scope
	if len(input.ScopeRequested) > 0 {
		scopeToUse = input.ScopeRequested
	}

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Code.Client.TokenExpirationInSeconds
	}

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	privKey, err := signingkeys.ParsePrivateKey(keyPair)
	if err != nil {
		return nil, errs.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	err = t.database.CodeLoadUser(ctx, nil, input.Code)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadGroups(ctx, nil, &input.Code.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, input.Code.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, &input.Code.User)
	if err != nil {
		return nil, err
	}

	// The PARENT refresh token is the authorizing credential here, not the code.
	accessTokenStr, err := t.generateAccessToken(ctx, settings, input.Code, scopeToUse, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeToUse

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateIdToken(ctx, settings, input.Code, scopeToUse, now, privKey, keyPair.KeyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := input.RefreshToken.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(ctx, settings, input.Code, originalRefreshTokenScope, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

// GenerateTokenResponseForRefreshROPC generates new tokens for an ROPC refresh token.
// Unlike auth code flow, ROPC tokens have UserId and ClientId directly on the RefreshToken.
func (t *TokenIssuer) GenerateTokenResponseForRefreshROPC(ctx context.Context, input *GenerateTokenForRefreshROPCInput) (*oauth.TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	// Load the User and Client from the refresh token
	err := t.database.RefreshTokenLoadUser(ctx, nil, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	err = t.database.RefreshTokenLoadClient(ctx, nil, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	scopeToUse := input.RefreshToken.Scope
	if len(input.ScopeRequested) > 0 {
		scopeToUse = input.ScopeRequested
	}

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.RefreshToken.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.RefreshToken.Client.TokenExpirationInSeconds
	}

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	privKey, err := signingkeys.ParsePrivateKey(keyPair)
	if err != nil {
		return nil, errs.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(ctx, nil, &input.RefreshToken.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, input.RefreshToken.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, &input.RefreshToken.User)
	if err != nil {
		return nil, err
	}

	// Create ROPCGrantInput for token generation
	ropcInput := &ROPCGrantInput{
		Client: &input.RefreshToken.Client,
		User:   &input.RefreshToken.User,
		Scope:  scopeToUse,
	}

	// access_token -----------------------------------------------------------------------

	// The parent refresh token authorizes this, not the reloaded user.
	accessTokenStr, err := t.generateROPCAccessToken(ctx, settings, ropcInput, scopeToUse, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeToUse

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateROPCIdToken(ctx, settings, ropcInput, scopeToUse, now, privKey, keyPair.KeyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := input.RefreshToken.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(ctx, settings, ropcInput, originalRefreshTokenScope, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

// claimMapper builds the user-claims mapper for one token type. The two fields after the port are
// issuance's side of the two divergences userclaims keeps as inputs rather than merging: the base
// URL is the one injected into this issuer, and the include flag is the token type's own (#387
// decision 5). updated_at was a third until it turned out to be a defect: issuance wrote it for
// any scope but a lone openid, and in an access token for a lone openid too, because the audience
// loop used to append a scope to the slice the claim block read. It now rides with the profile
// scope, as it does at /userinfo and as this repository's own documentation has always said.
func (t *TokenIssuer) claimMapper(inclusion userclaims.Inclusion) userclaims.Mapper {
	return userclaims.Mapper{
		Database:  t.database,
		BaseURL:   t.baseURL,
		Inclusion: inclusion,
	}
}

// generateAccessTokenCore creates an access token using the unified TokenGenerationInput.
// This is the single implementation used by all OAuth flows (auth code, implicit, ROPC).
func (t *TokenIssuer) generateAccessTokenCore(ctx context.Context, settings *models.Settings, input *TokenGenerationInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	claims := make(jwt.MapClaims)

	// Standard claims (same for all flows)
	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuidutil.New()
	claims["acr"] = input.AcrLevel
	// Omit amr rather than signing an empty array. OIDC Core 1.0 section 2 makes amr OPTIONAL, so
	// absent says nothing about how the user authenticated, where "amr": [] positively asserts that
	// no method was used. Reinstating the unconditional assignment would sign that false claim for
	// any grant whose session carries an empty auth_methods, which the column permits (#240).
	if len(input.AuthMethods) > 0 {
		claims["amr"] = input.AuthMethods
	}
	claims["auth_state_generation"] = input.AuthStateGeneration

	// Optional sid claim, suppressed for offline grants: see GrantIsOffline.
	if len(input.SessionIdentifier) > 0 && !input.GrantIsOffline {
		claims["sid"] = input.SessionIdentifier
	}

	scopes := strings.Split(input.Scope, " ")

	// Build audience collection from scopes
	audCollection := []string{}
	for _, s := range scopes {
		if oidc.IsClaimScope(s) {
			// A claim scope is answered at /userinfo, which the authserver resource serves, so it
			// names authserver as an audience. A groups-only grant, which carries no openid and
			// may carry no resource scope, would otherwise have no audience at all.
			if !slices.Contains(audCollection, coreconstants.AuthServerResourceIdentifier) {
				audCollection = append(audCollection, coreconstants.AuthServerResourceIdentifier)
			}
			continue
		}
		if !oidc.IsOfflineAccessScope(s) {
			parts := strings.Split(s, ":")
			if len(parts) != 2 {
				return "", errs.Errorf("invalid scope: %v", s)
			}
			if !slices.Contains(audCollection, parts[0]) {
				audCollection = append(audCollection, parts[0])
			}
		}
	}
	switch {
	case len(audCollection) == 0:
		return "", errs.Errorf("unable to generate an access token without an audience. scope: '%v'", input.Scope)
	case len(audCollection) == 1:
		claims["aud"] = audCollection[0]
	case len(audCollection) > 1:
		claims["aud"] = audCollection
	}

	claims["typ"] = TokenTypeBearer.String()

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()
	claims["scope"] = input.Scope

	// Optional nonce claim
	if len(input.Nonce) > 0 {
		claims["nonce"] = input.Nonce
	}

	// OpenID Connect claims in access token (if enabled)
	includeOpenIDConnectClaimsInAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	if input.Client.IncludeOpenIDConnectClaimsInAccessToken == models.ThreeStateSettingOn.String() ||
		input.Client.IncludeOpenIDConnectClaimsInAccessToken == models.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInAccessToken = input.Client.IncludeOpenIDConnectClaimsInAccessToken == models.ThreeStateSettingOn.String()
	}

	mapper := t.claimMapper(userclaims.InclusionAccessToken)

	if slices.Contains(scopes, "openid") && includeOpenIDConnectClaimsInAccessToken {
		mapper.AddOpenIdConnectClaims(ctx, claims, input.User, scopes)
	}

	// groups and attributes (using the IncludeInAccessToken filter), outside the OIDC claim
	// settings above: a client that turned the OIDC claims off still receives these.
	mapper.AddGroupClaims(claims, input.User, scopes)
	mapper.AddAttributeClaims(claims, input.User, scopes)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	accessToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", errs.Wrap(err, "unable to sign access_token")
	}
	return accessToken, nil
}

// generateIdTokenCore creates an id_token using the unified TokenGenerationInput.
// This is the single implementation used by all OAuth flows (auth code, implicit, ROPC).
func (t *TokenIssuer) generateIdTokenCore(ctx context.Context, settings *models.Settings, input *TokenGenerationInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	claims := make(jwt.MapClaims)

	// Standard claims (same for all flows)
	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuidutil.New()
	claims["acr"] = input.AcrLevel
	// Omitted when no method was recorded, for the reason given in generateAccessTokenCore (#240).
	if len(input.AuthMethods) > 0 {
		claims["amr"] = input.AuthMethods
	}

	// Optional sid claim
	if len(input.SessionIdentifier) > 0 {
		claims["sid"] = input.SessionIdentifier
	}

	scopes := strings.Split(input.Scope, " ")

	// ID token audience is always the client identifier
	claims["aud"] = input.Client.ClientIdentifier

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()

	// Optional nonce claim
	if len(input.Nonce) > 0 {
		claims["nonce"] = input.Nonce
	}

	// Optional at_hash claim (for implicit flow when id_token is issued alongside access_token)
	// Per OIDC Core 3.2.2.10
	if len(input.AccessToken) > 0 {
		claims["at_hash"] = t.calculateAtHash(input.AccessToken)
	}

	// OpenID Connect claims in ID token (if enabled)
	// Per OIDC Core 5.4, scope claims (email, profile, etc.) MAY be in ID tokens
	// but SHOULD be available from /userinfo endpoint for strict conformance.
	includeOpenIDConnectClaimsInIdToken := settings.IncludeOpenIDConnectClaimsInIdToken
	if input.Client.IncludeOpenIDConnectClaimsInIdToken == models.ThreeStateSettingOn.String() ||
		input.Client.IncludeOpenIDConnectClaimsInIdToken == models.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInIdToken = input.Client.IncludeOpenIDConnectClaimsInIdToken == models.ThreeStateSettingOn.String()
	}

	mapper := t.claimMapper(userclaims.InclusionIdToken)

	if includeOpenIDConnectClaimsInIdToken {
		mapper.AddOpenIdConnectClaims(ctx, claims, input.User, scopes)
	}

	// groups and attributes (using the IncludeInIdToken filter), outside the OIDC claim setting
	// above, as they are in the access token.
	mapper.AddGroupClaims(claims, input.User, scopes)
	mapper.AddAttributeClaims(claims, input.User, scopes)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	idToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", errs.Wrap(err, "unable to sign id_token")
	}
	return idToken, nil
}

// createTokenInputFromCode creates a TokenGenerationInput from an authorization code.
// Used by the authorization code flow.
func (t *TokenIssuer) createTokenInputFromCode(code *models.Code) *TokenGenerationInput {
	return &TokenGenerationInput{
		User:              &code.User,
		Client:            &code.Client,
		Scope:             code.Scope,
		AcrLevel:          code.AcrLevel,
		AuthMethods:       authMethodsToArray(code.AuthMethods),
		AuthenticatedAt:   code.AuthenticatedAt,
		SessionIdentifier: code.SessionIdentifier,
		Nonce:             code.Nonce,
	}
}

// createTokenInputFromImplicit creates a TokenGenerationInput from an ImplicitGrantInput.
// Used by the implicit flow (deprecated in OAuth 2.1).
func (t *TokenIssuer) createTokenInputFromImplicit(input *ImplicitGrantInput) *TokenGenerationInput {
	return &TokenGenerationInput{
		User:              input.User,
		Client:            input.Client,
		Scope:             input.Scope,
		AcrLevel:          input.AcrLevel,
		AuthMethods:       authMethodsToArray(input.AuthMethods),
		AuthenticatedAt:   input.AuthenticatedAt,
		SessionIdentifier: input.SessionIdentifier,
		Nonce:             input.Nonce,

		AuthStateGeneration: input.AuthStateGeneration,
		// Implicit is always session-bound: there is no refresh token, so nothing outlives
		// the session and sid stays on the access token.
		GrantIsOffline: false,
	}
}

// createTokenInputFromROPC creates a TokenGenerationInput from an ROPCGrantInput.
// Used by the ROPC flow (deprecated in OAuth 2.1).
// ROPC always uses password-only authentication (ACR: urn:goiabada:pwd, AMR: ["pwd"]).
func (t *TokenIssuer) createTokenInputFromROPC(input *ROPCGrantInput, now time.Time) *TokenGenerationInput {
	return &TokenGenerationInput{
		User:              input.User,
		Client:            input.Client,
		Scope:             input.Scope,
		AcrLevel:          "urn:goiabada:pwd", // ROPC is always password-only
		AuthMethods:       []string{"pwd"},    // ROPC is always password method
		AuthenticatedAt:   now,                // ROPC auth happens at token request time
		SessionIdentifier: "",                 // ROPC is sessionless: see ROPCGrantInput
		Nonce:             "",                 // ROPC doesn't use nonce
	}
}

// ImplicitGrantInput contains the parameters needed to generate tokens for implicit flow.
// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
type ImplicitGrantInput struct {
	Client            *models.Client
	User              *models.User
	Scope             string
	AcrLevel          string
	AuthMethods       string
	SessionIdentifier string
	Nonce             string
	AuthenticatedAt   time.Time
	// AuthStateGeneration comes from the AuthContext. Implicit issues no refresh token,
	// so this ceremony's own generation is the only possible source (#106 decision 13).
	AuthStateGeneration int64
}

// ImplicitGrantResponse contains the tokens generated for implicit flow.
// Per RFC 6749 4.2.2, NO refresh token is issued for implicit flow.
type ImplicitGrantResponse struct {
	AccessToken string
	IdToken     string
	TokenType   string
	ExpiresIn   int64
	Scope       string
}

// GenerateTokenResponseForImplicit creates tokens for the OAuth2/OIDC implicit flow.
// Per RFC 6749 4.2.2, NO refresh token is issued.
// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
func (t *TokenIssuer) GenerateTokenResponseForImplicit(ctx context.Context,
	input *ImplicitGrantInput, issueAccessToken bool, issueIdToken bool) (*ImplicitGrantResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	response := &ImplicitGrantResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	privKey, err := signingkeys.ParsePrivateKey(keyPair)
	if err != nil {
		return nil, errs.Wrap(err, "unable to parse private key from PEM")
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

	response.Scope = input.Scope

	// Generate access token if requested (response_type contains "token")
	if issueAccessToken {
		accessToken, err := t.generateImplicitAccessToken(ctx, settings, input, now, privKey, keyPair.KeyIdentifier)
		if err != nil {
			return nil, err
		}
		response.AccessToken = accessToken
	}

	// Generate id_token if requested (response_type contains "id_token")
	if issueIdToken {
		// For id_token token response, include at_hash in id_token (OIDC Core 3.2.2.10)
		idToken, err := t.generateImplicitIdToken(ctx, settings, input, now, privKey, keyPair.KeyIdentifier, response.AccessToken)
		if err != nil {
			return nil, err
		}
		response.IdToken = idToken
	}

	return response, nil
}

// generateImplicitAccessToken creates an access token for implicit flow.
func (t *TokenIssuer) generateImplicitAccessToken(ctx context.Context, settings *models.Settings, input *ImplicitGrantInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	return t.generateAccessTokenCore(ctx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateImplicitIdToken creates an id_token for implicit flow.
// Per OIDC Core 3.2.2.10, at_hash is REQUIRED when id_token is issued alongside access_token.
func (t *TokenIssuer) generateImplicitIdToken(ctx context.Context, settings *models.Settings, input *ImplicitGrantInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, accessToken string) (string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	tokenInput.AccessToken = accessToken // For at_hash claim
	return t.generateIdTokenCore(ctx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// calculateAtHash computes the at_hash claim per OIDC Core 3.2.2.10
// at_hash = base64url(left_half(SHA256(access_token)))
func (t *TokenIssuer) calculateAtHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	leftHalf := hash[:len(hash)/2] // Left-most half (16 bytes for SHA256)
	return base64.RawURLEncoding.EncodeToString(leftHalf)
}

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
}

// ROPCGrantResponse contains the tokens generated for ROPC flow.
// Unlike implicit flow, ROPC issues refresh tokens following auth code flow pattern.
type ROPCGrantResponse struct {
	AccessToken      string `json:"access_token"`
	IdToken          string `json:"id_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// GenerateTokenResponseForROPC creates tokens for Resource Owner Password Credentials flow.
// RFC 6749 Section 4.3
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
//
// Unlike implicit flow, ROPC issues refresh tokens.
// ROPC refresh tokens store UserId and ClientId directly (no Code entity needed).
func (t *TokenIssuer) GenerateTokenResponseForROPC(ctx context.Context,
	input *ROPCGrantInput) (*ROPCGrantResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	response := &ROPCGrantResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	privKey, err := signingkeys.ParsePrivateKey(keyPair)
	if err != nil {
		return nil, errs.Wrap(err, "unable to parse private key from PEM")
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

	// Generate access token
	// nil parent: initial password grant, so the validated User snapshot is the source.
	accessTokenStr, err := t.generateROPCAccessToken(ctx, settings, input, input.Scope, now, privKey, keyPair.KeyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	response.AccessToken = accessTokenStr
	response.Scope = input.Scope

	// Generate id_token if openid scope is present
	scopes := strings.Split(input.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateROPCIdToken(ctx, settings, input, input.Scope, now, privKey, keyPair.KeyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		response.IdToken = idTokenStr
	}

	// Generate refresh token with direct UserId/ClientId (no Code entity needed)
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(ctx, settings, input, input.Scope, now, privKey, keyPair.KeyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	response.RefreshToken = refreshToken
	response.RefreshExpiresIn = refreshExpiresIn

	return response, nil
}

// generateROPCAccessToken creates an access token for ROPC flow.
// generateROPCAccessToken builds an access token for the ROPC flow.
//
// parentRefreshToken is nil on the initial password grant, where the generation comes from
// the User snapshot the password validation returned, and set when refreshing, where it
// comes from the parent token. The distinction matters because the refresh path reloads
// the user: reading that reloaded user would stamp a grant authenticated under an older
// generation with the current one, laundering it forward (#106 decision 13).
//
// ROPC grants are always offline, so no access token here ever carries sid.
func (t *TokenIssuer) generateROPCAccessToken(ctx context.Context, settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string,
	parentRefreshToken *models.RefreshToken) (string, error) {

	tokenInput := t.createTokenInputFromROPC(input, now)
	tokenInput.Scope = scope // Use the provided scope
	tokenInput.GrantIsOffline = true

	if parentRefreshToken == nil {
		tokenInput.AuthStateGeneration = input.User.AuthStateGeneration
	} else {
		tokenInput.AuthStateGeneration = parentRefreshToken.AuthStateGeneration
	}

	return t.generateAccessTokenCore(ctx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateROPCIdToken creates an id_token for ROPC flow.
func (t *TokenIssuer) generateROPCIdToken(ctx context.Context, settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	tokenInput := t.createTokenInputFromROPC(input, now)
	tokenInput.Scope = scope // Use the provided scope
	return t.generateIdTokenCore(ctx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateRefreshTokenForROPC creates a refresh token specifically for ROPC flow.
// Unlike auth code flow, ROPC tokens store UserId and ClientId directly on the RefreshToken
// instead of referencing a Code entity.
func (t *TokenIssuer) generateRefreshTokenForROPC(ctx context.Context, settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, previousRefreshToken *models.RefreshToken) (string, int64, error) {

	claims := make(jwt.MapClaims)

	jti := uuidutil.New()
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["sub"] = input.User.Subject

	// ROPC tokens are always "Offline" type since there's no browser session
	// (The user authenticates directly with username/password via API)
	claims["typ"] = offlineRefreshTokenType

	exp, err := t.getRefreshTokenExpiration("Offline", now, settings, input.Client)
	if err != nil {
		return "", 0, err
	}

	maxLifetime := t.getRefreshTokenMaxLifetimeForROPC(now, settings, input.Client)
	if previousRefreshToken != nil {
		// if we are refreshing a refresh token, we need to use the max lifetime of the original refresh token
		maxLifetime = previousRefreshToken.MaxLifetime.Time.Unix()
	}
	claims["offline_access_max_lifetime"] = maxLifetime

	if exp < maxLifetime {
		claims["exp"] = exp
	} else {
		claims["exp"] = maxLifetime
	}

	claims["scope"] = scope

	// Create refresh token entity with direct UserId and ClientId (no Code reference)
	refreshTokenEntity := &models.RefreshToken{
		RefreshTokenJti:  jti,
		IssuedAt:         sql.NullTime{Time: now, Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Unix(claims["exp"].(int64), 0), Valid: true},
		UserId:           sql.NullInt64{Int64: input.User.Id, Valid: true},
		ClientId:         sql.NullInt64{Int64: input.Client.Id, Valid: true},
		RefreshTokenType: claims["typ"].(string),
		Scope:            claims["scope"].(string),
		Revoked:          false,
		MaxLifetime:      sql.NullTime{Time: time.Unix(maxLifetime, 0), Valid: true},
	}

	if previousRefreshToken != nil {
		refreshTokenEntity.PreviousRefreshTokenJti = previousRefreshToken.RefreshTokenJti
		refreshTokenEntity.FirstRefreshTokenJti = previousRefreshToken.FirstRefreshTokenJti
		// From the PARENT. The refresh path reloads the user, so reading input.User here
		// would stamp the current generation onto a grant authenticated under an older one
		// (#106 rule 5 and decision 13).
		refreshTokenEntity.AuthStateGeneration = previousRefreshToken.AuthStateGeneration
	} else {
		// first refresh token issued
		refreshTokenEntity.FirstRefreshTokenJti = jti
		// The User snapshot the password validation returned, not a reload.
		refreshTokenEntity.AuthStateGeneration = input.User.AuthStateGeneration
	}

	err = t.database.CreateRefreshToken(ctx, nil, refreshTokenEntity)
	if err != nil {
		return "", 0, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	rt, err := token.SignedString(signingKey)
	if err != nil {
		return "", 0, errs.Wrap(err, "unable to sign refresh_token")
	}
	refreshExpiresIn := claims["exp"].(int64) - now.Unix()

	return rt, refreshExpiresIn, nil
}

// getRefreshTokenMaxLifetimeForROPC calculates max lifetime for ROPC refresh tokens.
// ROPC tokens don't have user sessions, so we use the offline access max lifetime settings.
func (t *TokenIssuer) getRefreshTokenMaxLifetimeForROPC(now time.Time, settings *models.Settings, client *models.Client) int64 {
	// ROPC always uses offline access settings since there's no browser session
	maxLifetimeInSeconds := settings.RefreshTokenOfflineMaxLifetimeInSeconds
	if client.RefreshTokenOfflineMaxLifetimeInSeconds > 0 {
		maxLifetimeInSeconds = client.RefreshTokenOfflineMaxLifetimeInSeconds
	}
	return now.Add(time.Duration(time.Second * time.Duration(maxLifetimeInSeconds))).Unix()
}

// authMethodsToArray converts a space-separated auth methods string to a JSON array
// as required by OIDC Core 1.0 Section 2. The amr claim MUST be a JSON array of strings.
//
// Examples:
//   - "pwd" -> ["pwd"]
//   - "pwd otp" -> ["pwd", "otp"]
//   - "" -> []
func authMethodsToArray(authMethods string) []string {
	if authMethods == "" {
		return []string{}
	}
	return strings.Fields(authMethods)
}
