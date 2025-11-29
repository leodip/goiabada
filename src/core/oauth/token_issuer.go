package oauth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/pkg/errors"

	"slices"
)

type TokenIssuer struct {
	database data.Database
	baseURL  string
}

func NewTokenIssuer(database data.Database, baseURL string) *TokenIssuer {
	return &TokenIssuer{
		database: database,
		baseURL:  baseURL,
	}
}

type GenerateTokenForRefreshInput struct {
	Code             *models.Code
	ScopeRequested   string
	RefreshToken     *models.RefreshToken
	RefreshTokenInfo *JwtToken
}

// TokenGenerationInput contains all data needed to generate access/id tokens
// regardless of the OAuth flow being used (auth code, implicit, ROPC).
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
}

// GenerateTokenForRefreshROPCInput is the input for refreshing ROPC tokens.
// Unlike auth code flow, ROPC tokens have UserId and ClientId directly on the RefreshToken.
type GenerateTokenForRefreshROPCInput struct {
	RefreshToken     *models.RefreshToken
	ScopeRequested   string
	RefreshTokenInfo *JwtToken
}

func (t *TokenIssuer) GenerateTokenResponseForAuthCode(ctx context.Context,
	code *models.Code) (*TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	err := t.database.CodeLoadClient(nil, code)
	if err != nil {
		return nil, err
	}

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = code.Client.TokenExpirationInSeconds
	}

	var tokenResponse = TokenResponse{
		TokenType: enums.TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	err = t.database.CodeLoadUser(nil, code)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadGroups(nil, &code.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(nil, code.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(nil, &code.User)
	if err != nil {
		return nil, err
	}

	accessTokenStr, scopeFromAccessToken, err := t.generateAccessToken(settings, code, code.Scope, now, privKey, keyPair.KeyIdentifier)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeFromAccessToken

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(code.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, err := t.generateIdToken(settings, code, code.Scope, now, privKey, keyPair.KeyIdentifier)
		if err != nil {
			return nil, err
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(settings, code, scopeFromAccessToken, now, privKey, keyPair.KeyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

func (t *TokenIssuer) generateAccessToken(settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, string, error) {

	input := t.createTokenInputFromCode(code)
	input.Scope = scope // Use the provided scope (may differ from code.Scope for refresh)
	return t.generateAccessTokenCore(settings, input, now, signingKey, keyIdentifier)
}

func (t *TokenIssuer) generateIdToken(settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	input := t.createTokenInputFromCode(code)
	input.Scope = scope // Use the provided scope (may differ from code.Scope for refresh)
	return t.generateIdTokenCore(settings, input, now, signingKey, keyIdentifier)
}

func (t *TokenIssuer) generateRefreshToken(settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, refreshToken *models.RefreshToken) (string, int64, error) {

	claims := make(jwt.MapClaims)

	jti := uuid.New().String()
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["sub"] = code.User.Subject

	scopes := strings.Split(scope, " ")

	// Use Offline type if:
	// 1. offline_access scope is requested, OR
	// 2. No session identifier exists (e.g., ROPC flow which doesn't create browser sessions)
	// In both cases, the refresh token cannot be bound to a user session
	if slices.Contains(scopes, oidc.OfflineAccessScope) || code.SessionIdentifier == "" {
		// offline refresh token (not related to user session)
		claims["typ"] = "Offline"

		exp, err := t.getRefreshTokenExpiration("Offline", now, settings, &code.Client)
		if err != nil {
			return "", 0, err
		}

		maxLifetime, err := t.getRefreshTokenMaxLifetime("Offline", now, settings,
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
		claims["typ"] = "Refresh"
		claims["sid"] = code.SessionIdentifier

		exp, err := t.getRefreshTokenExpiration("Refresh", now, settings, &code.Client)
		if err != nil {
			return "", 0, err
		}

		maxLifetime, err := t.getRefreshTokenMaxLifetime("Refresh", now, settings, &code.Client, code.SessionIdentifier)
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
	} else {
		// first refresh token issued
		refreshTokenEntity.FirstRefreshTokenJti = jti
	}

	// Store either max lifetime (for Offline type) or session identifier (for Refresh type)
	if claims["typ"].(string) == "Offline" {
		t := time.Unix(claims["offline_access_max_lifetime"].(int64), 0)
		refreshTokenEntity.MaxLifetime = sql.NullTime{Time: t, Valid: true}
	} else {
		refreshTokenEntity.SessionIdentifier = claims["sid"].(string)
	}
	err := t.database.CreateRefreshToken(nil, refreshTokenEntity)
	if err != nil {
		return "", 0, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	rt, err := token.SignedString(signingKey)
	if err != nil {
		return "", 0, errors.Wrap(err, "unable to sign refresh_token")
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
	return 0, errors.WithStack(fmt.Errorf("invalid refresh token type: %v", refreshTokenType))
}

func (t *TokenIssuer) getRefreshTokenMaxLifetime(refreshTokenType string, now time.Time, settings *models.Settings,
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
		userSession, err := t.database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			return 0, err
		}
		maxLifetime := userSession.Started.Add(
			time.Duration(time.Second * time.Duration(settings.UserSessionMaxLifetimeInSeconds))).Unix()
		return maxLifetime, nil
	}
	return 0, errors.WithStack(fmt.Errorf("invalid refresh token type: %v", refreshTokenType))
}

func (t *TokenIssuer) GenerateTokenResponseForClientCred(ctx context.Context, client *models.Client,
	scope string) (*TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	var tokenResponse = TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: int64(settings.TokenExpirationInSeconds),
		Scope:     scope,
	}

	keyPair, err := t.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()
	claims := make(jwt.MapClaims)
	scopes := strings.Split(scope, " ")

	// access_token ---------------------------------------------------------------------------

	claims["iss"] = settings.Issuer
	claims["sub"] = client.ClientIdentifier
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = uuid.New().String()

	audCollection := []string{}
	for _, scope := range scopes {
		if oidc.IsIdTokenScope(scope) || oidc.IsOfflineAccessScope(scope) {
			continue
		}
		parts := strings.Split(scope, ":")
		if len(parts) != 2 {
			return nil, errors.WithStack(fmt.Errorf("invalid scope: %v", scope))
		}
		if !slices.Contains(audCollection, parts[0]) {
			audCollection = append(audCollection, parts[0])
		}
	}
	switch {
	case len(audCollection) == 0:
		return nil, errors.WithStack(fmt.Errorf("unable to generate an access token without an audience. scope: '%v'", scope))
	case len(audCollection) == 1:
		claims["aud"] = audCollection[0]
	default:
		claims["aud"] = audCollection
	}
	claims["typ"] = enums.TokenTypeBearer.String()
	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds))).Unix()
	claims["scope"] = scope

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyPair.KeyIdentifier
	accessToken, err := token.SignedString(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign access_token")
	}
	tokenResponse.AccessToken = accessToken
	return &tokenResponse, nil
}

func (t *TokenIssuer) GenerateTokenResponseForRefresh(ctx context.Context, input *GenerateTokenForRefreshInput) (*TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	err := t.database.CodeLoadClient(nil, input.Code)
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

	var tokenResponse = TokenResponse{
		TokenType: enums.TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	err = t.database.CodeLoadUser(nil, input.Code)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadGroups(nil, &input.Code.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(nil, input.Code.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(nil, &input.Code.User)
	if err != nil {
		return nil, err
	}

	accessTokenStr, scopeFromAccessToken, err := t.generateAccessToken(settings, input.Code, scopeToUse, now, privKey, keyPair.KeyIdentifier)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeFromAccessToken

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, err := t.generateIdToken(settings, input.Code, scopeToUse, now, privKey, keyPair.KeyIdentifier)
		if err != nil {
			return nil, err
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := input.RefreshToken.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(settings, input.Code, originalRefreshTokenScope, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

// GenerateTokenResponseForRefreshROPC generates new tokens for an ROPC refresh token.
// Unlike auth code flow, ROPC tokens have UserId and ClientId directly on the RefreshToken.
func (t *TokenIssuer) GenerateTokenResponseForRefreshROPC(ctx context.Context, input *GenerateTokenForRefreshROPCInput) (*TokenResponse, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	// Load the User and Client from the refresh token
	err := t.database.RefreshTokenLoadUser(nil, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	err = t.database.RefreshTokenLoadClient(nil, input.RefreshToken)
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

	var tokenResponse = TokenResponse{
		TokenType: enums.TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(nil, &input.RefreshToken.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(nil, input.RefreshToken.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(nil, &input.RefreshToken.User)
	if err != nil {
		return nil, err
	}

	// Create ROPCGrantInput for token generation
	ropcInput := &ROPCGrantInput{
		Client:            &input.RefreshToken.Client,
		User:              &input.RefreshToken.User,
		Scope:             scopeToUse,
		SessionIdentifier: "", // ROPC doesn't use sessions
	}

	// access_token -----------------------------------------------------------------------

	accessTokenStr, scopeFromAccessToken, err := t.generateROPCAccessToken(settings, ropcInput, scopeToUse, now, privKey, keyPair.KeyIdentifier)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeFromAccessToken

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, err := t.generateROPCIdToken(settings, ropcInput, scopeToUse, now, privKey, keyPair.KeyIdentifier)
		if err != nil {
			return nil, err
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := input.RefreshToken.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(settings, ropcInput, originalRefreshTokenScope, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

func (t *TokenIssuer) addClaimIfNotEmpty(claims jwt.MapClaims, claimName string, claimValue string) {
	if len(strings.TrimSpace(claimValue)) > 0 {
		claims[claimName] = claimValue
	}
}

// addOpenIdConnectClaimsFromUser adds OIDC claims to token claims using user data directly.
// This is the unified version used by all OAuth flows (auth code, implicit, ROPC).
func (t *TokenIssuer) addOpenIdConnectClaimsFromUser(claims jwt.MapClaims, user *models.User, scopes []string) {

	if len(scopes) > 1 || (len(scopes) == 1 && scopes[0] != "openid") {
		claims["updated_at"] = user.UpdatedAt.Time.UTC().Unix()
	}

	if slices.Contains(scopes, "profile") {
		t.addClaimIfNotEmpty(claims, "name", user.GetFullName())
		t.addClaimIfNotEmpty(claims, "given_name", user.GivenName)
		t.addClaimIfNotEmpty(claims, "middle_name", user.MiddleName)
		t.addClaimIfNotEmpty(claims, "family_name", user.FamilyName)
		t.addClaimIfNotEmpty(claims, "nickname", user.Nickname)
		t.addClaimIfNotEmpty(claims, "preferred_username", user.Username)
		claims["profile"] = fmt.Sprintf("%v/account/profile", t.baseURL)
		t.addClaimIfNotEmpty(claims, "website", user.Website)
		t.addClaimIfNotEmpty(claims, "gender", user.Gender)
		if user.BirthDate.Valid {
			claims["birthdate"] = user.BirthDate.Time.Format("2006-01-02")
		}
		t.addClaimIfNotEmpty(claims, "zoneinfo", user.ZoneInfo)
		t.addClaimIfNotEmpty(claims, "locale", user.Locale)

		// Add picture claim if user has a profile picture
		hasPicture, err := t.database.UserHasProfilePicture(nil, user.Id)
		if err == nil && hasPicture {
			claims["picture"] = fmt.Sprintf("%v/userinfo/picture/%v", t.baseURL, user.Subject.String())
		}
	}

	if slices.Contains(scopes, "email") {
		t.addClaimIfNotEmpty(claims, "email", user.Email)
		claims["email_verified"] = user.EmailVerified
	}

	if slices.Contains(scopes, "address") && user.HasAddress() {
		claims["address"] = user.GetAddressClaim()
	}

	if slices.Contains(scopes, "phone") {
		t.addClaimIfNotEmpty(claims, "phone_number", user.PhoneNumber)
		claims["phone_number_verified"] = user.PhoneNumberVerified
	}
}

// generateAccessTokenCore creates an access token using the unified TokenGenerationInput.
// This is the single implementation used by all OAuth flows (auth code, implicit, ROPC).
func (t *TokenIssuer) generateAccessTokenCore(settings *models.Settings, input *TokenGenerationInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, string, error) {

	claims := make(jwt.MapClaims)

	// Standard claims (same for all flows)
	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = input.AcrLevel
	claims["amr"] = input.AuthMethods

	// Optional sid claim
	if len(input.SessionIdentifier) > 0 {
		claims["sid"] = input.SessionIdentifier
	}

	scope := input.Scope
	scopes := strings.Split(scope, " ")

	addUserInfoScope := false

	// Build audience collection from scopes
	audCollection := []string{}
	for _, s := range scopes {
		if oidc.IsIdTokenScope(s) {
			// if an OIDC scope is present, give access to the userinfo endpoint
			if !slices.Contains(audCollection, constants.AuthServerResourceIdentifier) {
				audCollection = append(audCollection, constants.AuthServerResourceIdentifier)
			}
			addUserInfoScope = true
			continue
		}
		if !oidc.IsOfflineAccessScope(s) {
			parts := strings.Split(s, ":")
			if len(parts) != 2 {
				return "", "", errors.WithStack(fmt.Errorf("invalid scope: %v", s))
			}
			if !slices.Contains(audCollection, parts[0]) {
				audCollection = append(audCollection, parts[0])
			}
		}
	}
	switch {
	case len(audCollection) == 0:
		return "", "", errors.WithStack(fmt.Errorf("unable to generate an access token without an audience. scope: '%v'", scope))
	case len(audCollection) == 1:
		claims["aud"] = audCollection[0]
	case len(audCollection) > 1:
		claims["aud"] = audCollection
	}

	if addUserInfoScope {
		// if an OIDC scope is present, give access to the userinfo endpoint
		userInfoScopeStr := fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
		if !slices.Contains(scopes, userInfoScopeStr) {
			scopes = append(scopes, userInfoScopeStr)
		}
		scope = strings.Join(scopes, " ")
	}

	claims["typ"] = enums.TokenTypeBearer.String()

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()
	claims["scope"] = scope

	// Optional nonce claim
	if len(input.Nonce) > 0 {
		claims["nonce"] = input.Nonce
	}

	// OpenID Connect claims in access token (if enabled)
	includeOpenIDConnectClaimsInAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	if input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String() ||
		input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInAccessToken = input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String()
	}

	if slices.Contains(scopes, "openid") && includeOpenIDConnectClaimsInAccessToken {
		t.addOpenIdConnectClaimsFromUser(claims, input.User, scopes)
	}

	// groups (using IncludeInAccessToken filter)
	if slices.Contains(scopes, "groups") {
		groups := []string{}
		for _, group := range input.User.Groups {
			if group.IncludeInAccessToken {
				groups = append(groups, group.GroupIdentifier)
			}
		}
		if len(groups) > 0 {
			claims["groups"] = groups
		}
	}

	// attributes (using IncludeInAccessToken filter)
	if slices.Contains(scopes, "attributes") {
		attributes := map[string]string{}
		for _, attribute := range input.User.Attributes {
			if attribute.IncludeInAccessToken {
				attributes[attribute.Key] = attribute.Value
			}
		}

		for _, group := range input.User.Groups {
			for _, attribute := range group.Attributes {
				if attribute.IncludeInAccessToken {
					attributes[attribute.Key] = attribute.Value
				}
			}
		}
		if len(attributes) > 0 {
			claims["attributes"] = attributes
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	accessToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", "", errors.Wrap(err, "unable to sign access_token")
	}
	return accessToken, scope, nil
}

// generateIdTokenCore creates an id_token using the unified TokenGenerationInput.
// This is the single implementation used by all OAuth flows (auth code, implicit, ROPC).
func (t *TokenIssuer) generateIdTokenCore(settings *models.Settings, input *TokenGenerationInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	claims := make(jwt.MapClaims)

	// Standard claims (same for all flows)
	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = input.AcrLevel
	claims["amr"] = input.AuthMethods

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

	// Always include OpenID Connect claims in id_token
	t.addOpenIdConnectClaimsFromUser(claims, input.User, scopes)

	// groups (using IncludeInIdToken filter)
	if slices.Contains(scopes, "groups") {
		groups := []string{}
		for _, group := range input.User.Groups {
			if group.IncludeInIdToken {
				groups = append(groups, group.GroupIdentifier)
			}
		}
		if len(groups) > 0 {
			claims["groups"] = groups
		}
	}

	// attributes (using IncludeInIdToken filter)
	if slices.Contains(scopes, "attributes") {
		attributes := map[string]string{}
		for _, attribute := range input.User.Attributes {
			if attribute.IncludeInIdToken {
				attributes[attribute.Key] = attribute.Value
			}
		}

		for _, group := range input.User.Groups {
			for _, attribute := range group.Attributes {
				if attribute.IncludeInIdToken {
					attributes[attribute.Key] = attribute.Value
				}
			}
		}
		if len(attributes) > 0 {
			claims["attributes"] = attributes
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	idToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", errors.Wrap(err, "unable to sign id_token")
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
		SessionIdentifier: input.SessionIdentifier,
		Nonce:             "", // ROPC doesn't use nonce
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
		TokenType: enums.TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(nil, input.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(nil, input.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(nil, input.User)
	if err != nil {
		return nil, err
	}

	// Generate access token if requested (response_type contains "token")
	if issueAccessToken {
		accessToken, scopeFromToken, err := t.generateImplicitAccessToken(settings, input, now, privKey, keyPair.KeyIdentifier)
		if err != nil {
			return nil, err
		}
		response.AccessToken = accessToken
		response.Scope = scopeFromToken
	}

	// Generate id_token if requested (response_type contains "id_token")
	if issueIdToken {
		// For id_token token response, include at_hash in id_token (OIDC Core 3.2.2.10)
		idToken, err := t.generateImplicitIdToken(settings, input, now, privKey, keyPair.KeyIdentifier, response.AccessToken)
		if err != nil {
			return nil, err
		}
		response.IdToken = idToken

		// If only id_token (no access token), we need to set scope
		if !issueAccessToken {
			response.Scope = input.Scope
		}
	}

	return response, nil
}

// generateImplicitAccessToken creates an access token for implicit flow.
func (t *TokenIssuer) generateImplicitAccessToken(settings *models.Settings, input *ImplicitGrantInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	return t.generateAccessTokenCore(settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateImplicitIdToken creates an id_token for implicit flow.
// Per OIDC Core 3.2.2.10, at_hash is REQUIRED when id_token is issued alongside access_token.
func (t *TokenIssuer) generateImplicitIdToken(settings *models.Settings, input *ImplicitGrantInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, accessToken string) (string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	tokenInput.AccessToken = accessToken // For at_hash claim
	return t.generateIdTokenCore(settings, tokenInput, now, signingKey, keyIdentifier)
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
type ROPCGrantInput struct {
	Client            *models.Client
	User              *models.User
	Scope             string
	SessionIdentifier string // For normal refresh token linkage (optional, can be empty for offline tokens)
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
		TokenType: enums.TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(nil, input.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(nil, input.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(nil, input.User)
	if err != nil {
		return nil, err
	}

	// Generate access token
	accessTokenStr, scopeFromAccessToken, err := t.generateROPCAccessToken(settings, input, input.Scope, now, privKey, keyPair.KeyIdentifier)
	if err != nil {
		return nil, err
	}
	response.AccessToken = accessTokenStr
	response.Scope = scopeFromAccessToken

	// Generate id_token if openid scope is present
	scopes := strings.Split(input.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, err := t.generateROPCIdToken(settings, input, input.Scope, now, privKey, keyPair.KeyIdentifier)
		if err != nil {
			return nil, err
		}
		response.IdToken = idTokenStr
	}

	// Generate refresh token with direct UserId/ClientId (no Code entity needed)
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(settings, input, scopeFromAccessToken, now, privKey, keyPair.KeyIdentifier, nil)
	if err != nil {
		return nil, err
	}
	response.RefreshToken = refreshToken
	response.RefreshExpiresIn = refreshExpiresIn

	return response, nil
}

// generateROPCAccessToken creates an access token for ROPC flow.
func (t *TokenIssuer) generateROPCAccessToken(settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, string, error) {

	tokenInput := t.createTokenInputFromROPC(input, now)
	tokenInput.Scope = scope // Use the provided scope
	return t.generateAccessTokenCore(settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateROPCIdToken creates an id_token for ROPC flow.
func (t *TokenIssuer) generateROPCIdToken(settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	tokenInput := t.createTokenInputFromROPC(input, now)
	tokenInput.Scope = scope // Use the provided scope
	return t.generateIdTokenCore(settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateRefreshTokenForROPC creates a refresh token specifically for ROPC flow.
// Unlike auth code flow, ROPC tokens store UserId and ClientId directly on the RefreshToken
// instead of referencing a Code entity.
func (t *TokenIssuer) generateRefreshTokenForROPC(settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, previousRefreshToken *models.RefreshToken) (string, int64, error) {

	claims := make(jwt.MapClaims)

	jti := uuid.New().String()
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["sub"] = input.User.Subject

	// ROPC tokens are always "Offline" type since there's no browser session
	// (The user authenticates directly with username/password via API)
	claims["typ"] = "Offline"

	exp, err := t.getRefreshTokenExpiration("Offline", now, settings, input.Client)
	if err != nil {
		return "", 0, err
	}

	maxLifetime, err := t.getRefreshTokenMaxLifetimeForROPC(now, settings, input.Client)
	if err != nil {
		return "", 0, err
	}
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
	} else {
		// first refresh token issued
		refreshTokenEntity.FirstRefreshTokenJti = jti
	}

	err = t.database.CreateRefreshToken(nil, refreshTokenEntity)
	if err != nil {
		return "", 0, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	rt, err := token.SignedString(signingKey)
	if err != nil {
		return "", 0, errors.Wrap(err, "unable to sign refresh_token")
	}
	refreshExpiresIn := claims["exp"].(int64) - now.Unix()

	return rt, refreshExpiresIn, nil
}

// getRefreshTokenMaxLifetimeForROPC calculates max lifetime for ROPC refresh tokens.
// ROPC tokens don't have user sessions, so we use the offline access max lifetime settings.
func (t *TokenIssuer) getRefreshTokenMaxLifetimeForROPC(now time.Time, settings *models.Settings, client *models.Client) (int64, error) {
	// ROPC always uses offline access settings since there's no browser session
	maxLifetimeInSeconds := settings.RefreshTokenOfflineMaxLifetimeInSeconds
	if client.RefreshTokenOfflineMaxLifetimeInSeconds > 0 {
		maxLifetimeInSeconds = client.RefreshTokenOfflineMaxLifetimeInSeconds
	}
	maxLifetime := now.Add(time.Duration(time.Second * time.Duration(maxLifetimeInSeconds))).Unix()
	return maxLifetime, nil
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
