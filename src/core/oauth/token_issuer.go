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
    database    data.Database
    baseURL     string
}

func NewTokenIssuer(database data.Database, baseURL string) *TokenIssuer {
    return &TokenIssuer{
        database:    database,
        baseURL:     baseURL,
    }
}

type GenerateTokenForRefreshInput struct {
	Code             *models.Code
	ScopeRequested   string
	RefreshToken     *models.RefreshToken
	RefreshTokenInfo *JwtToken
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

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = code.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = code.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = code.AcrLevel
	claims["amr"] = authMethodsToArray(code.AuthMethods)
	claims["sid"] = code.SessionIdentifier

	scopes := strings.Split(scope, " ")

	addUserInfoScope := false

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
	if code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = code.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()
	claims["scope"] = scope
	if len(code.Nonce) > 0 {
		claims["nonce"] = code.Nonce
	}

	includeOpenIDConnectClaimsInAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	if code.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String() ||
		code.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInAccessToken = code.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String()
	}

	if slices.Contains(scopes, "openid") && includeOpenIDConnectClaimsInAccessToken {
		t.addOpenIdConnectClaims(claims, code)
	}

	// groups
	if slices.Contains(scopes, "groups") {
		groups := []string{}
		for _, group := range code.User.Groups {
			if group.IncludeInAccessToken {
				groups = append(groups, group.GroupIdentifier)
			}
		}
		if len(groups) > 0 {
			claims["groups"] = groups
		}
	}

	// attributes
	if slices.Contains(scopes, "attributes") {
		attributes := map[string]string{}
		for _, attribute := range code.User.Attributes {
			if attribute.IncludeInAccessToken {
				attributes[attribute.Key] = attribute.Value
			}
		}

		for _, group := range code.User.Groups {
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

func (t *TokenIssuer) generateIdToken(settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = code.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = code.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = code.AcrLevel
	claims["amr"] = authMethodsToArray(code.AuthMethods)
	claims["sid"] = code.SessionIdentifier

	scopes := strings.Split(scope, " ")

	claims["aud"] = code.Client.ClientIdentifier

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = code.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()
	if len(code.Nonce) > 0 {
		claims["nonce"] = code.Nonce
	}
	t.addOpenIdConnectClaims(claims, code)

	// groups
	if slices.Contains(scopes, "groups") {
		groups := []string{}
		for _, group := range code.User.Groups {
			if group.IncludeInIdToken {
				groups = append(groups, group.GroupIdentifier)
			}
		}
		if len(groups) > 0 {
			claims["groups"] = groups
		}
	}

	// attributes
	if slices.Contains(scopes, "attributes") {
		attributes := map[string]string{}
		for _, attribute := range code.User.Attributes {
			if attribute.IncludeInIdToken {
				attributes[attribute.Key] = attribute.Value
			}
		}

		for _, group := range code.User.Groups {
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

	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(settings, input.Code, scopeFromAccessToken, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
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

	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(settings, ropcInput, scopeFromAccessToken, now, privKey, keyPair.KeyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

func (t *TokenIssuer) addOpenIdConnectClaims(claims jwt.MapClaims, code *models.Code) {

	scopes := strings.Split(code.Scope, " ")

	if len(scopes) > 1 || (len(scopes) == 1 && scopes[0] != "openid") {
		claims["updated_at"] = code.User.UpdatedAt.Time.UTC().Unix()
	}

	if slices.Contains(scopes, "profile") {
		t.addClaimIfNotEmpty(claims, "name", code.User.GetFullName())
		t.addClaimIfNotEmpty(claims, "given_name", code.User.GivenName)
		t.addClaimIfNotEmpty(claims, "middle_name", code.User.MiddleName)
		t.addClaimIfNotEmpty(claims, "family_name", code.User.FamilyName)
		t.addClaimIfNotEmpty(claims, "nickname", code.User.Nickname)
		t.addClaimIfNotEmpty(claims, "preferred_username", code.User.Username)
		claims["profile"] = fmt.Sprintf("%v/account/profile", t.baseURL)
		t.addClaimIfNotEmpty(claims, "website", code.User.Website)
		t.addClaimIfNotEmpty(claims, "gender", code.User.Gender)
		if code.User.BirthDate.Valid {
			claims["birthdate"] = code.User.BirthDate.Time.Format("2006-01-02")
		}
		t.addClaimIfNotEmpty(claims, "zoneinfo", code.User.ZoneInfo)
		t.addClaimIfNotEmpty(claims, "locale", code.User.Locale)

		// Add picture claim if user has a profile picture
		hasPicture, err := t.database.UserHasProfilePicture(nil, code.User.Id)
		if err == nil && hasPicture {
			claims["picture"] = fmt.Sprintf("%v/userinfo/picture/%v", t.baseURL, code.User.Subject.String())
		}
	}

	if slices.Contains(scopes, "email") {
		t.addClaimIfNotEmpty(claims, "email", code.User.Email)
		claims["email_verified"] = code.User.EmailVerified
	}

	if slices.Contains(scopes, "address") && code.User.HasAddress() {
		claims["address"] = code.User.GetAddressClaim()
	}

	if slices.Contains(scopes, "phone") {
		t.addClaimIfNotEmpty(claims, "phone_number", code.User.PhoneNumber)
		claims["phone_number_verified"] = code.User.PhoneNumberVerified
	}
}

func (t *TokenIssuer) addClaimIfNotEmpty(claims jwt.MapClaims, claimName string, claimValue string) {
	if len(strings.TrimSpace(claimValue)) > 0 {
		claims[claimName] = claimValue
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

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = input.AcrLevel
	claims["amr"] = authMethodsToArray(input.AuthMethods)
	claims["sid"] = input.SessionIdentifier

	scope := input.Scope
	scopes := strings.Split(scope, " ")

	addUserInfoScope := false

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
	if len(input.Nonce) > 0 {
		claims["nonce"] = input.Nonce
	}

	includeOpenIDConnectClaimsInAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	if input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String() ||
		input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInAccessToken = input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String()
	}

	if slices.Contains(scopes, "openid") && includeOpenIDConnectClaimsInAccessToken {
		t.addOpenIdConnectClaimsForImplicit(claims, input, scopes)
	}

	// groups
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

	// attributes
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

// generateImplicitIdToken creates an id_token for implicit flow.
// Per OIDC Core 3.2.2.10, at_hash is REQUIRED when id_token is issued alongside access_token.
func (t *TokenIssuer) generateImplicitIdToken(settings *models.Settings, input *ImplicitGrantInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, accessToken string) (string, error) {

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = input.AcrLevel
	claims["amr"] = authMethodsToArray(input.AuthMethods)
	claims["sid"] = input.SessionIdentifier

	scopes := strings.Split(input.Scope, " ")

	claims["aud"] = input.Client.ClientIdentifier

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()

	// nonce is REQUIRED for implicit flow (OIDC Core 3.2.2.1)
	if len(input.Nonce) > 0 {
		claims["nonce"] = input.Nonce
	}

	// at_hash is REQUIRED when id_token is issued alongside access_token (OIDC Core 3.2.2.10)
	if len(accessToken) > 0 {
		atHash := t.calculateAtHash(accessToken)
		claims["at_hash"] = atHash
	}

	t.addOpenIdConnectClaimsForImplicit(claims, input, scopes)

	// groups
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

	// attributes
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

// calculateAtHash computes the at_hash claim per OIDC Core 3.2.2.10
// at_hash = base64url(left_half(SHA256(access_token)))
func (t *TokenIssuer) calculateAtHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	leftHalf := hash[:len(hash)/2] // Left-most half (16 bytes for SHA256)
	return base64.RawURLEncoding.EncodeToString(leftHalf)
}

// addOpenIdConnectClaimsForImplicit adds OIDC claims to token claims for implicit flow.
func (t *TokenIssuer) addOpenIdConnectClaimsForImplicit(claims jwt.MapClaims, input *ImplicitGrantInput, scopes []string) {

	if len(scopes) > 1 || (len(scopes) == 1 && scopes[0] != "openid") {
		claims["updated_at"] = input.User.UpdatedAt.Time.UTC().Unix()
	}

	if slices.Contains(scopes, "profile") {
		t.addClaimIfNotEmpty(claims, "name", input.User.GetFullName())
		t.addClaimIfNotEmpty(claims, "given_name", input.User.GivenName)
		t.addClaimIfNotEmpty(claims, "middle_name", input.User.MiddleName)
		t.addClaimIfNotEmpty(claims, "family_name", input.User.FamilyName)
		t.addClaimIfNotEmpty(claims, "nickname", input.User.Nickname)
		t.addClaimIfNotEmpty(claims, "preferred_username", input.User.Username)
		claims["profile"] = fmt.Sprintf("%v/account/profile", t.baseURL)
		t.addClaimIfNotEmpty(claims, "website", input.User.Website)
		t.addClaimIfNotEmpty(claims, "gender", input.User.Gender)
		if input.User.BirthDate.Valid {
			claims["birthdate"] = input.User.BirthDate.Time.Format("2006-01-02")
		}
		t.addClaimIfNotEmpty(claims, "zoneinfo", input.User.ZoneInfo)
		t.addClaimIfNotEmpty(claims, "locale", input.User.Locale)

		// Add picture claim if user has a profile picture
		hasPicture, err := t.database.UserHasProfilePicture(nil, input.User.Id)
		if err == nil && hasPicture {
			claims["picture"] = fmt.Sprintf("%v/userinfo/picture/%v", t.baseURL, input.User.Subject.String())
		}
	}

	if slices.Contains(scopes, "email") {
		t.addClaimIfNotEmpty(claims, "email", input.User.Email)
		claims["email_verified"] = input.User.EmailVerified
	}

	if slices.Contains(scopes, "address") && input.User.HasAddress() {
		claims["address"] = input.User.GetAddressClaim()
	}

	if slices.Contains(scopes, "phone") {
		t.addClaimIfNotEmpty(claims, "phone_number", input.User.PhoneNumber)
		claims["phone_number_verified"] = input.User.PhoneNumberVerified
	}
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

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = now.Unix() // ROPC authentication happens at token request time
	claims["jti"] = uuid.New().String()
	claims["acr"] = "urn:goiabada:pwd"    // Password-only authentication
	claims["amr"] = []string{"pwd"}       // Password authentication method (OIDC requires array)

	// Only include sid if we have a session identifier (optional for ROPC)
	if len(input.SessionIdentifier) > 0 {
		claims["sid"] = input.SessionIdentifier
	}

	scopes := strings.Split(scope, " ")

	addUserInfoScope := false

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

	includeOpenIDConnectClaimsInAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	if input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String() ||
		input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInAccessToken = input.Client.IncludeOpenIDConnectClaimsInAccessToken == enums.ThreeStateSettingOn.String()
	}

	if slices.Contains(scopes, "openid") && includeOpenIDConnectClaimsInAccessToken {
		t.addOpenIdConnectClaimsForROPC(claims, input, scopes)
	}

	// groups
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

	// attributes
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

// generateROPCIdToken creates an id_token for ROPC flow.
func (t *TokenIssuer) generateROPCIdToken(settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = now.Unix() // ROPC authentication happens at token request time
	claims["jti"] = uuid.New().String()
	claims["acr"] = "urn:goiabada:pwd"    // Password-only authentication
	claims["amr"] = []string{"pwd"}       // Password authentication method (OIDC requires array)

	// Only include sid if we have a session identifier
	if len(input.SessionIdentifier) > 0 {
		claims["sid"] = input.SessionIdentifier
	}

	scopes := strings.Split(scope, " ")

	claims["aud"] = input.Client.ClientIdentifier

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()

	t.addOpenIdConnectClaimsForROPC(claims, input, scopes)

	// groups
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

	// attributes
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

	maxLifetime, err := t.getRefreshTokenMaxLifetimeForROPC("Offline", now, settings, input.Client)
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
func (t *TokenIssuer) getRefreshTokenMaxLifetimeForROPC(refreshTokenType string, now time.Time, settings *models.Settings,
	client *models.Client) (int64, error) {
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

// addOpenIdConnectClaimsForROPC adds OIDC claims to token claims for ROPC flow.
func (t *TokenIssuer) addOpenIdConnectClaimsForROPC(claims jwt.MapClaims, input *ROPCGrantInput, scopes []string) {

	if len(scopes) > 1 || (len(scopes) == 1 && scopes[0] != "openid") {
		claims["updated_at"] = input.User.UpdatedAt.Time.UTC().Unix()
	}

	if slices.Contains(scopes, "profile") {
		t.addClaimIfNotEmpty(claims, "name", input.User.GetFullName())
		t.addClaimIfNotEmpty(claims, "given_name", input.User.GivenName)
		t.addClaimIfNotEmpty(claims, "middle_name", input.User.MiddleName)
		t.addClaimIfNotEmpty(claims, "family_name", input.User.FamilyName)
		t.addClaimIfNotEmpty(claims, "nickname", input.User.Nickname)
		t.addClaimIfNotEmpty(claims, "preferred_username", input.User.Username)
		claims["profile"] = fmt.Sprintf("%v/account/profile", t.baseURL)
		t.addClaimIfNotEmpty(claims, "website", input.User.Website)
		t.addClaimIfNotEmpty(claims, "gender", input.User.Gender)
		if input.User.BirthDate.Valid {
			claims["birthdate"] = input.User.BirthDate.Time.Format("2006-01-02")
		}
		t.addClaimIfNotEmpty(claims, "zoneinfo", input.User.ZoneInfo)
		t.addClaimIfNotEmpty(claims, "locale", input.User.Locale)

		// Add picture claim if user has a profile picture
		hasPicture, err := t.database.UserHasProfilePicture(nil, input.User.Id)
		if err == nil && hasPicture {
			claims["picture"] = fmt.Sprintf("%v/userinfo/picture/%v", t.baseURL, input.User.Subject.String())
		}
	}

	if slices.Contains(scopes, "email") {
		t.addClaimIfNotEmpty(claims, "email", input.User.Email)
		claims["email_verified"] = input.User.EmailVerified
	}

	if slices.Contains(scopes, "address") && input.User.HasAddress() {
		claims["address"] = input.User.GetAddressClaim()
	}

	if slices.Contains(scopes, "phone") {
		t.addClaimIfNotEmpty(claims, "phone_number", input.User.PhoneNumber)
		claims["phone_number_verified"] = input.User.PhoneNumberVerified
	}
}
