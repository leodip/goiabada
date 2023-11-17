package core

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"

	"slices"
)

type TokenIssuer struct {
	database    *data.Database
	tokenParser *TokenParser
}

func NewTokenIssuer(database *data.Database, tokenParser *TokenParser) *TokenIssuer {
	return &TokenIssuer{
		database:    database,
		tokenParser: tokenParser,
	}
}

type GenerateTokenForRefreshInput struct {
	Code             *entities.Code
	ScopeRequested   string
	RefreshToken     *entities.RefreshToken
	RefreshTokenInfo *dtos.JwtToken
}

type GenerateTokenResponseForAuthCodeInput struct {
	Code *entities.Code
}

func (t *TokenIssuer) GenerateTokenResponseForAuthCode(ctx context.Context,
	input *GenerateTokenResponseForAuthCodeInput) (*dtos.TokenResponse, error) {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Code.Client.TokenExpirationInSeconds
	}

	var tokenResponse = dtos.TokenResponse{
		TokenType: enums.TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey()
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	accessTokenStr, scopeFromAccessToken, err := t.generateAccessToken(settings, input.Code, input.Code.Scope, now, privKey)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeFromAccessToken

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(input.Code.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, err := t.generateIdToken(settings, input.Code, input.Code.Scope, now, privKey)
		if err != nil {
			return nil, err
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(settings, input.Code, scopeFromAccessToken, now, privKey, nil)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

func (t *TokenIssuer) generateAccessToken(settings *entities.Settings, code *entities.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey) (string, string, error) {

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = code.User.Subject
	claims["iat"] = now.Unix()
	claims["auth_time"] = code.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = code.AcrLevel
	claims["amr"] = code.AuthMethods
	claims["sid"] = code.SessionIdentifier

	scopes := strings.Split(scope, " ")

	addUserInfoScope := false

	audCollection := []string{}
	for _, s := range scopes {
		if core.IsIdTokenScope(s) {
			// if an OIDC scope is present, give access to the userinfo endpoint
			if !slices.Contains(audCollection, constants.AuthServerResourceIdentifier) {
				audCollection = append(audCollection, constants.AuthServerResourceIdentifier)
			}
			addUserInfoScope = true
			continue
		}
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid scope: %v", s)
		}
		if !slices.Contains(audCollection, parts[0]) {
			audCollection = append(audCollection, parts[0])
		}
	}
	if len(audCollection) == 0 {
		return "", "", fmt.Errorf("unable to generate an access token without an audience. scope: '%v'", scope)
	} else if len(audCollection) == 1 {
		claims["aud"] = audCollection[0]
	} else if len(audCollection) > 1 {
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
	claims["nonce"] = code.Nonce

	includeOpenIDConnectClaimsInAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	if code.Client.IncludeOpenIDConnectClaimsInAccessToken != enums.ThreeStateSettingDefault.String() {
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
		claims["groups"] = groups
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
		claims["attributes"] = attributes
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		return "", "", errors.Wrap(err, "unable to sign access_token")
	}
	return accessToken, scope, nil
}

func (t *TokenIssuer) generateIdToken(settings *entities.Settings, code *entities.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey) (string, error) {

	claims := make(jwt.MapClaims)

	claims["iss"] = settings.Issuer
	claims["sub"] = code.User.Subject
	claims["iat"] = now.Unix()
	claims["auth_time"] = code.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["acr"] = code.AcrLevel
	claims["amr"] = code.AuthMethods
	claims["sid"] = code.SessionIdentifier

	scopes := strings.Split(scope, " ")

	claims["aud"] = code.Client.ClientIdentifier
	claims["typ"] = enums.TokenTypeId.String()

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = code.Client.TokenExpirationInSeconds
	}

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()
	claims["nonce"] = code.Nonce

	t.addOpenIdConnectClaims(claims, code)

	// groups
	if slices.Contains(scopes, "groups") {
		groups := []string{}
		for _, group := range code.User.Groups {
			if group.IncludeInIdToken {
				groups = append(groups, group.GroupIdentifier)
			}
		}
		claims["groups"] = groups
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
		claims["attributes"] = attributes
	}

	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		return "", errors.Wrap(err, "unable to sign id_token")
	}
	return idToken, nil
}

func (t *TokenIssuer) generateRefreshToken(settings *entities.Settings, code *entities.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, refreshToken *entities.RefreshToken) (string, int64, error) {

	claims := make(jwt.MapClaims)

	jti := uuid.New().String()
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["sub"] = code.User.Subject

	scopes := strings.Split(scope, " ")

	if slices.Contains(scopes, "offline_access") {
		// offline refresh token (not related to user session)
		claims["typ"] = "Offline"

		exp, err := t.getRefreshTokenExpiration("Offline", now, settings, &code.Client)
		if err != nil {
			return "", 0, err
		}
		claims["exp"] = exp

		maxLifetime, err := t.getRefreshTokenMaxLifetime("Offline", now, settings,
			&code.Client, code.SessionIdentifier)
		if err != nil {
			return "", 0, err
		}
		if refreshToken != nil {
			// if we are refreshing a refresh token, we need to use the max lifetime of the original refresh token
			maxLifetime = refreshToken.MaxLifetime.Unix()
		}
		claims["offline_access_max_lifetime"] = maxLifetime

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
	refreshTokenEntity := entities.RefreshToken{
		RefreshTokenJti:  jti,
		IssuedAt:         now,
		ExpiresAt:        time.Unix(claims["exp"].(int64), 0),
		CodeId:           code.Id,
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

	if !slices.Contains(scopes, "offline_access") {
		refreshTokenEntity.SessionIdentifier = claims["sid"].(string)
	} else {
		t := time.Unix(claims["offline_access_max_lifetime"].(int64), 0)
		refreshTokenEntity.MaxLifetime = &t
	}
	_, err := t.database.SaveRefreshToken(&refreshTokenEntity)
	if err != nil {
		return "", 0, err
	}

	rt, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		return "", 0, errors.Wrap(err, "unable to sign refresh_token")
	}
	refreshExpiresIn := claims["exp"].(int64) - now.Unix()

	return rt, refreshExpiresIn, nil
}

func (t *TokenIssuer) getRefreshTokenExpiration(refreshTokenType string, now time.Time, settings *entities.Settings,
	client *entities.Client) (int64, error) {
	if refreshTokenType == "Offline" {
		refreshTokenExpirationInSeconds := settings.RefreshTokenOfflineIdleTimeoutInSeconds
		if client.RefreshTokenOfflineIdleTimeoutInSeconds > 0 {
			refreshTokenExpirationInSeconds = client.RefreshTokenOfflineIdleTimeoutInSeconds
		}
		exp := now.Add(time.Duration(time.Second * time.Duration(refreshTokenExpirationInSeconds))).Unix()
		return exp, nil
	} else if refreshTokenType == "Refresh" {
		refreshTokenExpirationInSeconds := settings.UserSessionIdleTimeoutInSeconds
		exp := now.Add(time.Duration(time.Second * time.Duration(refreshTokenExpirationInSeconds))).Unix()
		return exp, nil
	}
	return 0, fmt.Errorf("invalid refresh token type: %v", refreshTokenType)
}

func (t *TokenIssuer) getRefreshTokenMaxLifetime(refreshTokenType string, now time.Time, settings *entities.Settings,
	client *entities.Client, sessionIdentifier string) (int64, error) {
	if refreshTokenType == "Offline" {
		maxLifetimeInSeconds := settings.RefreshTokenOfflineMaxLifetimeInSeconds
		if client.RefreshTokenOfflineMaxLifetimeInSeconds > 0 {
			maxLifetimeInSeconds = client.RefreshTokenOfflineMaxLifetimeInSeconds
		}
		maxLifetime := now.Add(time.Duration(time.Second * time.Duration(maxLifetimeInSeconds))).Unix()
		return maxLifetime, nil
	} else if refreshTokenType == "Refresh" {
		userSession, err := t.database.GetUserSessionBySessionIdentifier(sessionIdentifier)
		if err != nil {
			return 0, err
		}
		maxLifetime := userSession.Started.Add(
			time.Duration(time.Second * time.Duration(settings.UserSessionMaxLifetimeInSeconds))).Unix()
		return maxLifetime, nil
	}
	return 0, fmt.Errorf("invalid refresh token type: %v", refreshTokenType)
}

func (t *TokenIssuer) GenerateTokenResponseForClientCred(ctx context.Context, client *entities.Client,
	scope string, keyPair *entities.KeyPair) (*dtos.TokenResponse, error) {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	var tokenResponse = dtos.TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: int64(settings.TokenExpirationInSeconds),
		Scope:     scope,
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
	claims["jti"] = uuid.New().String()

	audCollection := []string{}
	for _, scope := range scopes {
		if core.IsIdTokenScope(scope) {
			continue
		}
		parts := strings.Split(scope, ":")
		if !slices.Contains(audCollection, parts[0]) {
			audCollection = append(audCollection, parts[0])
		}
	}
	if len(audCollection) == 0 {
		return nil, fmt.Errorf("unable to generate an access token without an audience. scope: '%v'", scope)
	} else if len(audCollection) == 1 {
		claims["aud"] = audCollection[0]
	} else if len(audCollection) > 1 {
		claims["aud"] = audCollection
	}
	claims["typ"] = enums.TokenTypeBearer.String()
	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds))).Unix()
	claims["scope"] = scope
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign access_token")
	}
	tokenResponse.AccessToken = accessToken
	return &tokenResponse, nil
}

func (t *TokenIssuer) GenerateTokenResponseForRefresh(ctx context.Context, input *GenerateTokenForRefreshInput) (*dtos.TokenResponse, error) {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	scopeToUse := input.Code.Scope
	if len(input.ScopeRequested) > 0 {
		scopeToUse = input.ScopeRequested
	}

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Code.Client.TokenExpirationInSeconds
	}

	var tokenResponse = dtos.TokenResponse{
		TokenType: enums.TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	keyPair, err := t.database.GetCurrentSigningKey()
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	accessTokenStr, scopeFromAccessToken, err := t.generateAccessToken(settings, input.Code, scopeToUse, now, privKey)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeFromAccessToken

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, err := t.generateIdToken(settings, input.Code, scopeToUse, now, privKey)
		if err != nil {
			return nil, err
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(settings, input.Code, scopeFromAccessToken, now, privKey, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

func (tm *TokenIssuer) addOpenIdConnectClaims(claims jwt.MapClaims, code *entities.Code) {

	scopes := strings.Split(code.Scope, " ")

	if slices.Contains(scopes, "profile") {
		tm.addClaimIfNotEmpty(claims, "name", code.User.GetFullName())
		tm.addClaimIfNotEmpty(claims, "given_name", code.User.GivenName)
		tm.addClaimIfNotEmpty(claims, "middle_name", code.User.MiddleName)
		tm.addClaimIfNotEmpty(claims, "family_name", code.User.FamilyName)
		tm.addClaimIfNotEmpty(claims, "nickname", code.User.Nickname)
		tm.addClaimIfNotEmpty(claims, "preferred_username", code.User.Username)
		claims["profile"] = fmt.Sprintf("%v/account/profile", lib.GetBaseUrl())
		tm.addClaimIfNotEmpty(claims, "website", code.User.Website)
		tm.addClaimIfNotEmpty(claims, "gender", code.User.Gender)
		if code.User.BirthDate != nil {
			claims["birthdate"] = code.User.BirthDate.Format("2006-01-02")
		}
		tm.addClaimIfNotEmpty(claims, "zoneinfo", code.User.ZoneInfo)
		tm.addClaimIfNotEmpty(claims, "locale", code.User.Locale)
		claims["updated_at"] = code.User.UpdatedAt.UTC().Unix()
	}

	if slices.Contains(scopes, "email") {
		tm.addClaimIfNotEmpty(claims, "email", code.User.Email)
		claims["email_verified"] = code.User.EmailVerified
	}

	if slices.Contains(scopes, "address") && code.User.HasAddress() {
		claims["address"] = code.User.GetAddressClaim()
	}

	if slices.Contains(scopes, "phone") {
		tm.addClaimIfNotEmpty(claims, "phone_number", code.User.PhoneNumber)
		claims["phone_number_verified"] = code.User.PhoneNumberVerified
	}
}

func (tm *TokenIssuer) addClaimIfNotEmpty(claims jwt.MapClaims, claimName string, claimValue string) {
	if len(strings.TrimSpace(claimValue)) > 0 {
		claims[claimName] = claimValue
	}
}
