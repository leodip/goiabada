package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
)

type TokenIssuer struct {
}

func NewTokenIssuer() *TokenIssuer {
	return &TokenIssuer{}
}

func (t *TokenIssuer) GenerateTokenForAuthCode(ctx context.Context, code *entities.Code, keyPair *entities.KeyPair,
	baseUrl string) (*dtos.TokenResponse, error) {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	var tokenResponse = dtos.TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: settings.TokenExpirationInSeconds,
		Scope:     code.Scope,
	}

	privKeyPemBytes, err := base64.StdEncoding.DecodeString(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode base64 of private key PEM")
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyPemBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse private key from PEM")
	}

	now := time.Now().UTC()
	claims := make(jwt.MapClaims)
	scopes := strings.Split(code.Scope, " ")

	// access_token ---------------------------------------------------------------------------
	t.addCommonClaims(claims, settings, code, now)
	audCollection := []string{"account"}
	for _, scope := range scopes {
		if core.IsIdTokenScope(scope) {
			continue
		}
		parts := strings.Split(scope, ":")
		if !slices.Contains(audCollection, parts[0]) {
			audCollection = append(audCollection, parts[0])
		}
	}
	if len(audCollection) == 1 {
		claims["aud"] = audCollection[0]
	} else if len(audCollection) > 1 {
		claims["aud"] = audCollection
	}
	claims["typ"] = enums.TokenTypeBearer.String()
	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds))).Unix()
	claims["scope"] = code.Scope
	// add groups here (TODO)
	// if slices.Contains(scopes, "groups") {
	// 	claims["groups"] = code.User.GetGroupIdentifiers()
	// }
	if slices.Contains(scopes, "openid") {
		t.addOpenIdConnectClaims(claims, code, baseUrl)
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign access_token")
	}
	tokenResponse.AccessToken = accessToken

	// id_token ---------------------------------------------------------------------------
	if slices.Contains(scopes, "openid") {
		claims = make(jwt.MapClaims)
		t.addCommonClaims(claims, settings, code, now)
		claims["aud"] = code.Client.ClientIdentifier
		claims["typ"] = enums.TokenTypeId.String()
		claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(settings.TokenExpirationInSeconds))).Unix()
		claims["nonce"] = code.Nonce
		t.addOpenIdConnectClaims(claims, code, baseUrl)
		idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privKey)
		if err != nil {
			return nil, errors.Wrap(err, "unable to sign id_token")
		}
		// add groups here (TODO)
		// if slices.Contains(scopes, "groups") && settings.IncludeGroupsInIdToken {
		// 	claims["groups"] = code.User.GetGroupIdentifiers()
		// }
		tokenResponse.IdToken = idToken
	}

	// refresh_token ---------------------------------------------------------------------------
	if slices.Contains(scopes, "offline_access") {
		claims = make(jwt.MapClaims)

		claims["iss"] = settings.Issuer
		claims["iat"] = now.Unix()
		claims["jti"] = uuid.New().String()
		claims["aud"] = settings.Issuer
		claims["typ"] = enums.TokenTypeRefresh.String()
		claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(30))).Unix()
		refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privKey)
		if err != nil {
			return nil, errors.Wrap(err, "unable to sign refresh_token")
		}
		tokenResponse.RefreshToken = refreshToken
		tokenResponse.RefreshExpiresIn = 30
	}

	return &tokenResponse, nil
}

func (t *TokenIssuer) GenerateTokenForClientCred(ctx context.Context, client *entities.Client,
	scope string, keyPair *entities.KeyPair) (*dtos.TokenResponse, error) {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	var tokenResponse = dtos.TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: settings.TokenExpirationInSeconds,
		Scope:     scope,
	}

	privKeyPemBytes, err := base64.StdEncoding.DecodeString(keyPair.PrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode base64 of private key PEM")
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyPemBytes)
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
	claims["azp"] = client.ClientIdentifier

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
	if len(audCollection) == 1 {
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

func (tm *TokenIssuer) addCommonClaims(claims jwt.MapClaims, settings *entities.Settings, code *entities.Code,
	now time.Time) {

	claims["iss"] = settings.Issuer
	claims["sub"] = code.User.Subject
	claims["iat"] = now.Unix()
	claims["auth_time"] = code.AuthenticatedAt.Unix()
	claims["jti"] = uuid.New().String()
	claims["azp"] = code.Client.ClientIdentifier
	claims["acr"] = code.AcrLevel
	claims["amr"] = code.AuthMethods
	if len(code.SessionIdentifier) > 0 {
		claims["sid"] = code.SessionIdentifier
	}
}

func (tm *TokenIssuer) addOpenIdConnectClaims(claims jwt.MapClaims, code *entities.Code, baseUrl string) {

	scopes := strings.Split(code.Scope, " ")

	if slices.Contains(scopes, "profile") {
		tm.addClaimIfNotEmpty(claims, "name", code.User.GetFullName())
		tm.addClaimIfNotEmpty(claims, "family_name", code.User.FamilyName)
		tm.addClaimIfNotEmpty(claims, "given_name", code.User.GivenName)
		tm.addClaimIfNotEmpty(claims, "middle_name", code.User.MiddleName)
		tm.addClaimIfNotEmpty(claims, "nickname", code.User.Nickname)
		tm.addClaimIfNotEmpty(claims, "preferred_username", code.User.Username)
		claims["profile"] = fmt.Sprintf("%v/account/profile", baseUrl)
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
