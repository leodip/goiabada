package core

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/dtos"
)

type TokenParser struct {
	database datav2.Database
}

func NewTokenParser(database datav2.Database) *TokenParser {
	return &TokenParser{
		database: database,
	}
}

func (tp *TokenParser) ParseTokenResponse(ctx context.Context, tokenResponse *dtos.TokenResponse) (*dtos.JwtInfo, error) {

	keyPair, err := tp.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	result := &dtos.JwtInfo{
		TokenResponse: *tokenResponse,
	}

	if len(tokenResponse.AccessToken) > 0 {
		claimsAccessToken := jwt.MapClaims{}
		result.AccessToken = &dtos.JwtToken{
			TokenBase64: tokenResponse.AccessToken,
		}

		token, err := jwt.ParseWithClaims(tokenResponse.AccessToken, claimsAccessToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.AccessToken.SignatureIsValid = token.Valid
		exp := claimsAccessToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.AccessToken.IsExpired = true
		} else {
			result.AccessToken.Claims = claimsAccessToken
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		claimsIdToken := jwt.MapClaims{}
		result.IdToken = &dtos.JwtToken{
			TokenBase64: tokenResponse.IdToken,
		}

		token, err := jwt.ParseWithClaims(tokenResponse.IdToken, claimsIdToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.IdToken.SignatureIsValid = token.Valid
		exp := claimsIdToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.IdToken.IsExpired = true
		} else {
			result.IdToken.Claims = claimsIdToken
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		claimsRefreshToken := jwt.MapClaims{}
		result.RefreshToken = &dtos.JwtToken{
			TokenBase64: tokenResponse.RefreshToken,
		}

		token, err := jwt.ParseWithClaims(tokenResponse.RefreshToken, claimsRefreshToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.RefreshToken.SignatureIsValid = token.Valid
		exp := claimsRefreshToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.RefreshToken.IsExpired = true
		} else {
			result.RefreshToken.Claims = claimsRefreshToken
		}
	}

	return result, nil
}

func (tp *TokenParser) ParseToken(ctx context.Context, token string, validateClaims bool) (*dtos.JwtToken, error) {
	keyPair, err := tp.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	result := &dtos.JwtToken{
		TokenBase64: token,
	}

	if len(token) > 0 {
		claims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.SignatureIsValid = token.Valid
		exp := claims["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.IsExpired = true
		} else {
			result.Claims = claims
		}
	}

	return result, nil
}
