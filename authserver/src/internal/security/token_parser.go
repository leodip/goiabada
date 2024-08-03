package security

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/internal/data"
)

type TokenParser struct {
	database data.Database
}

func NewTokenParser(database data.Database) *TokenParser {
	return &TokenParser{
		database: database,
	}
}

func (tp *TokenParser) DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *TokenResponse) (*JwtInfo, error) {

	pubKey, err := tp.getPublicKey()
	if err != nil {
		return nil, err
	}

	result := &JwtInfo{
		TokenResponse: *tokenResponse,
	}

	if len(tokenResponse.AccessToken) > 0 {
		result.AccessToken, err = tp.DecodeAndValidateTokenString(ctx, tokenResponse.AccessToken, pubKey)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		result.IdToken, err = tp.DecodeAndValidateTokenString(ctx, tokenResponse.IdToken, pubKey)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		result.RefreshToken, err = tp.DecodeAndValidateTokenString(ctx, tokenResponse.RefreshToken, pubKey)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (tp *TokenParser) getPublicKey() (*rsa.PublicKey, error) {
	keyPair, err := tp.database.GetCurrentSigningKey(nil)
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func (tp *TokenParser) DecodeAndValidateTokenString(ctx context.Context, token string,
	pubKey *rsa.PublicKey) (*JwtToken, error) {

	if pubKey == nil {
		var err error
		pubKey, err = tp.getPublicKey()
		if err != nil {
			return nil, err
		}
	}

	result := &JwtToken{
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
