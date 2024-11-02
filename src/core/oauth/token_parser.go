package oauth

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/data"
)

type TokenParser struct {
	database data.Database
}

func NewTokenParser(database data.Database) *TokenParser {
	return &TokenParser{
		database: database,
	}
}

func (tp *TokenParser) DecodeAndValidateTokenResponse(tokenResponse *TokenResponse) (*JwtInfo, error) {

	pubKey, err := tp.getPublicKey()
	if err != nil {
		return nil, err
	}

	result := &JwtInfo{
		TokenResponse: *tokenResponse,
	}

	if len(tokenResponse.AccessToken) > 0 {
		result.AccessToken, err = tp.DecodeAndValidateTokenString(tokenResponse.AccessToken, pubKey, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		result.IdToken, err = tp.DecodeAndValidateTokenString(tokenResponse.IdToken, pubKey, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		result.RefreshToken, err = tp.DecodeAndValidateTokenString(tokenResponse.RefreshToken, pubKey, false)
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

func (tp *TokenParser) DecodeAndValidateTokenString(token string,
	pubKey *rsa.PublicKey, withExpirationCheck bool) (*JwtToken, error) {

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

		opts := []jwt.ParserOption{}
		if withExpirationCheck {
			opts = append(opts, jwt.WithExpirationRequired())
		} else {
			opts = append(opts, jwt.WithoutClaimsValidation())
		}

		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		}, opts...)
		if err != nil {
			return nil, err
		}
		result.Claims = claims
	}

	return result, nil
}
