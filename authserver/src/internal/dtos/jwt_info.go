package dtos

import (
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/internal/enums"
)

type JwtInfo struct {
	TokenResponse TokenResponse

	AccessTokenIsPresent        bool
	AccessTokenSignatureIsValid bool
	AccessTokenIsExpired        bool
	AccessTokenClaims           jwt.MapClaims

	IdTokenIsPresent        bool
	IdTokenSignatureIsValid bool
	IdTokenIsExpired        bool
	IdTokenClaims           jwt.MapClaims

	RefreshTokenIsPresent        bool
	RefreshTokenSignatureIsValid bool
	RefreshTokenIsExpired        bool
	RefreshTokenClaims           jwt.MapClaims
}

func (jwt JwtInfo) IsAccessTokenPresentAndValid() bool {
	return jwt.AccessTokenIsPresent && !jwt.AccessTokenIsExpired && jwt.AccessTokenSignatureIsValid
}

func (jwt JwtInfo) IsIdTokenPresentAndValid() bool {
	return jwt.IdTokenIsPresent && !jwt.IdTokenIsExpired && jwt.IdTokenSignatureIsValid
}

func (jwt JwtInfo) GetIdTokenAcrLevel() *enums.AcrLevel {
	if jwt.IsIdTokenPresentAndValid() {
		if jwt.IdTokenClaims["acr"] != nil {
			acr := jwt.IdTokenClaims["acr"].(string)
			acrInt, err := strconv.Atoi(acr)
			if err == nil {
				return (*enums.AcrLevel)(&acrInt)
			}
		}
	}
	return nil
}
