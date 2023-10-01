package dtos

import "github.com/golang-jwt/jwt/v5"

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

func (jwt JwtInfo) IsRefreshPresentAndValid() bool {
	return jwt.RefreshTokenIsPresent && !jwt.RefreshTokenIsExpired && jwt.RefreshTokenSignatureIsValid
}
