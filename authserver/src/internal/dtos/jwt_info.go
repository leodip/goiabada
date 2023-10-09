package dtos

import (
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
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

func (jwt JwtInfo) getAudience(claims jwt.MapClaims) []string {
	if claims["aud"] != nil {
		audArr, ok := claims["aud"].([]interface{})
		if ok {
			result := make([]string, len(audArr))
			for i, v := range audArr {
				result[i] = v.(string)
			}
			return result
		}

		aud, ok := claims["aud"].(string)
		if ok {
			return []string{aud}
		}
	}
	return []string{}
}

func (jwt JwtInfo) IsAccessTokenPresentAndValid() bool {
	return jwt.AccessTokenIsPresent && !jwt.AccessTokenIsExpired && jwt.AccessTokenSignatureIsValid
}

func (jwt JwtInfo) GetAccessTokenStringClaim(claimName string) string {
	if jwt.AccessTokenClaims[claimName] != nil {
		return jwt.AccessTokenClaims[claimName].(string)
	}
	return ""
}

func (jwt JwtInfo) GetAccessTokenTimeClaim(claimName string) time.Time {
	if jwt.AccessTokenClaims[claimName] != nil {
		f64, ok := jwt.AccessTokenClaims[claimName].(float64)
		if ok {
			return time.Unix(int64(f64), 0)
		}
	}

	var zeroValue time.Time
	return zeroValue
}

func (jwt JwtInfo) GetAccessTokenBoolClaim(claimName string) *bool {
	if jwt.AccessTokenClaims[claimName] != nil {
		b, ok := jwt.AccessTokenClaims[claimName].(bool)
		if ok {
			return &b
		}
	}
	return nil
}

func (jwt JwtInfo) GetAccessTokenRoles() []string {
	if jwt.AccessTokenClaims["roles"] != nil {
		rolesArr, ok := jwt.AccessTokenClaims["roles"].([]interface{})
		if ok {
			result := make([]string, len(rolesArr))
			for i, v := range rolesArr {
				result[i] = v.(string)
			}
			return result
		}
	}
	return []string{}
}

func (jwt JwtInfo) GetAccessTokenAddressClaim() map[string]string {
	if jwt.AccessTokenClaims["address"] != nil {
		addressMap, ok := jwt.AccessTokenClaims["address"].(map[string]interface{})
		if ok {
			result := make(map[string]string)
			for k, v := range addressMap {
				result[k] = v.(string)
			}
			return result
		}
	}
	return map[string]string{}
}

func (jwt JwtInfo) GetAccessTokenAudience() []string {
	return jwt.getAudience(jwt.AccessTokenClaims)
}

func (jwt JwtInfo) AccessTokenHasScope(scope string) bool {
	if jwt.AccessTokenClaims["scope"] != nil {
		scopesStr, ok := jwt.AccessTokenClaims["scope"].(string)
		if ok {
			scopesArr := strings.Split(scopesStr, " ")
			for _, v := range scopesArr {
				if v == scope {
					return true
				}
			}
		}
	}
	return false
}

func (jwt JwtInfo) IsIdTokenPresentAndValid() bool {
	return jwt.IdTokenIsPresent && !jwt.IdTokenIsExpired && jwt.IdTokenSignatureIsValid
}

func (jwt JwtInfo) GetIdTokenTimeClaim(claimName string) time.Time {
	if jwt.IdTokenClaims[claimName] != nil {
		f64, ok := jwt.IdTokenClaims[claimName].(float64)
		if ok {
			return time.Unix(int64(f64), 0)
		}
	}

	var zeroValue time.Time
	return zeroValue
}

func (jwt JwtInfo) GetIdTokenBoolClaim(claimName string) *bool {
	if jwt.IdTokenClaims[claimName] != nil {
		b, ok := jwt.IdTokenClaims[claimName].(bool)
		if ok {
			return &b
		}
	}
	return nil
}

func (jwt JwtInfo) GetIdTokenAddressClaim() map[string]string {
	if jwt.IdTokenClaims["address"] != nil {
		addressMap, ok := jwt.IdTokenClaims["address"].(map[string]interface{})
		if ok {
			result := make(map[string]string)
			for k, v := range addressMap {
				result[k] = v.(string)
			}
			return result
		}
	}
	return map[string]string{}
}

func (jwt JwtInfo) GetIdTokenStringClaim(claimName string) string {
	if jwt.IdTokenClaims[claimName] != nil {
		return jwt.IdTokenClaims[claimName].(string)
	}
	return ""
}

func (jwt JwtInfo) GetIdTokenAudience() []string {
	return jwt.getAudience(jwt.IdTokenClaims)
}

func (jwt JwtInfo) GetIdTokenAcrLevel() *enums.AcrLevel {
	if jwt.IdTokenClaims["acr"] != nil {
		acr := jwt.IdTokenClaims["acr"].(string)
		acrInt, err := strconv.Atoi(acr)
		if err == nil {
			return (*enums.AcrLevel)(&acrInt)
		}
	}
	return nil
}

func (jwt JwtInfo) IsIdTokenNonceValid(nonce string) bool {
	nonceHashFromIdToken := jwt.GetIdTokenStringClaim("nonce")
	if len(nonce) > 0 {
		return lib.VerifyPasswordHash(nonceHashFromIdToken, nonce)
	}
	return false
}

func (jwt JwtInfo) IsRefreshTokenPresentAndValid() bool {
	return jwt.RefreshTokenIsPresent && !jwt.RefreshTokenIsExpired && jwt.RefreshTokenSignatureIsValid
}

func (jwt JwtInfo) GetRefreshTokenTimeClaim(claimName string) time.Time {
	if jwt.RefreshTokenClaims[claimName] != nil {
		f64, ok := jwt.RefreshTokenClaims[claimName].(float64)
		if ok {
			return time.Unix(int64(f64), 0)
		}
	}

	var zeroValue time.Time
	return zeroValue
}

func (jwt JwtInfo) GetRefreshTokenAudience() []string {
	return jwt.getAudience(jwt.RefreshTokenClaims)
}

func (jwt JwtInfo) GetRefreshTokenStringClaim(claimName string) string {
	if jwt.RefreshTokenClaims[claimName] != nil {
		return jwt.RefreshTokenClaims[claimName].(string)
	}
	return ""
}
