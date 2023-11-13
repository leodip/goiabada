package dtos

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

type JwtToken struct {
	TokenBase64 string

	SignatureIsValid bool
	IsExpired        bool
	Claims           jwt.MapClaims
}

type JwtInfo struct {
	TokenResponse TokenResponse

	AccessToken  *JwtToken
	IdToken      *JwtToken
	RefreshToken *JwtToken
}

func (jwt JwtToken) GetAudience() []string {
	if jwt.Claims["aud"] != nil {
		audArr, ok := jwt.Claims["aud"].([]interface{})
		if ok {
			result := make([]string, len(audArr))
			for i, v := range audArr {
				result[i] = v.(string)
			}
			return result
		}

		aud, ok := jwt.Claims["aud"].(string)
		if ok {
			return []string{aud}
		}
	}
	return []string{}
}

func (jwt JwtToken) GetStringClaim(claimName string) string {
	if jwt.Claims[claimName] != nil {
		return jwt.Claims[claimName].(string)
	}
	return ""
}

func (jwt JwtToken) GetTimeClaim(claimName string) time.Time {
	if jwt.Claims[claimName] != nil {
		f64, ok := jwt.Claims[claimName].(float64)
		if ok {
			return time.Unix(int64(f64), 0)
		}
	}

	var zeroValue time.Time
	return zeroValue
}

func (jwt JwtToken) GetBoolClaim(claimName string) *bool {
	if jwt.Claims[claimName] != nil {
		b, ok := jwt.Claims[claimName].(bool)
		if ok {
			return &b
		}
	}
	return nil
}

func (jwt JwtToken) GetAddressClaim() map[string]string {
	if jwt.Claims["address"] != nil {
		addressMap, ok := jwt.Claims["address"].(map[string]interface{})
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

func (jwt JwtToken) HasScope(scope string) bool {
	if jwt.Claims["scope"] != nil {
		scopesStr, ok := jwt.Claims["scope"].(string)
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

func (jwt JwtToken) GetAcrLevel() *enums.AcrLevel {
	if jwt.Claims["acr"] != nil {
		acr := jwt.Claims["acr"].(string)
		acrLevel, err := enums.AcrLevelFromString(acr)
		if err == nil {
			return &acrLevel
		}
	}
	return nil
}

func (jwt JwtToken) IsNonceValid(nonce string) bool {
	nonceHashFromToken := jwt.GetStringClaim("nonce")
	if len(nonce) > 0 {
		return lib.VerifyStringHash(nonceHashFromToken, nonce)
	}
	return false
}
