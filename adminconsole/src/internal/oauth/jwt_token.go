package oauth

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/adminconsole/internal/enums"
	"github.com/leodip/goiabada/adminconsole/internal/hashutil"
)

type JwtToken struct {
	TokenBase64 string

	SignatureIsValid bool
	IsExpired        bool
	Claims           jwt.MapClaims
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
		return hashutil.VerifyStringHash(nonceHashFromToken, nonce)
	}
	return false
}

func (jwt JwtToken) IsIssuerValid(issuer string) bool {
	iss := jwt.GetStringClaim("iss")
	return iss == issuer
}
