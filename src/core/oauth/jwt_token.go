package oauth

import (
	"math"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/hashutil"
)

type JwtToken struct {
	TokenBase64 string
	Claims      jwt.MapClaims
}

// maxSafeFloat64Int is 2^53-1, the largest integer a float64 represents UNAMBIGUOUSLY.
// 2^53 itself is representable, but so is 2^53+1 as the same float64, so a parsed claim of
// 2^53 cannot be distinguished from one that was larger. Anything above this is therefore
// treated as malformed rather than silently accepted as a different number than was sent.
const maxSafeFloat64Int = float64(1<<53 - 1)

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
		s, ok := jwt.Claims[claimName].(string)
		if ok {
			return s
		}
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

// GetIntClaim returns an integral numeric claim, reporting whether a PRESENT claim
// parsed. It does not distinguish absent from malformed: both yield (0, false). A caller
// that needs the distinction tests raw map presence first, which is the idiom
// RequireUserBoundToken already uses for auth_time.
//
// The float64 assertion is not an oversight. Claims arrive through encoding/json via
// jwt.MapClaims, so every JSON number is a float64, exactly as GetTimeClaim assumes.
// Asserting to int here would reject every well-formed token (#106 decision 15).
//
// Rejects non-integral, negative, and values beyond the range float64 represents
// exactly, since none of those can be a generation counter that started at 0.
func (jwt JwtToken) GetIntClaim(claimName string) (int64, bool) {
	raw, ok := jwt.Claims[claimName]
	if !ok || raw == nil {
		return 0, false
	}

	f64, ok := raw.(float64)
	if !ok {
		return 0, false
	}
	if f64 != math.Trunc(f64) {
		return 0, false
	}
	if f64 < 0 {
		return 0, false
	}
	if f64 > maxSafeFloat64Int {
		return 0, false
	}

	return int64(f64), true
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
