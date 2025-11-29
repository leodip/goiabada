package oauth

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

var (
	AuthStateInitial                 = "initial"
	AuthStateRequiresLevel1          = "requires_level_1"
	AuthStateRequiresLevel2          = "requires_level_2"
	AuthStateLevel1Password          = "level1_password"
	AuthStateLevel1PasswordCompleted = "level1_password_completed"
	AuthStateLevel1ExistingSession   = "level1_existing_session"
	AuthStateLevel2OTP               = "level2_otp"
	AuthStateLevel2OTPCompleted      = "level2_otp_completed"
	AuthStateAuthenticationCompleted = "authentication_completed"
	AuthStateRequiresConsent         = "requires_consent"
	AuthStateReadyToIssueCode        = "ready_to_issue_code"
)

type AuthContext struct {
	ClientId                      string
	RedirectURI                   string
	ResponseType                  string
	CodeChallengeMethod           string
	CodeChallenge                 string
	ResponseMode                  string
	Scope                         string
	ConsentedScope                string
	MaxAge                        string
	AcrValuesFromAuthorizeRequest string
	State                         string
	Nonce                         string
	UserAgent                     string
	IpAddress                     string
	AcrLevel                      string
	AuthMethods                   string
	UserId                        int64
	AuthState                     string
}

func (ac *AuthContext) SetScope(scope string) {
	scopeArr := []string{}

	// remove duplicated spaces
	space := regexp.MustCompile(`\s+`)
	scopeSanitized := space.ReplaceAllString(scope, " ")

	// remove duplicated scopes
	scopeElements := strings.Split(scopeSanitized, " ")
	for _, s := range scopeElements {
		if !slices.Contains(scopeArr, strings.TrimSpace(s)) {
			scopeArr = append(scopeArr, strings.TrimSpace(s))
		}
	}
	ac.Scope = strings.TrimSpace(strings.Join(scopeArr, " "))
}

func (ac *AuthContext) HasScope(scope string) bool {
	if len(ac.Scope) == 0 {
		return false
	}
	return slices.Contains(strings.Split(ac.Scope, " "), scope)
}

func (ac *AuthContext) AddAuthMethod(method string) {
	method = strings.ToLower(strings.TrimSpace(method))

	if method == "" {
		return
	}

	if ac.AuthMethods == "" {
		ac.AuthMethods = method
		return
	}

	lowerMethods := strings.ToLower(ac.AuthMethods)
	methods := strings.Fields(lowerMethods)

	for _, existingMethod := range methods {
		if existingMethod == method {
			return
		}
	}

	ac.AuthMethods = ac.AuthMethods + " " + method
}

func (ac *AuthContext) ParseRequestedMaxAge() *int {
	var requestedMaxAge *int
	if len(ac.MaxAge) > 0 {
		i, err := strconv.Atoi(ac.MaxAge)
		if err == nil {
			requestedMaxAge = &i
		}
	}
	return requestedMaxAge
}

// SetAcrLevel sets the AuthContext's ACR level, taking into account the user's
// existing session. The effective ACR is the maximum of the target and session ACR,
// ensuring we never downgrade the authentication level within a session.
//
// Uses enums.AcrMax() as the single source of truth for ACR comparison.
func (ac *AuthContext) SetAcrLevel(targetAcrLevel enums.AcrLevel, userSession *models.UserSession) error {
	if userSession == nil {
		ac.AcrLevel = targetAcrLevel.String()
		return nil
	}

	userSessionAcrLevel, err := enums.AcrLevelFromString(userSession.AcrLevel)
	if err != nil {
		return err
	}

	// Use the higher of the two ACR levels (never downgrade)
	ac.AcrLevel = enums.AcrMax(targetAcrLevel, userSessionAcrLevel).String()
	return nil
}

func (ac *AuthContext) parseAcrValuesFromAuthorizeRequest() []enums.AcrLevel {
	arr := []enums.AcrLevel{}
	acrValues := ac.AcrValuesFromAuthorizeRequest
	if len(strings.TrimSpace(acrValues)) > 0 {
		space := regexp.MustCompile(`\s+`)
		acrValues = space.ReplaceAllString(acrValues, " ")
		parts := strings.Split(acrValues, " ")
		for _, v := range parts {
			acr, err := enums.AcrLevelFromString(v)
			if err == nil && !slices.Contains(arr, acr) {
				arr = append(arr, acr)
			}
		}
	}
	return arr
}

func (ac *AuthContext) GetTargetAcrLevel(defaultAcrLevelFromClient enums.AcrLevel) enums.AcrLevel {
	acrValuesFromAuthorizeRequest := ac.parseAcrValuesFromAuthorizeRequest()
	if len(acrValuesFromAuthorizeRequest) > 0 {
		return acrValuesFromAuthorizeRequest[0]
	}
	return defaultAcrLevelFromClient
}
