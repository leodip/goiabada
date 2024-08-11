package oauth

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/models"
)

type AuthContext struct {
	ClientId            string
	RedirectURI         string
	ResponseType        string
	CodeChallengeMethod string
	CodeChallenge       string
	ResponseMode        string
	Scope               string
	ConsentedScope      string
	MaxAge              string
	RequestedAcrValues  string
	State               string
	Nonce               string
	UserAgent           string
	IpAddress           string
	AcrLevel            string
	AuthMethods         string
	AuthTime            time.Time
	UserId              int64
	AuthCompleted       bool
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

func (ac *AuthContext) SetAcrLevel(targetAcrLevel enums.AcrLevel, userSession *models.UserSession) error {

	if userSession == nil {
		ac.AcrLevel = targetAcrLevel.String()
		return nil
	}

	userSessionAcrLevel, err := enums.AcrLevelFromString(userSession.AcrLevel)
	if err != nil {
		return err
	}

	switch targetAcrLevel {
	case enums.AcrLevel1:
		if userSessionAcrLevel == enums.AcrLevel2 || userSessionAcrLevel == enums.AcrLevel3 {
			ac.AcrLevel = userSessionAcrLevel.String()
		} else {
			ac.AcrLevel = targetAcrLevel.String()
		}
	case enums.AcrLevel2:
		if userSessionAcrLevel == enums.AcrLevel3 {
			ac.AcrLevel = userSessionAcrLevel.String()
		} else {
			ac.AcrLevel = targetAcrLevel.String()
		}
	default:
		ac.AcrLevel = targetAcrLevel.String()
	}

	return nil
}

func (ac *AuthContext) ParseRequestedAcrValues() []enums.AcrLevel {
	arr := []enums.AcrLevel{}
	acrValues := ac.RequestedAcrValues
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
