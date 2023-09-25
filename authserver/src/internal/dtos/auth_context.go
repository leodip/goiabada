package dtos

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/internal/enums"
)

type AuthContext struct {
	ClientId            string
	RedirectUri         string
	ResponseType        string
	CodeChallengeMethod string
	CodeChallenge       string
	ResponseMode        string
	Scope               string
	ConsentedScope      string
	MaxAge              string
	AcrValues           string
	State               string
	Nonce               string
	UserAgent           string
	IpAddress           string
	SessionIdentifier   string
	AcrLevel            string
	AuthMethods         string
	Username            string
	AuthCompleted       bool
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

func (ac *AuthContext) ParseRequestedAcrValues() []enums.AcrLevel {
	arr := []enums.AcrLevel{}
	acrValues := ac.AcrValues
	if len(strings.TrimSpace(acrValues)) > 0 {
		space := regexp.MustCompile(`\s+`)
		acrValues = space.ReplaceAllString(acrValues, " ")
		parts := strings.Split(acrValues, " ")
		for _, v := range parts {
			if v == "0" && !slices.Contains(arr, enums.AcrLevel0) {
				arr = append(arr, enums.AcrLevel0)
			} else if v == "1" && !slices.Contains(arr, enums.AcrLevel1) {
				arr = append(arr, enums.AcrLevel1)
			} else if v == "2" && !slices.Contains(arr, enums.AcrLevel2) {
				arr = append(arr, enums.AcrLevel2)
			}
		}
	}
	return arr
}
