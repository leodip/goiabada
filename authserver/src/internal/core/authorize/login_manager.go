package core

import (
	"context"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"golang.org/x/exp/slices"
)

type LoginManager struct {
	codeIssuer codeIssuer
}

/*

Acr Level 0 - cookie (no active authentication)
Acr Level 1 - pwd
Acr Level 2 - pwd + otp

*/

func NewLoginManager(codeIssuer codeIssuer) *LoginManager {
	return &LoginManager{
		codeIssuer: codeIssuer,
	}
}

type GetNextLoginStepInput struct {
	UserSession              *entities.UserSession
	RequestedMaxAgeInSeconds *int
	RequestedAcrValues       []enums.AcrLevel
	Step1Completed           bool
	User                     *entities.User
}

func (lm *LoginManager) HasValidUserSession(ctx context.Context, userSession *entities.UserSession, requestedMaxAgeInSeconds *int) bool {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	isValid := false
	if userSession != nil {
		isValid = userSession.IsValid(settings.UserSessionIdleTimeoutInSeconds,
			settings.UserSessionMaxLifetimeInSeconds, requestedMaxAgeInSeconds)
	}

	return isValid
}

func (lm *LoginManager) MustPerformPasswordAuth(ctx context.Context, userSession *entities.UserSession,
	requestedAcrValues []enums.AcrLevel) bool {

	acrLevel := lm.codeIssuer.GetUserSessionAcrLevel(ctx, userSession)
	if acrLevel == 0 {
		if (len(requestedAcrValues) == 0) || slices.Contains(requestedAcrValues, enums.AcrLevel0) {
			return false
		}

		return true
	}

	return false
}

func (lm *LoginManager) MustPerformOTPAuth(ctx context.Context, userSession *entities.UserSession,
	requestedAcrValues []enums.AcrLevel) bool {

	acrLevel := lm.codeIssuer.GetUserSessionAcrLevel(ctx, userSession)

	if acrLevel == 0 || acrLevel == 1 {

		if len(requestedAcrValues) > 0 {
			minAcrLevel := slices.Min(requestedAcrValues)
			if minAcrLevel == 2 && userSession.User.OTPEnabled {
				return true
			}
			if minAcrLevel == 3 {
				return true
			}
		}
	}

	return false
}
