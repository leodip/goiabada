package core

import (
	"context"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
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

func (lm *LoginManager) MustPerformOTPAuth(ctx context.Context, client *entities.Client,
	userSession *entities.UserSession, targetAcrLevel enums.AcrLevel) bool {

	currentAcrLevel, err := enums.AcrLevelFromString(userSession.AcrLevel)
	if err != nil {
		return false
	}

	if currentAcrLevel == enums.AcrLevel1 {
		if (targetAcrLevel == enums.AcrLevel2 && userSession.User.OTPEnabled) ||
			(targetAcrLevel == enums.AcrLevel3) {
			return true
		}
	} else if currentAcrLevel == enums.AcrLevel2 {
		if targetAcrLevel == enums.AcrLevel3 {
			return true
		}
	}

	return false
}
