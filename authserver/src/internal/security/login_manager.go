package security

import (
	"context"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/models"
)

type LoginManager struct {
	codeIssuer *CodeIssuer
}

/*

Acr Level 0 - cookie (no active authentication)
Acr Level 1 - pwd
Acr Level 2 - pwd + otp

*/

func NewLoginManager(codeIssuer *CodeIssuer) *LoginManager {
	return &LoginManager{
		codeIssuer: codeIssuer,
	}
}

type GetNextLoginStepInput struct {
	UserSession              *models.UserSession
	RequestedMaxAgeInSeconds *int
	RequestedAcrValues       []enums.AcrLevel
	Step1Completed           bool
	User                     *models.User
}

func (lm *LoginManager) HasValidUserSession(ctx context.Context, userSession *models.UserSession, requestedMaxAgeInSeconds *int) bool {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	isValid := false
	if userSession != nil {
		isValid = userSession.IsValid(settings.UserSessionIdleTimeoutInSeconds,
			settings.UserSessionMaxLifetimeInSeconds, requestedMaxAgeInSeconds)
	}

	return isValid
}

func (lm *LoginManager) MustPerformOTPAuth(ctx context.Context, client *models.Client,
	userSession *models.UserSession, targetAcrLevel enums.AcrLevel) bool {

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
