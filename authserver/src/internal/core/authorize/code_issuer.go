package core

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"golang.org/x/exp/slices"
)

type CodeIssuer struct {
	database *data.Database
}

type CreateCodeInput struct {
	dtos.AuthContext
	SessionIdentifier string
}

func NewCodeIssuer(database *data.Database) *CodeIssuer {
	return &CodeIssuer{
		database: database,
	}
}

func (ci *CodeIssuer) CreateAuthCode(ctx context.Context, input *CreateCodeInput) (*entities.Code, error) {

	responseMode := input.ResponseMode
	if responseMode == "" {
		responseMode = "query"
	}

	client, err := ci.database.GetClientByClientIdentifier(input.ClientId)
	if err != nil {
		return nil, err
	}

	space := regexp.MustCompile(`\s+`)

	scope := ""
	if len(input.ConsentedScope) > 0 {
		scope = space.ReplaceAllString(input.ConsentedScope, " ")
	} else {
		scope = space.ReplaceAllString(input.Scope, " ")
	}
	scope = strings.TrimSpace(scope)

	if len(scope) == 0 {
		scope = "openid"
	}

	authCode := strings.Replace(uuid.New().String(), "-", "", -1) + lib.GenerateSecureRandomString(96)
	code := &entities.Code{
		Code:                authCode,
		ClientId:            client.Id,
		AuthenticatedAt:     time.Now().UTC(),
		UserId:              input.UserId,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		RedirectURI:         input.RedirectURI,
		Scope:               scope,
		State:               input.State,
		Nonce:               input.Nonce,
		UserAgent:           input.UserAgent,
		ResponseMode:        responseMode,
		IpAddress:           input.IpAddress,
		AuthMethods:         input.AuthMethods,
		SessionIdentifier:   input.SessionIdentifier,
		Used:                false,
	}

	requestedAcrValues := input.ParseRequestedAcrValues()
	if len(requestedAcrValues) == 0 {
		code.AcrLevel = input.AcrLevel
	} else {
		max := slices.Max(requestedAcrValues)
		code.AcrLevel = max.String()
	}

	code, err = ci.database.CreateCode(code)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (ci *CodeIssuer) GetUserSessionAcrLevel(ctx context.Context, userSession *entities.UserSession) enums.AcrLevel {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	if userSession != nil {

		utcNow := time.Now().UTC()
		authMethods := strings.Split(userSession.AuthMethods, " ")

		pwdAuth := slices.Contains(authMethods, enums.AuthMethodPassword.String())
		otpAuth := slices.Contains(authMethods, enums.AuthMethodOTP.String())

		if pwdAuth && otpAuth {

			// what was the requested acr level, if any?
			authContext := &dtos.AuthContext{RequestedAcrValues: userSession.RequestedAcrValues}
			requestedAcrValues := authContext.ParseRequestedAcrValues()

			if len(requestedAcrValues) == 1 && requestedAcrValues[0] == enums.AcrLevel3 {
				// requested acr level 3 (otp mandatory)
				max := userSession.Started.Add(time.Second * time.Duration(settings.AcrLevel3MaxAgeInSeconds))
				isValid := utcNow.Before(max) || utcNow.Equal(max)
				if isValid {
					return enums.AcrLevel3
				}
			} else {
				// requested acr level 2 (otp optional)
				max := userSession.Started.Add(time.Second * time.Duration(settings.AcrLevel2MaxAgeInSeconds))
				isValid := utcNow.Before(max) || utcNow.Equal(max)
				if isValid {
					return enums.AcrLevel2
				}
			}
		} else if pwdAuth {
			// authenticated with pwd only
			max := userSession.Started.Add(time.Second * time.Duration(settings.AcrLevel1MaxAgeInSeconds))
			isValid := utcNow.Before(max) || utcNow.Equal(max)

			if isValid {
				return enums.AcrLevel1
			}
		}

	}
	return enums.AcrLevel0
}
