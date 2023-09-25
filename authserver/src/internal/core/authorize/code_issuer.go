package core

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"golang.org/x/exp/slices"
)

type CodeIssuer struct {
	database core.Database
}

type CreateCodeInput struct {
	dtos.AuthContext
	UserId      uint
	AcrLevel    string
	AuthMethods string
}

func NewCodeIssuer(database core.Database) *CodeIssuer {
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
		ClientID:            client.ID,
		AuthenticatedAt:     time.Now().UTC(),
		UserID:              input.UserId,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		RedirectUri:         input.RedirectUri,
		Scope:               scope,
		State:               input.State,
		Nonce:               input.Nonce,
		UserAgent:           input.UserAgent,
		ResponseMode:        responseMode,
		IpAddress:           input.IpAddress,
		AcrLevel:            input.AcrLevel,
		AuthMethods:         input.AuthMethods,
		SessionIdentifier:   input.SessionIdentifier,
		Used:                false,
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

		level1 := slices.Contains(authMethods, enums.AuthMethodPassword.String())

		level2 := level1 && (slices.Contains(authMethods, enums.AuthMethodOTP.String()))

		if level2 {
			// authenticated with pwd or pin + totp or sms or email
			max := userSession.Started.Add(time.Second * time.Duration(settings.AcrLevel2MaxAgeInSeconds))
			isValid := utcNow.Before(max) || utcNow.Equal(max)

			if isValid {
				return enums.AcrLevel2
			}
		} else if level1 {
			// authenticated with level 1 (pwd or pin) only
			max := userSession.Started.Add(time.Second * time.Duration(settings.AcrLevel1MaxAgeInSeconds))
			isValid := utcNow.Before(max) || utcNow.Equal(max)

			if isValid {
				return enums.AcrLevel1
			}
		}

	}
	return enums.AcrLevel0
}
