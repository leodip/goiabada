package core

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/entities"

	"github.com/leodip/goiabada/internal/dtos"

	"github.com/leodip/goiabada/internal/lib"
)

type CodeIssuer struct {
	database data.Database
}

type CreateCodeInput struct {
	dtos.AuthContext
	SessionIdentifier string
}

func NewCodeIssuer(database data.Database) *CodeIssuer {
	return &CodeIssuer{
		database: database,
	}
}

func (ci *CodeIssuer) CreateAuthCode(ctx context.Context, input *CreateCodeInput) (*entities.Code, error) {

	responseMode := input.ResponseMode
	if responseMode == "" {
		responseMode = "query"
	}

	client, err := ci.database.GetClientByClientIdentifier(nil, input.ClientId)
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

	authCode := strings.ReplaceAll(uuid.New().String(), "-", "") + lib.GenerateSecureRandomString(96)
	authCodeHash, err := lib.HashString(authCode)
	if err != nil {
		return nil, err
	}
	code := &entities.Code{
		Code:                authCode,
		CodeHash:            authCodeHash,
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
		AcrLevel:            input.AcrLevel,
		AuthMethods:         input.AuthMethods,
		SessionIdentifier:   input.SessionIdentifier,
		Used:                false,
	}

	err = ci.database.CreateCode(nil, code)
	if err != nil {
		return nil, err
	}

	lib.LogAudit(constants.AuditCreatedAuthCode, map[string]interface{}{
		"userId":   input.UserId,
		"clientId": client.Id,
	})

	return code, nil
}
