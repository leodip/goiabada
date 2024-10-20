package oauth

import (
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
)

type CodeIssuer struct {
	database data.Database
}

type CreateCodeInput struct {
	AuthContext
	SessionIdentifier string
}

func NewCodeIssuer(database data.Database) *CodeIssuer {
	return &CodeIssuer{
		database: database,
	}
}

func (ci *CodeIssuer) CreateAuthCode(input *CreateCodeInput) (*models.Code, error) {

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

	authCode := strings.ReplaceAll(uuid.New().String(), "-", "") + stringutil.GenerateSecurityRandomString(96)
	authCodeHash, err := hashutil.HashString(authCode)
	if err != nil {
		return nil, err
	}
	code := &models.Code{
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

	return code, nil
}
