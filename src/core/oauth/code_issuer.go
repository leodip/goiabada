package oauth

import (
	"database/sql"
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

// CreateAuthCode inserts one authorization code. Both of its statements run on tx, which the
// caller opens: the insert has to be ordered against a concurrent session termination, and the
// client lookup has to join it because sqlitedb sets SetMaxOpenConns(1), so a nil-transaction read
// issued while tx holds the single connection waits for a connection tx itself owns. That is a
// hang rather than an error, so neither statement may be reverted to nil (#139).
func (ci *CodeIssuer) CreateAuthCode(tx *sql.Tx, input *CreateCodeInput) (*models.Code, error) {

	responseMode := input.ResponseMode
	if responseMode == "" {
		responseMode = "query"
	}

	client, err := ci.database.GetClientByClientIdentifier(tx, input.ClientId)
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
	// Handle PKCE fields - store as NULL if not provided
	var codeChallenge, codeChallengeMethod sql.NullString
	if input.CodeChallenge != "" {
		codeChallenge = sql.NullString{String: input.CodeChallenge, Valid: true}
		codeChallengeMethod = sql.NullString{String: input.CodeChallengeMethod, Valid: true}
	}

	// Use provided AuthenticatedAt if set (for prompt=none), otherwise use current time
	authenticatedAt := time.Now().UTC()
	if input.AuthenticatedAt != nil && !input.AuthenticatedAt.IsZero() {
		authenticatedAt = *input.AuthenticatedAt
	}

	code := &models.Code{
		Code:                authCode,
		CodeHash:            authCodeHash,
		ClientId:            client.Id,
		AuthenticatedAt:     authenticatedAt,
		UserId:              input.UserId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
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
		// From the AuthContext, which captured it when this ceremony authenticated.
		// Redemption compares it against the user's current value, so a code issued by a
		// ceremony that straddled a credential change is rejected (#106 decision 11).
		AuthStateGeneration: input.AuthStateGeneration,
	}

	err = ci.database.CreateCode(tx, code)
	if err != nil {
		return nil, err
	}

	return code, nil
}
