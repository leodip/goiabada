package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
)

func SetCodeInsertColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, code *entitiesv2.Code) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("codes")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"code_hash",
		"client_id",
		"code_challenge",
		"code_challenge_method",
		"scope",
		"state",
		"nonce",
		"redirect_uri",
		"user_id",
		"ip_address",
		"user_agent",
		"response_mode",
		"authenticated_at",
		"session_identifier",
		"acr_level",
		"auth_methods",
		"used",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		code.CodeHash,
		code.ClientId,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.Scope,
		code.State,
		code.Nonce,
		code.RedirectURI,
		code.UserId,
		code.IpAddress,
		code.UserAgent,
		code.ResponseMode,
		code.AuthenticatedAt,
		code.SessionIdentifier,
		code.AcrLevel,
		code.AuthMethods,
		code.Used,
	)

	return insertBuilder
}

func ScanCode(rows *sql.Rows) (*entitiesv2.Code, error) {
	var (
		id                    int64
		created_at            time.Time
		updated_at            time.Time
		code_hash             string
		client_id             int64
		code_challenge        string
		code_challenge_method string
		scope                 string
		state                 string
		nonce                 string
		redirect_uri          string
		user_id               int64
		ip_address            string
		user_agent            string
		response_mode         string
		authenticated_at      time.Time
		session_identifier    string
		acr_level             string
		auth_methods          string
		used                  bool
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&code_hash,
		&client_id,
		&code_challenge,
		&code_challenge_method,
		&scope,
		&state,
		&nonce,
		&redirect_uri,
		&user_id,
		&ip_address,
		&user_agent,
		&response_mode,
		&authenticated_at,
		&session_identifier,
		&acr_level,
		&auth_methods,
		&used,
	)
	if err != nil {
		return nil, err
	}

	return &entitiesv2.Code{
		Id:                  id,
		CreatedAt:           created_at,
		UpdatedAt:           updated_at,
		CodeHash:            code_hash,
		ClientId:            client_id,
		CodeChallenge:       code_challenge,
		CodeChallengeMethod: code_challenge_method,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		RedirectURI:         redirect_uri,
		UserId:              user_id,
		IpAddress:           ip_address,
		UserAgent:           user_agent,
		ResponseMode:        response_mode,
		AuthenticatedAt:     authenticated_at,
		SessionIdentifier:   session_identifier,
		AcrLevel:            acr_level,
		AuthMethods:         auth_methods,
		Used:                used,
	}, nil
}
