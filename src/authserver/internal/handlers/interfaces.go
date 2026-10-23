package handlers

import (
	"bytes"
	"context"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"

	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
)

// PageRenderer and JSONWriter are the two ways a handler here answers, and a handler is handed
// exactly one of them. The token, userinfo, JWKS and discovery endpoints take JSONWriter alone, so
// an HTML error page on one of them is a compile error rather than a review finding (#435). Every other handler answers pages and takes PageRenderer. The concrete
// render.Renderer satisfies both, so routes.go builds it once.
type PageRenderer interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	NotFound(w http.ResponseWriter, r *http.Request)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
}

// JSONWriter answers the JSON endpoints. JSONError writes an ErrorDetail in the RFC 6749 section
// 5.2 shape and anything else as a 500 server_error.
type JSONWriter interface {
	JSONError(w http.ResponseWriter, r *http.Request, err error)
	EncodeJSON(w http.ResponseWriter, r *http.Request, data interface{})
}

// CeremonyStore is what the ceremony's HTTP side calls on ceremony.Store, which keeps the
// AuthContext in the browser session between hops: the route boundary loads the ceremony through
// it, and every write an authflow operation makes reaches it through the per-request adapter
// (browserSession), with the request and the response writer of the request at hand. UILocales is
// on the concrete type and not here: only the locale middleware reads it, and no handler does
// (#435).
type CeremonyStore interface {
	// GetAuthContext reads the ceremony the request names (ceremony.RequestedId). It answers
	// ceremony.ErrCeremonyNotHeld when the browser session holds a ceremony but not that one, and
	// ceremony.ErrNoAuthContext when it holds none.
	GetAuthContext(r *http.Request) (*ceremony.AuthContext, error)
	// LatestAuthContext reads the ceremony the browser most recently wrote, whatever the request
	// names, which the ceremony mismatch audit event records.
	LatestAuthContext(r *http.Request) (*ceremony.AuthContext, error)
	// SaveAuthContext is a step's save, which writes only while the browser session still holds
	// the step's ceremony, making it the most recently written, and otherwise answers
	// ceremony.ErrCeremonyReplaced, writing nothing (#579, #246). Every step after /auth/authorize saves through it, and answers that error through
	// CeremonyBoundary.answerStepSaveFailure.
	SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *ceremony.AuthContext) error
	// AddAuthContext is /auth/authorize's save, which starts a ceremony beside the ones the
	// browser session holds, pushing out the least recently written beyond
	// ceremony.MaxHeldCeremonies (#246).
	AddAuthContext(w http.ResponseWriter, r *http.Request, authContext *ceremony.AuthContext) error
	// ClearAuthContext is a step's clear, which ends the ceremony only while the browser session
	// still holds it and otherwise answers ceremony.ErrCeremonyReplaced, writing nothing (#579).
	ClearAuthContext(w http.ResponseWriter, r *http.Request, ceremonyId string) error
	// RegenerateSession replaces the browser session's identifier without losing its
	// contents, which is what a server-side session store must do at every privilege
	// change to match a cookie store's structural immunity to session fixation (#266). It
	// rotates only while the browser session still holds the ceremony named, and otherwise
	// answers ceremony.ErrCeremonyReplaced, writing nothing (#579). It keeps no ceremony held for a
	// user other than userId, the user the rotation is for (#246).
	RegenerateSession(w http.ResponseWriter, r *http.Request, ceremonyId string, userId int64) error
	// RegenerateSessionAndBind is RegenerateSession for /auth/completed's create arm, which also
	// writes the new user session's identifier into the browser session as it rotates it (#266),
	// on the same condition (#579 decision 4).
	RegenerateSessionAndBind(w http.ResponseWriter, r *http.Request, ceremonyId string, userId int64,
		userSessionIdentifier string) error
	// ConfirmCeremony answers nil while the browser session, read afresh, still holds the
	// ceremony named, and ceremony.ErrCeremonyReplaced otherwise. It writes nothing (#579).
	ConfirmCeremony(w http.ResponseWriter, r *http.Request, ceremonyId string) error
}

// TokenIssuer redeems a validated grant at the token endpoint, one method per grant. Each owns its
// grant from the claim on what is redeemed to the minted tokens, so the handler parses, dispatches,
// audits and answers, and writes nothing of a grant itself (#437).
type TokenIssuer interface {
	IssueAuthorizationCodeGrant(ctx context.Context, settings *record.Settings, code *record.Code) (*oauth.TokenResponse, error)
	IssueClientCredentialsGrant(ctx context.Context, settings *record.Settings, client *record.Client, scope string) (*oauth.TokenResponse, error)
	IssueRefreshTokenGrant(ctx context.Context, settings *record.Settings, input *issuance.RefreshTokenGrantInput) (*oauth.TokenResponse, *issuance.RefreshOutcome, error)
	// IssuePasswordGrant issues the resource owner password credentials grant, RFC 6749 section 4.3.
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
	IssuePasswordGrant(ctx context.Context, settings *record.Settings, input *issuance.ROPCGrantInput) (*oauth.TokenResponse, error)
}

type TokenValidator interface {
	ValidateTokenRequest(ctx context.Context, settings *record.Settings, input *protocolvalidation.ValidateTokenRequestInput) (protocolvalidation.TokenGrant, error)
}

type TokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, withExpirationCheck bool) (*oauth.JwtToken, error)
}

// AuditLogger records one security event. The context is first because every audit event raised
// while serving a request is correlated to that request: the installed slog handler reads the
// request id core/requestid's middleware put on it, so the console record joins the request's own
// log line, and the persisted row carries the same id. A call that passed context.Background() here would produce exactly the
// uncorrelated record this exists to prevent, which is why guard.AssertAuditLogContext refuses
// one in a request-path package (#328).
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// CredentialFailureRecorder marks the credential check this request performed as failed, so
// the rate limiter charges the reservation it is holding instead of dropping it.
//
// A handler names no bucket and no key: the limiter chose those before the handler ran, and
// a handler deriving them again could disagree with the limiter about which account the
// request is (#219). *middleware.RateLimiter satisfies it, and the call is a
// no-op on a request that carries no reservation.
type CredentialFailureRecorder interface {
	RecordCredentialFailure(r *http.Request)
}
