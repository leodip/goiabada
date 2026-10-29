package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/leodip/goiabada/authserver/internal/clientauth"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/liveness"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/ratelimit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/revocationmetrics"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/requestid"
)

// revokeDatabase is what the revocation endpoint reads and writes: the calling client, the state the
// two liveness checks read, the client a refresh token was issued to, the grant it revokes, and the
// jti of an access token without a grant it stores.
type revokeDatabase interface {
	revocation.Database
	revocation.AccessTokenDatabase
	liveness.Database
	liveness.RefreshDatabase
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
}

// revokeRequestParameters are every form parameter the revocation endpoint reads, and so every one
// whose copies must agree (RFC 6749 section 3.2). token_type_hint is not among them: it is never
// read (decision 12), so a repeated one is ignored with it.
var revokeRequestParameters = []string{"token", "client_id", "client_secret"}

// errAnotherClientsToken is decision 8's answer to a client that sent another client's live token:
// RFC 6749 section 5.2's invalid_grant names a grant "issued to another client".
var errAnotherClientsToken = oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
	"The token was issued to another client.", http.StatusBadRequest)

// HandleRevokePost is the token revocation endpoint, RFC 7009 (#676 decisions 1, 8, 9, 10 and 12).
// A client sends one of its tokens, and the whole grant behind it ends: a refresh token's family,
// or the family an access token names as grant_id, is recorded revoked and every member of it
// revoked, which ends the grant's access tokens at the auth server's own endpoints too. An access
// token without a grant, of the client credentials grant or the implicit flow, is revoked on its own:
// its jti is stored until it expires, which ends it at those endpoints as well. A second revocation
// of it finds the token no longer live, and is answered as any invalid token is.
//
// The order is decision 10's countermeasure: the client is authenticated before anything else, as at
// the token endpoint, so a request with no client costs one read of it. The token parser refuses a
// malformed or foreign token before it reads a key, and token_type_hint is never read, so it causes
// no lookup at all: the token says what it is, an access token by its at+jwt header and a refresh
// token by its typ claim.
//
// Then the token is judged by the same liveness checks the auth server's own endpoints apply, and
// only then is its owner compared with the caller (decision 8): an invalid token is answered 200
// whatever client it names (RFC 7009 section 2.2), and a live one of another client 400
// invalid_grant, with nothing revoked.
//
// A fault reading the database or the signing keys is 503, RFC 7009 section 2.2.1's "the token still
// exists, retry later", never the 200 of an invalid token.
func HandleRevokePost(
	jsonWriter JSONWriter,
	database revokeDatabase,
	tokenParser TokenParser,
	dataCipher *encryption.DataCipher,
	auditLogger AuditLogger,
	revocationMetrics *revocationmetrics.Recorder,
) http.HandlerFunc {
	endpoint := revocationEndpoint{
		jsonWriter:       jsonWriter,
		database:         database,
		tokenParser:      tokenParser,
		clients:          clientauth.NewAuthenticator(database, dataCipher),
		auditLogger:      auditLogger,
		metrics:          revocationMetrics,
		refusalAuditGate: ratelimit.New(1, time.Minute).Gate(),
	}
	return endpoint.serve
}

// revocationEndpoint is the revocation endpoint's dependencies, so each step of a request is a method.
type revocationEndpoint struct {
	jsonWriter  JSONWriter
	database    revokeDatabase
	tokenParser TokenParser
	clients     *clientauth.Authenticator
	auditLogger AuditLogger
	metrics     *revocationmetrics.Recorder
	// As for rate-limit refusals, audit the first refusal per key per window on this instance.
	// The key is the verified token owner: public caller identifiers, tokens and token types can
	// change between replays without earning more writes. Only owners seen in two windows are held.
	refusalAuditGate *ratelimit.Gate
}

func (e revocationEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// A body that cannot be parsed is the client's malformed request, as at the token endpoint.
	if err := r.ParseForm(); err != nil {
		e.refuse(w, r, protocolvalidation.UnparseableRequest())
		return
	}
	if err := protocolvalidation.ValidateNoRepeatedParameters(r.PostForm, revokeRequestParameters); err != nil {
		e.refuse(w, r, err)
		return
	}
	clientIdentifier, clientSecret, err := extractClientCredentials(r)
	if err != nil {
		e.refuse(w, r, err)
		return
	}

	// RFC 7009 section 2.1: the client authenticates as at the token endpoint, and a public client
	// by its client_id alone (section 5).
	client, err := e.clients.Authenticate(ctx, clientIdentifier, clientSecret)
	if err != nil {
		var refusal *oauth.ErrorDetail
		if !errors.As(err, &refusal) {
			e.fault(w, r, err)
			return
		}
		atRevocationEndpoint.logClientAuthenticationRefusal(r, clientIdentifier, err)
		e.refuse(w, r, err)
		return
	}

	presented := r.PostForm.Get("token")
	if presented == "" {
		e.refuse(w, r, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Missing required token parameter.", http.StatusBadRequest))
		return
	}

	settings, ok := reqctx.SettingsFrom(ctx)
	if !ok {
		e.fault(w, r, reqctx.ErrNoSettings)
		return
	}

	token, err := e.tokenParser.DecodeAndValidateTokenString(ctx, presented, true)
	if err != nil {
		// A token the parser refused, unsigned by any key, malformed or expired, is invalid. A
		// token it could not check because the keys could not be read says nothing about the
		// token (#680).
		if errors.Is(err, signingkeys.ErrTokenRefused) {
			e.invalid(w)
			return
		}
		e.fault(w, r, errs.Wrap(err, "unable to check the token to revoke"))
		return
	}

	now := time.Now().UTC()
	verdict, err := liveness.AccessToken(ctx, e.database, *token, settings, now)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if verdict.Refusal != liveness.NotAnAccessTokenHeader {
		e.revokeAccessToken(w, r, client, *token, verdict)
		return
	}

	switch token.StringClaim("typ") {
	case issuance.TokenTypeRefresh.String(), issuance.TokenTypeOffline.String():
		e.revokeRefreshToken(w, r, client, *token, settings, now)
	default:
		// An ID token, or an access token issued before #676, which carries the header typ JWT
		// (decision 4): neither is a token this endpoint revokes, and both are answered as invalid.
		e.invalid(w)
	}
}

// revokeAccessToken answers an access token the access-token check has judged.
func (e revocationEndpoint) revokeAccessToken(w http.ResponseWriter, r *http.Request, client *record.Client,
	token oauth.JwtToken, verdict liveness.Verdict) {

	if !verdict.Live() {
		e.invalid(w)
		return
	}
	// A live token's client_id has resolved to an enabled client: the token's owner.
	if verdict.Client.Id != client.Id {
		e.refuseAnotherClientsToken(w, r, client, verdict.Client, revocation.TokenTypeAccessToken)
		return
	}

	// A user's token, of a grant or of the implicit flow, has had its user read by the check; a
	// client's has none.
	var userId int64
	if verdict.User != nil {
		userId = verdict.User.Id
	}
	grantId := token.StringClaim("grant_id")
	if grantId == "" {
		e.revokeByJti(w, r, client, userId, token)
		return
	}
	e.revokeGrant(w, r, client, userId, grantId, revocation.TokenTypeAccessToken)
}

// revokeByJti revokes a live access token without a grant, of the client credentials grant or the
// implicit flow, by storing its jti until it expires (decision 1), audits it, and answers 200 with
// an empty body. The check found its jti not stored, so it carries one. A revocation that overlapped
// this one and stored the jti first leaves nothing for this one to do: it is answered as a token
// already revoked is, and the event is the other's.
func (e revocationEndpoint) revokeByJti(w http.ResponseWriter, r *http.Request, client *record.Client, userId int64,
	token oauth.JwtToken) {

	jti := token.StringClaim("jti")
	stored, err := revocation.RevokeAccessToken(r.Context(), e.database, jti, token.TimeClaim("exp").UTC())
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if !stored {
		e.invalid(w)
		return
	}
	revocation.LogRevokedAccessToken(r.Context(), e.auditLogger, client.Id, userId, jti)
	e.metrics.Count(revocationmetrics.Revoked)
	w.WriteHeader(http.StatusOK)
}

// revokeRefreshToken judges a refresh token by the refresh grant's own check and answers it.
func (e revocationEndpoint) revokeRefreshToken(w http.ResponseWriter, r *http.Request, client *record.Client,
	token oauth.JwtToken, settings *record.Settings, now time.Time) {

	ctx := r.Context()
	stored, err := liveness.FindRefreshToken(ctx, e.database, token)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if stored == nil {
		e.invalid(w)
		return
	}
	refusal, err := liveness.RefreshToken(ctx, e.database, stored, token, settings, now)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if refusal != liveness.RefreshLive {
		e.invalid(w)
		return
	}

	if stored.ClientId != client.Id {
		// The refresh check reads no client, since the refresh grant answers only the token's own,
		// which client authentication found enabled. Here the token's owner is another, so it is
		// read: a token of a client disabled or deleted is not live (decision 6), and is answered as
		// invalid rather than as another client's.
		owner, err := e.database.GetClientById(ctx, nil, stored.ClientId)
		if err != nil {
			e.fault(w, r, err)
			return
		}
		if owner == nil || !owner.Enabled {
			e.invalid(w)
			return
		}
		e.refuseAnotherClientsToken(w, r, client, owner, revocation.TokenTypeRefreshToken)
		return
	}

	if stored.Row.FirstRefreshTokenJti == "" {
		e.fault(w, r, errs.Errorf("the refresh token %v has no family identifier", stored.Row.Id))
		return
	}
	e.revokeGrant(w, r, client, stored.UserId, stored.Row.FirstRefreshTokenJti, revocation.TokenTypeRefreshToken)
}

// revokeGrant ends the grant, audits it once it committed, and answers 200 with an empty body.
func (e revocationEndpoint) revokeGrant(w http.ResponseWriter, r *http.Request, client *record.Client, userId int64,
	grantId string, tokenType string) {

	result, err := revocation.RevokeGrantTx(r.Context(), e.database, grantId)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	revocation.LogRevokedGrant(r.Context(), e.auditLogger, client.Id, userId, grantId, tokenType, result)
	e.metrics.Count(revocationmetrics.Revoked)
	w.WriteHeader(http.StatusOK)
}

// invalid answers a token that is not live, RFC 7009 section 2.2's 200: nothing happened, so nothing
// is recorded.
func (e revocationEndpoint) invalid(w http.ResponseWriter) {
	e.metrics.Count(revocationmetrics.InvalidToken)
	w.WriteHeader(http.StatusOK)
}

// refuseAnotherClientsToken answers decision 8's refusal and records it at most once per token
// owner per minute window on this instance. Every request is still refused and counted.
func (e revocationEndpoint) refuseAnotherClientsToken(w http.ResponseWriter, r *http.Request, client *record.Client,
	owner *record.Client, tokenType string) {

	if e.refusalAuditGate.First(strconv.FormatInt(owner.Id, 10)) {
		revocation.LogTokenRevocationRefused(r.Context(), e.auditLogger, client.Id, owner.Id, tokenType)
	}
	e.refuse(w, r, errAnotherClientsToken)
}

// refuse answers a request the client got wrong with err, RFC 6749 section 5.2's error response.
func (e revocationEndpoint) refuse(w http.ResponseWriter, r *http.Request, err error) {
	e.metrics.Count(revocationmetrics.Refused)
	e.jsonWriter.JSONError(w, r, err)
}

// fault answers a request the server could not decide.
func (e revocationEndpoint) fault(w http.ResponseWriter, r *http.Request, err error) {
	answerRevocationFault(w, r, e.jsonWriter, e.metrics, err)
}

// answerRevocationFault answers a fault at the revocation endpoint, the handler's own or one met
// before it: logged once at Error, counted as error, and answered 503, which RFC 7009 section 2.2.1
// defines as "the token still exists, retry later". temporarily_unavailable is RFC 6749's code for
// that status. The request id is in the description, as in a 500's.
func answerRevocationFault(w http.ResponseWriter, r *http.Request, jsonWriter JSONWriter,
	revocationMetrics *revocationmetrics.Recorder, err error) {

	slog.ErrorContext(r.Context(), "unable to answer a token revocation request", "error", errs.WithStack(err))
	revocationMetrics.Count(revocationmetrics.Error)
	jsonWriter.JSONError(w, r, oauth.NewErrorDetailWithHTTPStatus("temporarily_unavailable",
		fmt.Sprintf("The token could not be revoked. Retry later. Request Id: %v", requestid.FromContext(r.Context())),
		http.StatusServiceUnavailable))
}

// RevocationFaultWriter is the revocation endpoint's error writer for the faults met before its
// handler runs, the settings or the session failing to load or a panic, on the branch the endpoint
// alone is registered on: each is answered as the handler answers its own.
type RevocationFaultWriter struct {
	jsonWriter JSONWriter
	metrics    *revocationmetrics.Recorder
}

// RevocationFaults returns the revocation branch's fault writer, answering through jsonWriter.
func RevocationFaults(jsonWriter JSONWriter, revocationMetrics *revocationmetrics.Recorder) RevocationFaultWriter {
	return RevocationFaultWriter{jsonWriter: jsonWriter, metrics: revocationMetrics}
}

// JSONError answers err as a fault of the revocation endpoint.
func (w RevocationFaultWriter) JSONError(rw http.ResponseWriter, r *http.Request, err error) {
	answerRevocationFault(rw, r, w.jsonWriter, w.metrics, err)
}
