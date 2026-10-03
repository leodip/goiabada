package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/core/oauth"
)

// authCodeNotAuthorizedErrorMsg refuses a refresh token that an authorization code minted, for a
// client whose authorization code flow is now off. The wording is what the token validator's
// refresh arm carried before the gate moved below replay containment, kept verbatim so that half of
// the endpoint's observable behaviour did not change (#250). The gate itself is the refresh
// redemption's, in issuance; the answer is this handler's.
const authCodeNotAuthorizedErrorMsg = "The client associated with the provided client_id does not support authorization code flow."

// revokedRefreshTokenMessage answers a refresh token that is no longer live, whether the validator
// read it revoked (a replay, whose family was just contained) or its claim was lost to a concurrent
// rotation or revocation. The client can act on neither differently (#128).
const revokedRefreshTokenMessage = "This refresh token has been revoked."

// respondRefreshToken redeems a validated refresh (RFC 6749 section 6) and answers with the new
// token set. Its three refusals are the redemption's: a replayed token, audited when containment
// revoked anything; a token whose issuing flow is off for the client (#250); and a lost claim.
func (tr tokenResponder) respondRefreshToken(w http.ResponseWriter, r *http.Request,
	settings *models.Settings, grant *protocolvalidation.RefreshTokenGrant) {

	tokenResponse, outcome, err := tr.issuer.IssueRefreshTokenGrant(r.Context(), settings, &issuance.RefreshTokenGrantInput{
		Client:         grant.Client,
		RefreshToken:   grant.RefreshToken,
		ScopeRequested: grant.ScopeRequested,
		IsROPC:         grant.IsROPC,
	})
	var replayed *issuance.RefreshTokenReplayedError
	switch {
	case errors.As(err, &replayed):
		tr.auditRefreshTokenReplay(r.Context(), grant, replayed.FamilyRevokedCount, replayed.FamilyRecorded)
		tr.jsonWriter.JsonError(w, r, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			revokedRefreshTokenMessage, http.StatusBadRequest))
		return
	case errors.Is(err, issuance.ErrRefreshFlowDisabled):
		description := authCodeNotAuthorizedErrorMsg
		if grant.IsROPC {
			description = protocolvalidation.ROPCNotAuthorizedErrorMsg
		}
		tr.jsonWriter.JsonError(w, r, oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
			description, http.StatusBadRequest))
		return
	case errors.Is(err, issuance.ErrRefreshTokenNotClaimed), errors.Is(err, issuance.ErrRefreshFamilyRevoked):
		// A family revoked between the validator's read and the rotation gets the lost claim's
		// answer: the client can act on neither differently, and the record says nothing about
		// why (#132, #259).
		tr.jsonWriter.JsonError(w, r, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			revokedRefreshTokenMessage, http.StatusBadRequest))
		return
	case err != nil:
		tr.jsonWriter.JsonError(w, r, err)
		return
	}

	refreshToken := grant.RefreshToken
	if grant.IsROPC {
		tr.auditLogger.Log(r.Context(), audit.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
			"userId":          refreshToken.UserId.Int64,
			"clientId":        refreshToken.ClientId.Int64,
			"refreshTokenJti": refreshToken.RefreshTokenJti,
			"flow":            "ropc",
		})
	} else {
		if outcome.BumpedSession != nil {
			tr.auditLogger.Log(r.Context(), audit.AuditBumpedUserSession, map[string]interface{}{
				"userId":   outcome.BumpedSession.UserId,
				"clientId": refreshToken.Code.ClientId,
			})
		}
		tr.auditLogger.Log(r.Context(), audit.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
			"codeId":          refreshToken.Code.Id,
			"refreshTokenJti": refreshToken.RefreshTokenJti,
			"flow":            "auth_code",
		})
	}

	tr.writeTokenResponse(w, r, tokenResponse)
}

// auditRefreshTokenReplay records a replay whose containment moved at least one family member from
// live to revoked, or wrote the family's revocation record. A zero count and no record means
// containment changed no state, which an already-swept family, an earlier auth-code-reuse cascade
// and a repeated replay all produce. Suppressing the event there avoids duplicate and misattributed
// audit rows and stops a client amplifying the log by replaying the same token repeatedly.
//
// The record counts on its own because a rotation in flight holds no live row to revoke: the
// containment that arrives between its claim and its insert revokes nothing, yet it contained the
// family, and the event is the only trace of the theft it answered (#132).
//
// It does NOT classify the presentation as benign. A repeated replay may well be malicious; it
// simply caused no new containment, and the presentation that DID contain the family is the one
// that recorded it.
func (tr tokenResponder) auditRefreshTokenReplay(ctx context.Context, grant *protocolvalidation.RefreshTokenGrant,
	revokedCount int64, recorded bool) {

	refreshToken := grant.RefreshToken
	if revokedCount == 0 && !recorded {
		slog.DebugContext(ctx, "revoked refresh token presented, with no live family members to revoke",
			"grant_type", oidc.GrantTypeRefreshToken.String(),
			"refresh_token_id", refreshToken.Id)
		return
	}

	// The principal fields are populated uniformly for both linkage shapes, so a security-event
	// consumer does not need flow-specific logic just to identify the client and user. This
	// deliberately departs from AuditTokenIssuedRefreshTokenResponse, which logs codeId on one shape
	// and userId/clientId on the other.
	replayClientId := refreshToken.ClientId.Int64
	replayUserId := refreshToken.UserId.Int64
	replayFlow := "ropc"
	if !grant.IsROPC {
		replayClientId = refreshToken.Code.ClientId
		replayUserId = refreshToken.Code.UserId
		replayFlow = "auth_code"
	}

	tr.auditLogger.Log(ctx, audit.AuditRefreshTokenReplayDetected, map[string]interface{}{
		"presentedRefreshTokenJti": refreshToken.RefreshTokenJti,
		"firstRefreshTokenJti":     refreshToken.FirstRefreshTokenJti,
		"revokedCount":             revokedCount,
		"clientId":                 replayClientId,
		"userId":                   replayUserId,
		"flow":                     replayFlow,
	})
}
