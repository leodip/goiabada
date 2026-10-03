package handlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// respondAuthorizationCode redeems a validated code (RFC 6749 section 4.1.3) and answers with its
// tokens. A code whose claim was lost is answered as the validator answers an invalid one, since a
// concurrent redemption and a revocation cannot be told apart from here (#77, #129).
func (tr tokenResponder) respondAuthorizationCode(w http.ResponseWriter, r *http.Request,
	settings *record.Settings, grant *protocolvalidation.AuthorizationCodeGrant) {

	tokenResponse, err := tr.issuer.IssueAuthorizationCodeGrant(r.Context(), settings, grant.Code)
	if errors.Is(err, issuance.ErrCodeNotClaimed) {
		tr.jsonWriter.JSONError(w, r, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"Code is invalid.", http.StatusBadRequest))
		return
	}
	if err != nil {
		tr.jsonWriter.JSONError(w, r, err)
		return
	}

	tr.auditLogger.Log(r.Context(), audit.EventTokenIssuedAuthorizationCodeResponse, map[string]interface{}{
		"codeId": grant.Code.Id,
	})

	tr.writeTokenResponse(w, r, tokenResponse)
}
