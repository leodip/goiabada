package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
)

// respondPassword issues a validated resource owner password credentials grant (RFC 6749 section
// 4.3.3) and answers with its tokens.
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
//
// No session identifier is read here on purpose. middleware.SessionIdentifier is mounted globally,
// so a browser cookie's session lands in the request context even on the token endpoint, and
// forwarding it made a password grant for one user carry another user's session identifier in its
// ID token whenever the browser was logged in as somebody else. ROPC is a direct credential
// exchange with no session of its own (#106).
func (tr tokenResponder) respondPassword(w http.ResponseWriter, r *http.Request,
	settings *models.Settings, grant *protocolvalidation.PasswordGrant) {

	tokenResponse, err := tr.issuer.IssuePasswordGrant(r.Context(), settings, &issuance.ROPCGrantInput{
		Client: grant.Client,
		User:   grant.User,
		Scope:  grant.Scope,
	})
	if err != nil {
		tr.jsonWriter.JsonError(w, r, err)
		return
	}

	tr.auditLogger.Log(r.Context(), audit.EventTokenIssuedROPCResponse, map[string]interface{}{
		"userId":   grant.User.Id,
		"clientId": grant.Client.Id,
	})

	tr.writeTokenResponse(w, r, tokenResponse)
}
