package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
)

// respondClientCredentials issues a validated client credentials grant (RFC 6749 section 4.4.3) and
// answers with its access token.
func (tr tokenResponder) respondClientCredentials(w http.ResponseWriter, r *http.Request,
	settings *models.Settings, grant *protocolvalidation.ClientCredentialsGrant) {

	tokenResponse, err := tr.issuer.IssueClientCredentialsGrant(r.Context(), settings, grant.Client, grant.Scope)
	if err != nil {
		tr.jsonWriter.JSONError(w, r, err)
		return
	}

	tr.auditLogger.Log(r.Context(), audit.EventTokenIssuedClientCredentialsResponse, map[string]interface{}{
		"clientId": grant.Client.Id,
		// Which scopes were issued, to whom. Absent before, which is why exploitation of
		// the #104 cross-resource escalation cannot be reconstructed from the audit log for
		// any period before this release. Forward-looking only.
		"scope": grant.Scope,
	})

	tr.writeTokenResponse(w, r, tokenResponse)
}
