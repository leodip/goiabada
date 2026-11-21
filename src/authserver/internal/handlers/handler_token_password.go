package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/clientauth"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
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
	settings *record.Settings, grant *protocolvalidation.PasswordGrant, dpopThumbprint string) {

	tokenResponse, err := tr.issuer.IssuePasswordGrant(r.Context(), settings, &issuance.ROPCGrantInput{
		Client:         grant.Client,
		User:           grant.User,
		Scope:          grant.Scope,
		DPoPThumbprint: dpopThumbprint,
	})
	if errors.Is(err, issuance.ErrPasswordGrantClientRenamed) {
		// The client was renamed, or deleted, after the request named it, and before the grant wrote
		// its first refresh token: the request named an identifier no client holds now, and is
		// answered as such a request is (#710 decision 5). The answer says nothing of the rename, so
		// the record says it.
		slog.WarnContext(r.Context(), "password grant refused: the client no longer holds the identifier the request named",
			"client_id", grant.Client.ID)
		tr.refuse(w, r, oidc.GrantTypePassword, clientauth.ClientDoesNotExist())
		return
	}
	if err != nil {
		tr.refuse(w, r, oidc.GrantTypePassword, err)
		return
	}

	tr.auditLogger.Log(r.Context(), audit.EventTokenIssuedROPCResponse, map[string]interface{}{
		"user_id":   grant.User.ID,
		"client_id": grant.Client.ID,
	})

	tr.writeTokenResponse(w, r, oidc.GrantTypePassword, tokenResponse)
}
