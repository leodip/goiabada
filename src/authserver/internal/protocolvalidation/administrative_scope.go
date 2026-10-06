package protocolvalidation

import (
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// RefusedAdministrativeScopes is the administrative scopes in scope that client may not request on
// a user's behalf, in the order scope names them: none for a client that may
// (record.Client.MayRequestAdministrativeScopes), and for any other client every scope of the
// administrative set, which permissions.IsAdministrativeScope defines once for this check and the
// Admin API's policy alike (#499 decisions 2 and 5). scope is space delimited, as a request and a
// ceremony carry it.
func RefusedAdministrativeScopes(client *record.Client, scope string) []string {
	if client.MayRequestAdministrativeScopes() {
		return nil
	}
	var refused []string
	for _, s := range oidc.SplitScope(scope) {
		if permissions.IsAdministrativeScope(s) {
			refused = append(refused, s)
		}
	}
	return refused
}

// AdministrativeScopeRefusal is the answer to a client asking for administrative scopes it may not
// request, naming the first of them: invalid_scope, which RFC 6749 4.1.2.1 and 4.2.2.1 name for a
// requested scope the server will not grant. It refuses rather than narrows, so a misconfigured tool
// is told why instead of receiving a token the Admin API then refuses (#499 decision 7). The
// authorization endpoint, /auth/issue and the password grant answer with it, and the refresh token
// grant's invalid_grant carries it, so one condition gets one sentence wherever it is met. English, as every error_description is: the scope is a validated identifier
// of the administrative set, so the sentence stays within RFC 6749's character set.
func AdministrativeScopeRefusal(refused []string) *oauth.ErrorDetail {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
		fmt.Sprintf("The client is not allowed to request the administrative scope '%v'.", refused[0]),
		http.StatusBadRequest)
}

// AdministrativeScopeRefusedError is the token validator's refusal of administrative scopes the
// client may not request, on the refresh token grant and the password grant (#499 decision 6).
// Detail is what the client is answered with, and Unwrap puts it on the chain, so the writer answers
// it as it answers any ErrorDetail; the type is what tells the token handler to write
// administrative_scope_refused, with what that record names: the client refused, the scopes, and
// the user they were asked for (decision 9). A type rather than a match on the answer, because the
// refresh grant's answer is invalid_grant, which every other refusal of a grant shares.
type AdministrativeScopeRefusedError struct {
	Detail *oauth.ErrorDetail
	Client *record.Client
	Scopes []string
	UserId int64
}

func (e *AdministrativeScopeRefusedError) Error() string {
	return e.Detail.Error()
}

// Unwrap puts Detail on the chain, as UserDisabledError's does.
func (e *AdministrativeScopeRefusedError) Unwrap() error {
	return e.Detail
}
