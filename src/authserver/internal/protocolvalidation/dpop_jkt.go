package protocolvalidation

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// An authorization request's dpop_jkt binds the code it yields to one DPoP key (RFC 9449 section 10,
// #42 decision 14): the authorization endpoint holds the value to the canonical form of a SHA-256
// JWK thumbprint, and the token endpoint redeems a bound code only with a proof by that key.

// dpopJktRuleText is the rule a dpop_jkt is refused under: RFC 7638's SHA-256 thumbprint, which is
// the canonical form isBase64URLSHA256 accepts (#42 decision 20).
const dpopJktRuleText = "It must be the SHA-256 JWK thumbprint of the DPoP key (RFC 7638), base64url-encoded without padding: " +
	"43 characters of A-Z, a-z, 0-9, '-' and '_'."

// dpopJktRefusal answers a dpop_jkt that cannot be a SHA-256 thumbprint, invalid_request, before
// the sign-in: a code bound to it could never be redeemed.
func dpopJktRefusal() error {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
		"The dpop_jkt parameter is incorrect. "+dpopJktRuleText, http.StatusBadRequest)
}

// dpopJktWithoutCodeRefusal answers a dpop_jkt beside a response type that returns no code, so
// nothing could be bound to the key.
func dpopJktWithoutCodeRefusal() error {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
		"The dpop_jkt parameter binds the authorization code to a DPoP key, so it is accepted only with response_type=code.",
		http.StatusBadRequest)
}

// BoundCodeMessage refuses a code bound to a DPoP key when the request carries no proof by that
// key: none at all, or a valid one by another key (#42 decision 14). invalid_grant, which tells the
// client the code cannot be used, where invalid_dpop_proof would invite a retry that cannot succeed.
const BoundCodeMessage = "The authorization code is bound to a DPoP key, and the request carries no proof by that key."

// refuseCodeWithoutItsKey refuses the redemption of a code bound to a DPoP key unless the request's
// proof is by that key, with a Warn record, as a refused client authentication is. thumbprint is the
// request's proof key, empty when it carries no proof; the proof itself was checked at the endpoint.
func refuseCodeWithoutItsKey(ctx context.Context, client *record.Client, code *record.Code, thumbprint string) error {
	if !code.DPoPJkt.Valid || code.DPoPJkt.String == thumbprint {
		return nil
	}
	reason := "the request's dpop proof is by another key"
	if thumbprint == "" {
		reason = "the request carries no dpop proof"
	}
	slog.WarnContext(ctx, "authorization code refused for its dpop binding",
		"reason", reason,
		"client_identifier", client.ClientIdentifier,
		"code_id", code.Id)
	return oauth.NewErrorDetailWithHTTPStatus("invalid_grant", BoundCodeMessage, http.StatusBadRequest)
}
