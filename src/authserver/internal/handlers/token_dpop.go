package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/oauth"
)

// The descriptions of the token endpoint's two DPoP refusals (RFC 9449 sections 5 and 8). The
// second is the RFC's own example.
const (
	invalidDPoPProofDescription = "The DPoP proof is invalid."
	useDPoPNonceDescription     = "Authorization server requires nonce in DPoP proof."
)

// TokenProofs is how the token endpoint checks a request's DPoP proof (RFC 9449 section 5): the
// checker for the public base URL, and the server nonces whose freshness stands in for the proof's
// iat there (#42 decisions 7 and 8).
type TokenProofs struct {
	Checker *dpop.Checker
	Nonces  *dpop.Nonces
	// Now is the server's clock, time.Now when nil.
	Now func() time.Time
}

func (p TokenProofs) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// checkTokenProof checks the request's proofs, every value of its DPoP header, at now, and returns
// the RFC 7638 thumbprint of the key the access token is bound to. A proof with no nonce, or one
// the server does not accept, is refused use_dpop_nonce, and a proof failing any other check
// invalid_dpop_proof with a Warn record, both 400 (RFC 9449 sections 5 and 8). The answer carries
// the fresh nonce the handler set before. clientIdentifier is the one the request named, not yet
// authenticated, for the record.
func (p TokenProofs) checkTokenProof(r *http.Request, values []string, now time.Time, clientIdentifier string) (string, error) {
	proof, err := p.Checker.Check(dpop.Request{
		Proofs:       values,
		Method:       r.Method,
		Path:         r.URL.EscapedPath(),
		Now:          now,
		NonceIsValid: func(nonce string) bool { return p.Nonces.Accepts(nonce, now) },
	})
	switch {
	case err == nil:
		return proof.Thumbprint, nil
	case errors.Is(err, dpop.ErrNonceRequired):
		// Every DPoP client's first token request ends here, and retries: not a refusal to warn of.
		slog.DebugContext(r.Context(), "dpop nonce required at the token endpoint",
			"reason", err.Error(),
			"grant_type", requestedGrantType(r).String())
		return "", oauth.NewErrorDetailWithHTTPStatus("use_dpop_nonce", useDPoPNonceDescription, http.StatusBadRequest)
	case errors.Is(err, dpop.ErrInvalidProof):
		// The reason as a message, as a refused client authentication's is: a client's mistake, with
		// no stack to read.
		slog.WarnContext(r.Context(), "dpop proof refused at the token endpoint",
			"reason", err.Error(),
			"client_identifier", logging.FieldForLog(clientIdentifier),
			"grant_type", requestedGrantType(r).String())
		return "", oauth.NewErrorDetailWithHTTPStatus("invalid_dpop_proof", invalidDPoPProofDescription, http.StatusBadRequest)
	default:
		return "", err
	}
}
