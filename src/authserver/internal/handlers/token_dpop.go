package handlers

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/core/errs"
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
// checker for the public base URL, the server nonces whose freshness stands in for the proof's iat
// there (#42 decisions 7 and 8), and the replay store that makes each proof single-use (decision 9).
type TokenProofs struct {
	Checker *dpop.Checker
	Nonces  *dpop.Nonces
	Replays dpopProofRecorder
	// Now is the server's clock, time.Now when nil.
	Now func() time.Time
}

// dpopProofRecorder is the replay store: it records a proof's replay key until expiresAt, and
// reports false when the key was recorded before, by this instance or another sharing the database.
type dpopProofRecorder interface {
	RecordDPoPProof(ctx context.Context, tx *sql.Tx, proofHash string, expiresAt time.Time) (bool, error)
}

func (p TokenProofs) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// checkTokenProof checks the request's proofs, every value of its DPoP header, at now, and returns
// the accepted proof, whose key the access token is bound to. A proof with no nonce, or one
// the server does not accept, is refused use_dpop_nonce, and a proof failing any other check
// invalid_dpop_proof with a Warn record, both 400 (RFC 9449 sections 5 and 8). The answer carries
// the fresh nonce the handler set before. clientIdentifier is the one the request named, not yet
// authenticated, for the record.
func (p TokenProofs) checkTokenProof(r *http.Request, values []string, now time.Time, clientIdentifier string) (*dpop.Proof, error) {
	proof, err := p.Checker.Check(dpop.Request{
		Proofs:       values,
		Method:       r.Method,
		Path:         r.URL.EscapedPath(),
		Now:          now,
		NonceIsValid: func(nonce string) bool { return p.Nonces.Accepts(nonce, now) },
	})
	switch {
	case err == nil:
		return proof, nil
	case errors.Is(err, dpop.ErrNonceRequired):
		// Every DPoP client's first token request ends here, and retries: not a refusal to warn of.
		slog.DebugContext(r.Context(), "dpop nonce required at the token endpoint",
			"reason", err.Error(),
			"grant_type", requestedGrantType(r).String())
		return nil, oauth.NewErrorDetailWithHTTPStatus("use_dpop_nonce", useDPoPNonceDescription, http.StatusBadRequest)
	case errors.Is(err, dpop.ErrInvalidProof):
		// The reason as a message, as a refused client authentication's is: a client's mistake, with
		// no stack to read.
		slog.WarnContext(r.Context(), "dpop proof refused at the token endpoint",
			"reason", err.Error(),
			"client_identifier", logging.FieldForLog(clientIdentifier),
			"grant_type", requestedGrantType(r).String())
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_dpop_proof", invalidDPoPProofDescription, http.StatusBadRequest)
	default:
		return nil, err
	}
}

// recordTokenProof records an accepted proof in the replay store until its nonce expires, the last
// moment the token endpoint could accept it again (#42 decisions 8 and 9). It runs once the grant
// has validated, just before anything is minted, so only a request that would otherwise succeed
// spends its proof. A proof recorded before is a replay, refused invalid_dpop_proof with a Warn
// record, 400 (RFC 9449 section 11.1). A store that cannot answer is returned as the fault it is,
// answered 500: the request never goes ahead unchecked.
func (p TokenProofs) recordTokenProof(r *http.Request, proof *dpop.Proof, clientIdentifier string) error {
	expiresAt, ok := p.Nonces.ExpiresAt(proof.Nonce)
	if !ok {
		// Unreachable: the checker accepted this nonce under these nonces' key.
		return errs.New("the accepted DPoP proof carries a nonce with no expiry")
	}
	recorded, err := p.Replays.RecordDPoPProof(r.Context(), nil, proof.ReplayKey(), expiresAt)
	if err != nil {
		return errs.Wrap(err, "unable to record the DPoP proof in the replay store")
	}
	if !recorded {
		slog.WarnContext(r.Context(), "dpop proof refused at the token endpoint",
			"reason", dpop.ErrInvalidProof.Error()+": it has been used before",
			"client_identifier", logging.FieldForLog(clientIdentifier),
			"grant_type", requestedGrantType(r).String())
		return oauth.NewErrorDetailWithHTTPStatus("invalid_dpop_proof", invalidDPoPProofDescription, http.StatusBadRequest)
	}
	return nil
}
