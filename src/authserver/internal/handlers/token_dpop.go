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

// TokenDPoPNonce gives every answer to a DPoP request at the token endpoint, one carrying a DPoP
// header, exactly one DPoP-Nonce header with a fresh nonce, whatever the answer (RFC 9449 sections 8
// and 8.2, #42 decision 7), and makes it no-store, as section 8.2 asks of an answer carrying one. It
// is mounted on the token route ahead of everything that can answer the request there, the ROPC
// limiter's 400 for a body that does not parse and its 429 included, so a refusal before the
// handler carries the nonce as the handler's own answers do. It is the one place the endpoint mints
// a nonce.
func TokenDPoPNonce(proofs TokenProofs) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.Header.Values("DPoP")) > 0 {
				h := w.Header()
				h.Set("DPoP-Nonce", proofs.Nonces.Mint(proofs.now()))
				h.Set("Cache-Control", "no-store")
				h.Set("Pragma", "no-cache")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// checkTokenProof checks the request's proofs, every value of its DPoP header, at the server's
// clock, and returns the accepted proof, whose key the access token is bound to. A proof with no
// nonce, or one the server does not accept, is refused use_dpop_nonce, and a proof failing any
// other check invalid_dpop_proof with a Warn record, both 400 (RFC 9449 sections 5 and 8). The
// answer carries the fresh nonce TokenDPoPNonce set. It runs once the form is parsed and before
// anything reads the client's credentials, so the nonce round trip is never a client
// authentication refusal (#42 decision 7). clientIdentifier is the one the request named, not yet
// authenticated, for the record.
func (p TokenProofs) checkTokenProof(r *http.Request, values []string, clientIdentifier string) (*dpop.Proof, error) {
	now := p.now()
	proof, err := p.Checker.Check(dpop.Request{
		Proofs:       values,
		Method:       r.Method,
		Path:         dpop.RequestPath(r.RequestURI, r.URL.EscapedPath()),
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
// moment the token endpoint could accept it again (#42 decisions 8 and 9), and dpop.ReplayRecordGrace
// beyond, for the instances whose clocks run behind the one that sweeps. It runs once the grant has
// validated, just before anything is minted, so only a request that would otherwise succeed spends
// its proof. The nonce is judged again first, at the clock of this moment: a request still being
// validated when its nonce expired is refused use_dpop_nonce, as it would be were it sent now, and
// so can never record as new a proof whose record a sweep has since removed. A proof recorded
// before is a replay, refused invalid_dpop_proof with a Warn record, 400 (RFC 9449 section 11.1). A
// store that cannot answer is returned as the fault it is, answered 500: the request never goes
// ahead unchecked.
func (p TokenProofs) recordTokenProof(r *http.Request, proof *dpop.Proof, clientIdentifier string) error {
	expiresAt, ok := p.Nonces.ExpiresAt(proof.Nonce)
	if !ok {
		// Unreachable: the checker accepted this nonce under these nonces' key.
		return errs.New("the accepted DPoP proof carries a nonce with no expiry")
	}
	if !p.Nonces.Accepts(proof.Nonce, p.now()) {
		slog.DebugContext(r.Context(), "dpop nonce required at the token endpoint",
			"reason", "the proof's nonce expired while the request was validated",
			"grant_type", requestedGrantType(r).String())
		return oauth.NewErrorDetailWithHTTPStatus("use_dpop_nonce", useDPoPNonceDescription, http.StatusBadRequest)
	}
	recorded, err := p.Replays.RecordDPoPProof(r.Context(), nil, proof.ReplayKey(), expiresAt.Add(dpop.ReplayRecordGrace))
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
