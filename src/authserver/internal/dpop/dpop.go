// Package dpop reads and checks DPoP proofs, RFC 9449's demonstration of proof of possession: the
// one checker the token endpoint and the auth server's own resources call. It knows nothing of
// HTTP beyond the plain values a request carries, and leaves the answer, the log record and what a
// proof binds to its caller.
package dpop

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// MaxProofBytes is the longest DPoP header value read (#42 decision 9). A longer one is refused
// before it is parsed.
const MaxProofBytes = 8 * 1024

// IssuedAtWindow is how far a proof's iat may lie either side of the server's clock when its
// freshness comes from iat rather than from a server nonce (#42 decision 8). It is fixed, not a
// setting.
const IssuedAtWindow = 60 * time.Second

var (
	// ErrInvalidProof marks a proof that failed a check, answered invalid_dpop_proof (RFC 9449
	// section 5 and 7.1).
	ErrInvalidProof = errors.New("the DPoP proof is invalid")
	// ErrNonceRequired marks a proof that passed every other check without a nonce the server
	// accepts, answered use_dpop_nonce (RFC 9449 section 8). It does not carry ErrInvalidProof.
	ErrNonceRequired = errors.New("the DPoP proof needs a fresh server nonce")
)

// SigningAlgorithms returns the algorithms a proof may be signed with, in the order discovery and
// the DPoP challenge list them (#42 decision 4). The list is written out here, never taken from a
// library, so an upgrade cannot widen it. Each call returns a new slice.
func SigningAlgorithms() []string {
	algs := make([]string, len(signingAlgorithms))
	for i, a := range signingAlgorithms {
		algs[i] = a.name
	}
	return algs
}

// Checker checks proofs sent to the auth server at its public base URL. The internal base URL plays
// no part: a proof naming it is refused (#42 decision 6).
type Checker struct {
	publicBaseURL string
}

// NewChecker returns a checker for requests addressed to publicBaseURL, which must be an absolute
// http or https URL with a host and with no userinfo, query or fragment.
func NewChecker(publicBaseURL string) (*Checker, error) {
	if strings.ContainsAny(publicBaseURL, "?#") {
		return nil, errs.New("the public base URL has a query or a fragment")
	}
	if _, err := normalizeHTTPURI(publicBaseURL); err != nil {
		return nil, errs.Wrap(err, "the public base URL cannot name a request")
	}
	return &Checker{publicBaseURL: publicBaseURL}, nil
}

// Request is what a proof is checked against: plain values from the HTTP request, the server's
// clock, and how the proof's freshness is judged.
type Request struct {
	// Proofs is every value of the request's DPoP header, as http.Header.Values gives them. Exactly
	// one must be present.
	Proofs []string
	// Method is the request's method, which htm must equal exactly.
	Method string
	// Path is the request's path as it arrived, percent-encoding kept (url.URL.EscapedPath). htu
	// must name the public base URL followed by it.
	Path string
	// AccessToken, when not empty, is the access token presented beside the proof, whose hash the
	// proof's ath must be (RFC 9449 section 4.2). Empty, ath is not read.
	AccessToken string
	// Now is the server's clock.
	Now time.Time
	// NonceIsValid, when set, judges the proof's nonce: true when the server minted it and it has
	// not expired. Freshness then comes from the nonce alone, and iat is not compared with Now.
	// When nil, as at the resources, iat must lie within IssuedAtWindow of Now (#42 decision 8).
	NonceIsValid func(nonce string) bool
}

// Proof is what a proof that passed every check says.
type Proof struct {
	// Thumbprint is the RFC 7638 SHA-256 thumbprint of the proof's key, base64url without padding:
	// the value of cnf.jkt and dpop_jkt.
	Thumbprint string
	JTI        string
	// HTU is the proof's htu as normalized for the comparison.
	HTU      string
	IssuedAt time.Time
	// Nonce is the nonce NonceIsValid accepted, empty when freshness came from iat.
	Nonce string
}

// Check reads and checks the request's proof, as RFC 9449 section 4.3 lists the checks. A proof
// failing any check is refused with ErrInvalidProof, and the error says which, for the log. Only a
// proof passing every other check is judged on its nonce, so a client is told to retry with a nonce
// only when that alone stands between it and an accepted proof.
func (c *Checker) Check(req Request) (*Proof, error) {
	if len(req.Proofs) != 1 {
		return nil, invalid("the request carries %d DPoP headers, and one is required", len(req.Proofs))
	}
	raw := req.Proofs[0]
	if len(raw) > MaxProofBytes {
		return nil, invalid("the DPoP header is %d bytes, over the %d read", len(raw), MaxProofBytes)
	}
	if err := oauth.CheckJWTStructure(raw); err != nil {
		return nil, errs.Errorf("%w: %w", ErrInvalidProof, err)
	}
	segments := strings.Split(raw, ".")

	header, err := decodeObject(segments[0])
	if err != nil {
		return nil, invalid("the header: %w", err)
	}
	if typ, ok := stringMember(header, "typ"); !ok || !isDPoPMediaType(typ) {
		return nil, invalid("the header's typ is not dpop+jwt")
	}
	algName, ok := stringMember(header, "alg")
	if !ok {
		return nil, invalid("the header has no alg")
	}
	alg, ok := findAlgorithm(algName)
	if !ok {
		return nil, invalid("the header's alg is not one of the accepted algorithms")
	}
	jwkRaw, ok := header["jwk"]
	if !ok {
		return nil, invalid("the header has no jwk")
	}
	key, err := parsePublicKey(jwkRaw, alg)
	if err != nil {
		return nil, errs.Errorf("%w: the header's jwk: %w", ErrInvalidProof, err)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(segments[2])
	if err != nil {
		return nil, invalid("the signature does not decode")
	}
	if !key.verify([]byte(segments[0]+"."+segments[1]), signature) {
		return nil, invalid("the signature does not verify with the header's jwk")
	}

	claims, err := decodeObject(segments[1])
	if err != nil {
		return nil, invalid("the payload: %w", err)
	}
	jti, ok := stringMember(claims, "jti")
	if !ok || jti == "" {
		return nil, invalid("the proof has no jti")
	}
	htm, ok := stringMember(claims, "htm")
	if !ok {
		return nil, invalid("the proof has no htm")
	}
	htu, ok := stringMember(claims, "htu")
	if !ok {
		return nil, invalid("the proof has no htu")
	}
	issuedAt, ok := numericDateMember(claims, "iat")
	if !ok {
		return nil, invalid("the proof has no iat that is a NumericDate")
	}

	if htm != req.Method {
		return nil, invalid("the proof's htm is not the request's method")
	}
	normalizedHTU, err := normalizeHTTPURI(htu)
	if err != nil {
		return nil, errs.Errorf("%w: the proof's htu: %w", ErrInvalidProof, err)
	}
	expectedHTU, err := normalizeHTTPURI(c.publicBaseURL + req.Path)
	if err != nil {
		return nil, errs.Wrap(err, "the request's URL cannot be built from the public base URL")
	}
	if normalizedHTU != expectedHTU {
		return nil, invalid("the proof's htu is not the public base URL and the request's path")
	}

	if req.AccessToken != "" {
		ath, hasATH := stringMember(claims, "ath")
		sum := sha256.Sum256([]byte(req.AccessToken))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if !hasATH || subtle.ConstantTimeCompare([]byte(ath), []byte(want)) != 1 {
			return nil, invalid("the proof's ath is not the hash of the access token presented")
		}
	}

	proof := &Proof{Thumbprint: key.thumbprint, JTI: jti, HTU: normalizedHTU, IssuedAt: issuedAt}

	if req.NonceIsValid == nil {
		if issuedAt.Before(req.Now.Add(-IssuedAtWindow)) || issuedAt.After(req.Now.Add(IssuedAtWindow)) {
			return nil, invalid("the proof's iat is more than %s from the server's clock", IssuedAtWindow)
		}
		return proof, nil
	}

	nonce, ok := stringMember(claims, "nonce")
	if _, present := claims["nonce"]; present && !ok {
		return nil, invalid("the proof's nonce is not a string")
	}
	if nonce == "" {
		return nil, errs.Wrap(ErrNonceRequired, "the proof has no nonce")
	}
	if !req.NonceIsValid(nonce) {
		return nil, errs.Wrap(ErrNonceRequired, "the proof's nonce is not one the server accepts")
	}
	proof.Nonce = nonce
	return proof, nil
}

func invalid(format string, args ...any) error {
	return errs.Errorf("%w: "+format, append([]any{ErrInvalidProof}, args...)...)
}

// decodeObject decodes a segment the structural check passed into its members, read by their exact
// names: decoding into a struct would match a name in any case.
func decodeObject(segment string) (map[string]json.RawMessage, error) {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, errs.Wrap(err, "it does not decode")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, errs.Wrap(err, "it is not a JSON object")
	}
	if members == nil {
		return nil, errs.New("it is not a JSON object")
	}
	return members, nil
}

// stringMember returns the named member when it is present and a JSON string. A JSON null would
// otherwise decode into a string as nothing at all.
func stringMember(members map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := members[name]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// maxNumericDate bounds an iat to what converts to a time exactly enough, some 146 billion years
// either side of 1970.
const maxNumericDate = 1 << 62

// numericDateMember returns the named member when it is a JSON number usable as a NumericDate
// (RFC 7519 section 2), fractions of a second included.
func numericDateMember(members map[string]json.RawMessage, name string) (time.Time, bool) {
	raw, ok := members[name]
	if !ok || len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsInf(seconds, 0) || math.IsNaN(seconds) || math.Abs(seconds) >= maxNumericDate {
		return time.Time{}, false
	}
	whole, frac := math.Modf(seconds)
	return time.Unix(int64(whole), int64(math.Round(frac*1e9))), true
}

// isDPoPMediaType reports whether typ names application/dpop+jwt, compared as a media type:
// case-insensitively, and with application/ implied when typ has no slash (RFC 7515 section
// 4.1.9).
func isDPoPMediaType(typ string) bool {
	return strings.EqualFold(typ, "dpop+jwt") || strings.EqualFold(typ, "application/dpop+jwt")
}

// ReplayKey is the key the replay store keeps the proof under (#42 decision 9): the SHA-256 hex
// digest of its normalized htu, a space, and its jti. No URI holds a space, so the pair is read
// back unambiguously, and the jti, the client's own value, is never stored. One jti at two URLs
// names two proofs.
func (p Proof) ReplayKey() string {
	sum := sha256.Sum256([]byte(p.HTU + " " + p.JTI))
	return hex.EncodeToString(sum[:])
}
