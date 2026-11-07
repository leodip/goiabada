package oauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/leodip/goiabada/core/errs"
)

// CheckJWTStructure refuses a compact JWS whose structure Goiabada does not accept, before any
// signature is verified (#709). It reads the serialization and the header only, and judges nothing
// the JWT library checks after it: the algorithm, the signature and the claims are each reader's.
//
// A token is refused when it is not exactly three segments; when any segment holds a character
// outside the unpadded base64url alphabet, A-Z a-z 0-9 - and _, so CR, LF, whitespace and = are all
// refused (RFC 7515 sections 2 and 5.2 steps 2, 6 and 7), where Go's decoder skips CR and LF; when
// the decoded header or payload is not valid UTF-8 (RFC 7515 section 5.2 step 3, RFC 7519 section
// 7.2 step 10), where Go's JSON decoder replaces an invalid byte rather than refusing it; when the
// header is not a JSON object; when the header has crit, whatever its value, the empty list
// included, since Goiabada understands no extension (RFC 7515 section 4.1.11); and when its cty is
// JWT or application/jwt, compared case-insensitively as media types are (RFC 7515 section
// 4.1.10), since Goiabada supports no nested JWT (RFC 7519 section 7.2 step 8). Any other cty is
// left to the reader.
//
// The error says which rule refused the token, for the log; a reader answers it as it answers a
// malformed token.
func CheckJWTStructure(token string) error {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return errs.Errorf("a compact JWS has 3 segments, and this token has %d", len(segments))
	}
	for i, segment := range segments {
		if !isUnpaddedBase64URL(segment) {
			return errs.Errorf("segment %d holds a character outside the unpadded base64url alphabet", i+1)
		}
	}

	header, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return errs.Wrap(err, "the header segment does not decode")
	}
	if !utf8.Valid(header) {
		return errs.New("the decoded header is not valid UTF-8")
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return errs.Wrap(err, "the payload segment does not decode")
	}
	if !utf8.Valid(payload) {
		return errs.New("the decoded payload is not valid UTF-8")
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(header, &members); err != nil {
		return errs.Wrap(err, "the header is not a JSON object")
	}
	if members == nil {
		return errs.New("the header is not a JSON object")
	}
	if _, ok := members["crit"]; ok {
		return errs.New("the header has crit, and no extension is understood")
	}
	if raw, ok := members["cty"]; ok {
		var cty string
		if json.Unmarshal(raw, &cty) == nil &&
			(strings.EqualFold(cty, "JWT") || strings.EqualFold(cty, "application/jwt")) {
			return errs.New("the header's cty names a nested JWT, which is not supported")
		}
	}
	return nil
}

// isUnpaddedBase64URL reports whether every byte of segment is in RFC 4648 section 5's alphabet,
// without the padding character.
func isUnpaddedBase64URL(segment string) bool {
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
