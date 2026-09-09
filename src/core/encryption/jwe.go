package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
)

// The encrypted id_token_hint scheme (see the docs at
// integration/endpoints.mdx, "Encrypting the ID token hint"):
//
//	alg = dir      key management: the derived key IS the content-encryption key
//	enc = A256GCM  content encryption: AES-256-GCM
//	key = SHA-256(UTF-8 client_secret)   (always 32 bytes)
//
// This implements OpenID Connect Core 1.0 §2 (an encrypted ID Token is a Nested
// JWT: the signed ID Token wrapped in a JWE) together with RP-Initiated Logout's
// symmetrically-encrypted id_token_hint, which is keyed off the client_id so the
// OP knows whose secret to derive the key from.
//
// The parser below reads that one scheme and nothing else, so the file needs no
// JOSE library (#277). It accepts exactly one shape -- five canonical base64url
// segments whose protected header is a JSON object naming "dir" and "A256GCM"
// and carrying nothing the recipient does not understand -- and every departure
// from that shape is refused before the cipher runs. Nothing in the header is
// dispatched on: "alg" and "enc" are asserted, never used to pick a primitive,
// so algorithm substitution and downgrade have no surface to work on.

// idTokenHintJWEHeader is the protected header EncryptIDTokenHintJWE writes, byte
// for byte. It is the header of the scheme integration/endpoints.mdx documents.
const idTokenHintJWEHeader = `{"alg":"dir","enc":"A256GCM","cty":"JWT"}`

const (
	// RFC 7518 section 5.3: "Use of an IV of size 96 bits is REQUIRED with this
	// algorithm. The requested size of the Authentication Tag output MUST be 128
	// bits, regardless of the key size."
	idTokenHintIVLen  = 12
	idTokenHintTagLen = 16
)

// jweSegmentNames names the five compact-serialization segments of RFC 7516
// section 7.1, in order, so a refusal can say which one was malformed.
var jweSegmentNames = [5]string{
	"protected header",
	"encrypted key",
	"initialization vector",
	"ciphertext",
	"authentication tag",
}

// DeriveIDTokenHintKey derives the 32-byte AES-256 key used to decrypt an
// encrypted id_token_hint from the client secret (SHA-256 of the UTF-8 client
// secret). Exported so tests and tooling derive the key exactly the way the
// decrypt path does.
func DeriveIDTokenHintKey(clientSecret string) []byte {
	sum := sha256.Sum256([]byte(clientSecret))
	return sum[:]
}

// EncryptIDTokenHintJWE is the reference encryptor for the id_token_hint scheme
// documented at integration/endpoints.mdx: it produces what DecryptIDTokenHintJWE
// reads, with the header above. Nothing in the binaries calls it -- an RP does the
// encrypting -- but keeping the two halves in one file is what lets every test in
// either module build a fixture without a JOSE library, and what makes the
// documented scheme executable rather than prose (#277).
func EncryptIDTokenHintJWE(plaintext string, clientSecret string) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.WithStack(errors.New("id_token_hint plaintext is empty"))
	}
	if len(clientSecret) == 0 {
		return "", errors.WithStack(errors.New("client secret is empty"))
	}

	protected := base64.RawURLEncoding.EncodeToString([]byte(idTokenHintJWEHeader))

	iv := make([]byte, idTokenHintIVLen)
	if _, err := rand.Read(iv); err != nil {
		return "", errors.Wrap(err, "could not read a random initialization vector")
	}

	gcm, err := idTokenHintGCM(clientSecret)
	if err != nil {
		return "", err
	}

	// RFC 7516 section 5.1 steps 14 and 15: the AAD is ASCII(BASE64URL(UTF8(header))),
	// so the header is authenticated in the exact form it goes on the wire.
	sealed := gcm.Seal(nil, iv, []byte(plaintext), []byte(protected))
	ciphertext := sealed[:len(sealed)-idTokenHintTagLen]
	tag := sealed[len(sealed)-idTokenHintTagLen:]

	return strings.Join([]string{
		protected,
		// RFC 7518 section 4.5: with "dir" the JWE Encrypted Key is an empty octet sequence.
		"",
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, "."), nil
}

// DecryptIDTokenHintJWE decrypts a compact-serialized JWE id_token_hint with a
// key derived from the client secret and returns the plaintext, which is the
// inner signed ID Token (a compact JWS) to be validated by the caller. Only the
// dir + A256GCM scheme is accepted; every other input is refused, each with its
// own message so the server log tells a malformed hint from a wrong key.
func DecryptIDTokenHintJWE(compactJWE string, clientSecret string) (string, error) {
	if len(compactJWE) == 0 {
		return "", errors.WithStack(errors.New("id_token_hint is empty"))
	}
	if len(clientSecret) == 0 {
		return "", errors.WithStack(errors.New("client secret is empty"))
	}

	// RFC 7516 section 5.2 step 1: the compact serialization has "exactly four
	// delimiting period characters".
	parts := strings.Split(compactJWE, ".")
	if len(parts) != 5 {
		return "", errors.Errorf("id_token_hint is not a compact JWE: expected 5 segments, got %d", len(parts))
	}

	decoded := make([][]byte, len(parts))
	for i, part := range parts {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return "", errors.Wrapf(err, "id_token_hint segment %d (%s) is not valid base64url", i, jweSegmentNames[i])
		}
		// RFC 7515 section 2: base64url "with all trailing '=' characters omitted ...
		// and without the inclusion of any line breaks, whitespace, or other additional
		// characters". Go's decoder silently skips \r and \n anywhere in its input and
		// accepts non-zero trailing bits, so re-encoding and comparing is what enforces
		// the canonical form. Undo this and a hint carrying a stray %0A is accepted,
		// which is a serialization the RFC does not define (#277).
		if base64.RawURLEncoding.EncodeToString(raw) != part {
			return "", errors.Errorf("id_token_hint segment %d (%s) is not canonical base64url", i, jweSegmentNames[i])
		}
		decoded[i] = raw
	}

	header, err := parseIDTokenHintHeader(decoded[0])
	if err != nil {
		return "", err
	}

	// RFC 7516 section 5.2's closing paragraph: "unless the algorithms used in the JWE
	// are acceptable to the application, it SHOULD consider the JWE to be invalid".
	// Both are exact string compares, and neither value selects any code path below.
	if alg := idTokenHintHeaderString(header, "alg"); alg != "dir" {
		return "", errors.Errorf("id_token_hint header alg is %q, want \"dir\"", alg)
	}
	if enc := idTokenHintHeaderString(header, "enc"); enc != "A256GCM" {
		return "", errors.Errorf("id_token_hint header enc is %q, want \"A256GCM\"", enc)
	}
	// RFC 7516 section 4.1.3 makes "zip" a parameter an implementation MUST understand
	// and process. This one does not compress, so it refuses rather than ignores: no
	// decompression means no decompression bomb and no cap to pick. The documented
	// scheme has no compression row, so no documented client can hit this (#277).
	if _, ok := header["zip"]; ok {
		return "", errors.WithStack(errors.New("id_token_hint header has a zip parameter, which is not supported"))
	}
	// RFC 7515 section 4.1.11: "If any of the listed extension Header Parameters are
	// not understood and supported by the recipient, then the JWS is invalid." No
	// extension is understood here, and the empty list a producer "MUST NOT use" is
	// refused with the rest (#277).
	if _, ok := header["crit"]; ok {
		return "", errors.WithStack(errors.New("id_token_hint header has a crit parameter, and no extension is understood"))
	}

	encryptedKey, iv, ciphertext, tag := decoded[1], decoded[2], decoded[3], decoded[4]

	// RFC 7516 section 5.2 step 10: "When Direct Key Agreement or Direct Encryption are
	// employed, verify that the JWE Encrypted Key value is an empty octet sequence."
	if len(encryptedKey) != 0 {
		return "", errors.Errorf("id_token_hint encrypted key is %d bytes, want empty with alg dir", len(encryptedKey))
	}
	// The next three are checked here rather than left to the AEAD. The iv check is not
	// only cosmetic: crypto/cipher's GCM panics on a nonce that is not its nonce size,
	// and the iv here comes straight off the wire. The ciphertext check matters because
	// an empty ciphertext with a valid tag authenticates, and would decrypt to an empty
	// hint. Explicit checks also tell a malformed hint from a wrong key in the log,
	// which one shared "decryption failed" could not (#277).
	if len(iv) != idTokenHintIVLen {
		return "", errors.Errorf("id_token_hint iv is %d bytes, want %d", len(iv), idTokenHintIVLen)
	}
	if len(tag) != idTokenHintTagLen {
		return "", errors.Errorf("id_token_hint authentication tag is %d bytes, want %d", len(tag), idTokenHintTagLen)
	}
	if len(ciphertext) == 0 {
		return "", errors.WithStack(errors.New("id_token_hint ciphertext is empty"))
	}

	gcm, err := idTokenHintGCM(clientSecret)
	if err != nil {
		return "", err
	}

	// Go's AEAD takes the tag appended to the ciphertext, and the AAD is the protected
	// header segment exactly as received -- never re-serialized -- per RFC 7516 section
	// 5.2 steps 14 and 15.
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	plaintext, err := gcm.Open(nil, iv, sealed, []byte(parts[0]))
	if err != nil {
		// Step 16 rejects "without emitting any decrypted output". GCM cannot tell a wrong
		// key from a tampered segment, so both land on this one message.
		return "", errors.Wrap(err, "id_token_hint decryption failed")
	}

	return string(plaintext), nil
}

// idTokenHintGCM builds the AES-256-GCM primitive both halves use. The key is a
// SHA-256 sum, so it is always 32 bytes and aes.NewCipher can only ever build
// AES-256 here; the errors below are unreachable in practice, and are returned
// rather than panicked on.
func idTokenHintGCM(clientSecret string) (cipher.AEAD, error) {
	block, err := aes.NewCipher(DeriveIDTokenHintKey(clientSecret))
	if err != nil {
		return nil, errors.Wrap(err, "id_token_hint cipher setup failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "id_token_hint cipher setup failed")
	}
	return gcm, nil
}

// parseIDTokenHintHeader validates the decoded protected header and returns its
// top-level members keyed by their exact names.
//
// It is deliberately not a struct unmarshal. encoding/json matches struct fields
// case-insensitively, so a struct would read "ALG" as "alg" and "ZIP" as "zip",
// where RFC 7515 section 5.3 compares header parameter names code point for code
// point. Reading into a map keeps "ALG" an unknown parameter, which per RFC 7515
// section 4 is ignored, leaving "alg" absent (#277).
func parseIDTokenHintHeader(raw []byte) (map[string]json.RawMessage, error) {
	// RFC 7516 section 5.2 step 3: the decoded header must be "a UTF-8-encoded
	// representation of a completely valid JSON object". encoding/json substitutes
	// U+FFFD for invalid bytes instead of failing, so the check has to be explicit.
	if !utf8.Valid(raw) {
		return nil, errors.WithStack(errors.New("id_token_hint header is not valid UTF-8"))
	}

	// RFC 7515 section 4: a parser "MUST either reject JWSs with duplicate Header
	// Parameter names or use a JSON parser that returns only the lexically last
	// duplicate member name". encoding/json silently keeps the last, so the tokens are
	// walked here and a repeated top-level name is refused. Undo this and a header
	// carrying two "alg" values is accepted on the strength of whichever copy comes
	// last, which is a malformed header either way (#277).
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errors.Wrap(err, "id_token_hint header is not a JSON object")
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.WithStack(errors.New("id_token_hint header is not a JSON object"))
	}

	seen := make(map[string]bool)
	depth := 1
	// Inside the top-level object the tokens alternate name, value. Anything deeper is
	// skipped by depth, so a name repeated inside a nested object is not a duplicate.
	expectName := true
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return nil, errors.Wrap(err, "id_token_hint header is not a JSON object")
		}
		if delim, ok := tok.(json.Delim); ok {
			if delim == '{' || delim == '[' {
				depth++
			} else {
				depth--
				if depth == 1 {
					expectName = true
				}
			}
			continue
		}
		if depth != 1 {
			continue
		}
		if !expectName {
			expectName = true
			continue
		}
		name, _ := tok.(string)
		if seen[name] {
			return nil, errors.Errorf("id_token_hint header repeats the member name %q", name)
		}
		seen[name] = true
		expectName = false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.WithStack(errors.New("id_token_hint header has trailing data after the JSON object"))
	}

	var header map[string]json.RawMessage
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, errors.Wrap(err, "id_token_hint header is not a JSON object")
	}
	return header, nil
}

// idTokenHintHeaderString reads a string member by its exact name, and reports an
// absent member and a member that is not a string alike as the empty string: both
// mean the parameter this scheme requires is not there.
func idTokenHintHeaderString(header map[string]json.RawMessage, name string) string {
	raw, ok := header[name]
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}
