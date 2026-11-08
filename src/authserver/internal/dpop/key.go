package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"

	// Registered for crypto.Hash.New, which the RSA and EC checks use.
	_ "crypto/sha512"

	"github.com/leodip/goiabada/core/errs"
)

// keyFamily is the kind of key an algorithm takes, and how its signature is made.
type keyFamily int

const (
	familyEC keyFamily = iota
	familyRSAPKCS1
	familyRSAPSS
	familyEd25519
)

// algorithm is one accepted proof algorithm: the key it takes and the hash it signs.
type algorithm struct {
	name   string
	family keyFamily
	hash   crypto.Hash
	// For EC: the curve, its JWK name and the length of a coordinate in bytes.
	curve     elliptic.Curve
	curveName string
	coordLen  int
}

// signingAlgorithms is #42 decision 4's list, written out and in the order it is published.
var signingAlgorithms = []algorithm{
	{name: "ES256", family: familyEC, hash: crypto.SHA256, curve: elliptic.P256(), curveName: "P-256", coordLen: 32},
	{name: "ES384", family: familyEC, hash: crypto.SHA384, curve: elliptic.P384(), curveName: "P-384", coordLen: 48},
	{name: "ES512", family: familyEC, hash: crypto.SHA512, curve: elliptic.P521(), curveName: "P-521", coordLen: 66},
	{name: "PS256", family: familyRSAPSS, hash: crypto.SHA256},
	{name: "PS384", family: familyRSAPSS, hash: crypto.SHA384},
	{name: "PS512", family: familyRSAPSS, hash: crypto.SHA512},
	{name: "RS256", family: familyRSAPKCS1, hash: crypto.SHA256},
	{name: "RS384", family: familyRSAPKCS1, hash: crypto.SHA384},
	{name: "RS512", family: familyRSAPKCS1, hash: crypto.SHA512},
	// RFC 9864's fully specified name, and the polymorphic name it deprecates, held to Ed25519.
	{name: "Ed25519", family: familyEd25519},
	{name: "EdDSA", family: familyEd25519},
}

// findAlgorithm returns the listed algorithm of that exact name: alg is case-sensitive (RFC 7515
// section 4.1.1).
func findAlgorithm(name string) (algorithm, bool) {
	for _, a := range signingAlgorithms {
		if a.name == name {
			return a, true
		}
	}
	return algorithm{}, false
}

const (
	minRSABits = 2048
	// maxRSABits caps what verifying a proof can cost (#42 decision 4).
	maxRSABits = 8192
	// maxRSAExponent is the largest exponent Go's RSA takes.
	maxRSAExponent = 1<<31 - 1
)

// privateMembers are the JWK members that carry private or symmetric key material (RFC 7518
// sections 6.2.2, 6.3.2 and 6.4, RFC 8037 section 2). A proof's key holding any is refused.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// publicKey is a proof's key, checked against its algorithm.
type publicKey struct {
	alg        algorithm
	ec         *ecdsa.PublicKey
	rsa        *rsa.PublicKey
	ed25519    ed25519.PublicKey
	thumbprint string
}

// parsePublicKey reads the jwk header member as a public key of the type alg takes, and computes
// its RFC 7638 thumbprint from the required members it was read from.
func parsePublicKey(raw json.RawMessage, alg algorithm) (*publicKey, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errs.New("it is not a JSON object")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, errs.Wrap(err, "it is not a JSON object")
	}
	for _, name := range privateMembers {
		if _, ok := members[name]; ok {
			return nil, errs.Errorf("it holds the private or symmetric member %s", name)
		}
	}
	kty, ok := stringMember(members, "kty")
	if !ok {
		return nil, errs.New("it has no kty")
	}

	switch alg.family {
	case familyEC:
		return parseECKey(members, kty, alg)
	case familyRSAPKCS1, familyRSAPSS:
		return parseRSAKey(members, kty, alg)
	case familyEd25519:
		return parseEd25519Key(members, kty, alg)
	}
	return nil, errs.Errorf("no key type is known for %s", alg.name)
}

func parseECKey(members map[string]json.RawMessage, kty string, alg algorithm) (*publicKey, error) {
	if kty != "EC" {
		return nil, errs.Errorf("%s takes an EC key", alg.name)
	}
	crv, ok := stringMember(members, "crv")
	if !ok || crv != alg.curveName {
		return nil, errs.Errorf("%s takes a key on %s", alg.name, alg.curveName)
	}
	x, xb, err := keyMember(members, "x", alg.coordLen)
	if err != nil {
		return nil, err
	}
	y, yb, err := keyMember(members, "y", alg.coordLen)
	if err != nil {
		return nil, err
	}
	point := make([]byte, 0, 1+2*alg.coordLen)
	point = append(append(append(point, 4), xb...), yb...)
	// It refuses a point that is not on the curve, or is the point at infinity.
	key, err := ecdsa.ParseUncompressedPublicKey(alg.curve, point)
	if err != nil {
		return nil, errs.Wrap(err, "its point is not on its curve")
	}
	return &publicKey{
		alg:        alg,
		ec:         key,
		thumbprint: thumbprintOf(`{"crv":"` + crv + `","kty":"EC","x":"` + x + `","y":"` + y + `"}`),
	}, nil
}

func parseRSAKey(members map[string]json.RawMessage, kty string, alg algorithm) (*publicKey, error) {
	if kty != "RSA" {
		return nil, errs.Errorf("%s takes an RSA key", alg.name)
	}
	n, nb, err := keyMember(members, "n", 0)
	if err != nil {
		return nil, err
	}
	e, eb, err := keyMember(members, "e", 0)
	if err != nil {
		return nil, err
	}
	// Both are unsigned integers in the fewest octets (RFC 7518 section 6.3.1).
	if nb[0] == 0 || eb[0] == 0 {
		return nil, errs.New("its modulus or exponent has a leading zero octet")
	}
	modulus := new(big.Int).SetBytes(nb)
	if bits := modulus.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, errs.Errorf("its modulus is %d bits, outside %d to %d", bits, minRSABits, maxRSABits)
	}
	if len(eb) > 4 {
		return nil, errs.New("its exponent is longer than four octets")
	}
	exponent := new(big.Int).SetBytes(eb)
	if exponent.Bit(0) == 0 || exponent.Cmp(big.NewInt(3)) < 0 || exponent.Cmp(big.NewInt(maxRSAExponent)) > 0 {
		return nil, errs.New("its exponent is not an odd number from 3 to 2^31-1")
	}
	return &publicKey{
		alg:        alg,
		rsa:        &rsa.PublicKey{N: modulus, E: int(exponent.Int64())},
		thumbprint: thumbprintOf(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`),
	}, nil
}

func parseEd25519Key(members map[string]json.RawMessage, kty string, alg algorithm) (*publicKey, error) {
	if kty != "OKP" {
		return nil, errs.Errorf("%s takes an OKP key", alg.name)
	}
	crv, ok := stringMember(members, "crv")
	if !ok || crv != "Ed25519" {
		return nil, errs.Errorf("%s takes an Ed25519 key only", alg.name)
	}
	x, xb, err := keyMember(members, "x", ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return &publicKey{
		alg:        alg,
		ed25519:    ed25519.PublicKey(xb),
		thumbprint: thumbprintOf(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`),
	}, nil
}

// keyMember returns a key member's string and its octets. The string must be the canonical
// unpadded base64url form of a non-empty value, of exactly length octets when length is not 0, so
// the thumbprint built from it is the one any party computes from the key.
func keyMember(members map[string]json.RawMessage, name string, length int) (string, []byte, error) {
	s, ok := stringMember(members, name)
	if !ok {
		return "", nil, errs.Errorf("it has no %s", name)
	}
	if !isBase64URL(s) {
		return "", nil, errs.Errorf("its %s is not unpadded base64url", name)
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return "", nil, errs.Errorf("its %s is not the canonical base64url of a value", name)
	}
	if len(b) == 0 || (length != 0 && len(b) != length) {
		return "", nil, errs.Errorf("its %s is %d octets, not %d", name, len(b), length)
	}
	return s, b, nil
}

// isBase64URL reports whether every byte of s is in the unpadded base64url alphabet. The strict
// decoder still skips CR and LF.
func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// thumbprintOf is RFC 7638's thumbprint of a key's required members, already in lexicographic
// order and without whitespace: SHA-256, base64url without padding.
func thumbprintOf(canonicalJSON string) string {
	sum := sha256.Sum256([]byte(canonicalJSON))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verify reports whether signature is the key's signature of input under its algorithm (RFC 7518
// section 3, RFC 8037 section 3.1).
func (k *publicKey) verify(input, signature []byte) bool {
	switch k.alg.family {
	case familyEC:
		// R and S, each the full length of a coordinate (RFC 7518 section 3.4).
		if len(signature) != 2*k.alg.coordLen {
			return false
		}
		r := new(big.Int).SetBytes(signature[:k.alg.coordLen])
		s := new(big.Int).SetBytes(signature[k.alg.coordLen:])
		return ecdsa.Verify(k.ec, digest(k.alg.hash, input), r, s)
	case familyRSAPKCS1:
		return rsa.VerifyPKCS1v15(k.rsa, k.alg.hash, digest(k.alg.hash, input), signature) == nil
	case familyRSAPSS:
		// The salt is as long as the hash's output (RFC 7518 section 3.5).
		return rsa.VerifyPSS(k.rsa, k.alg.hash, digest(k.alg.hash, input), signature,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case familyEd25519:
		return len(signature) == ed25519.SignatureSize && ed25519.Verify(k.ed25519, input, signature)
	}
	return false
}

func digest(hash crypto.Hash, input []byte) []byte {
	h := hash.New()
	h.Write(input)
	return h.Sum(nil)
}
