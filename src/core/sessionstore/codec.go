package sessionstore

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// envelopeVersion is the first byte of every sealed value. It exists so the next
	// format change has a discriminator to switch on rather than a guess: an envelope
	// carrying any other value is refused, which is what makes adding version 2 later a
	// change to this file and not to every stored row.
	//
	// Nothing reads any other value today. Version 1 is the first sealed format this
	// repository has ever written, and no value from the codec it replaces is accepted at
	// all (#269, #270).
	envelopeVersion = 1

	// nonceBytes is XChaCha20-Poly1305's 24 byte nonce, which is the whole reason that
	// variant was chosen: it is long enough to generate at random with no collision
	// bookkeeping, where a 96 bit nonce would bound one key to 2^32 messages (#270).
	nonceBytes = chacha20poly1305.NonceSizeX

	// envelopeMinBytes is the shortest envelope that could possibly be genuine: the
	// version byte, a nonce, and an authentication tag over an empty plaintext. Anything
	// shorter cannot be opened, and checking it here is what keeps the slicing below from
	// having to be defensive.
	envelopeMinBytes = 1 + nonceBytes + chacha20poly1305.Overhead

	// cookieKeyInfo and dataKeyInfo are the HKDF context strings that separate the two
	// sealing keys. Two keys rather than one is not tidiness: it is what stops a value
	// sealed for one purpose from opening as the other, which the two codec sets used to
	// give for free and which nothing else in the envelope would give (decision 9).
	cookieKeyInfo = "goiabada/sessionstore/cookie/v1"
	dataKeyInfo   = "goiabada/sessionstore/data/v1"

	// sealingKeyBytes is XChaCha20-Poly1305's key size.
	sealingKeyBytes = chacha20poly1305.KeySize
)

// KeyPair is one deployment's configured session keys: the 64 byte authentication key and
// the 32 byte encryption key, exactly as they reach the two main.go files.
//
// Lengths are not checked here. Both are validated at startup, before anything constructs
// a store, and repeating the rule in a second place would let the two disagree about what
// a valid deployment looks like (#269).
type KeyPair struct {
	AuthenticationKey []byte
	EncryptionKey     []byte
}

// DecodeKeyPair decodes one configured pair from the hex an environment variable carries.
//
// Both values are validated at startup, before anything calls this, so an error here means a
// caller that skipped validation rather than a deployment that is misconfigured. It is
// returned rather than dropped because the alternative is a store built from two empty byte
// slices, which is the hazard DecodePreviousKeyPair describes below.
func DecodeKeyPair(authenticationKey, encryptionKey string) (KeyPair, error) {
	authKey, err := hex.DecodeString(strings.TrimSpace(authenticationKey))
	if err != nil {
		return KeyPair{}, errors.Wrap(err, "unable to decode the session authentication key")
	}

	encKey, err := hex.DecodeString(strings.TrimSpace(encryptionKey))
	if err != nil {
		return KeyPair{}, errors.Wrap(err, "unable to decode the session encryption key")
	}

	return KeyPair{AuthenticationKey: authKey, EncryptionKey: encKey}, nil
}

// DecodePreviousKeyPair decodes the pair a rotating deployment configured as its previous one,
// and returns nil when it configured none.
//
// nil and a zero-value KeyPair are not the same thing here, and the difference is a security
// one. That is why this is a function with a test on it rather than an `if` inside each
// binary's main(): hkdf.Key accepts an empty secret and an empty salt and returns a valid 32
// byte key, chacha20poly1305.NewX accepts that key, and a value seals and opens under it. A
// caller that built a previous pair out of two empty strings would therefore hand the store a
// second, permanently valid opening key derived from nothing but the two info constants above,
// which anyone holding this source can recompute. Nothing would error and nothing would look
// wrong. newSealer refuses an empty key too, so the state is unreachable from both sides
// (#269).
//
// Both halves or neither. One alone opens nothing, so it is an error rather than a silent
// no-rotation: an operator who mistypes one variable name would otherwise be told a rotation
// is in place while every session sealed under the old pair is being turned away. The startup
// validators refuse it first, with the variable name in the message; this says the same thing
// for any caller that has not run them.
func DecodePreviousKeyPair(authenticationKey, encryptionKey string) (*KeyPair, error) {
	auth := strings.TrimSpace(authenticationKey)
	enc := strings.TrimSpace(encryptionKey)

	if auth == "" && enc == "" {
		return nil, nil
	}
	if auth == "" || enc == "" {
		return nil, errors.New("the previous session key pair needs both the authentication key and the encryption key, or neither")
	}

	pair, err := DecodeKeyPair(auth, enc)
	if err != nil {
		return nil, errors.Wrap(err, "invalid previous session key pair")
	}
	return &pair, nil
}

// sealer holds one AEAD per purpose, both derived from one KeyPair.
//
// One sealer is one generation of keys. The store keeps the current one and, while an
// operator is rotating, the previous one, which is what lets a rotation happen without
// signing anybody out (decision 10).
type sealer struct {
	cookie cipher.AEAD
	data   cipher.AEAD
}

// newSealer derives the two sealing keys from the configured pair and builds an AEAD over
// each.
//
// Both configured secrets feed the derivation, the encryption key as HKDF's secret and the
// authentication key as its salt, so neither becomes a variable a deployment sets and
// nothing reads. That is the whole of why HKDF is here rather than using the encryption
// key directly: the authentication key had a job under the previous codec and it keeps one
// (decision 9).
//
// The empty-key check below is the one error here a caller can actually provoke. The three
// after it are structural: HKDF cannot fail for a 32 byte output and the AEAD cannot fail on
// a 32 byte key, so those are unreachable with the derivation above, and they are returned
// rather than dropped so a future change to either call cannot fail silently at the first
// save instead of at startup.
func newSealer(pair KeyPair) (*sealer, error) {
	// A key of no bytes is refused rather than trusted to be impossible. HKDF accepts an
	// empty secret and an empty salt and derives a perfectly valid key from them, so a
	// zero-value KeyPair arriving here would build a working sealer whose keys anyone can
	// recompute from the two info constants above -- a permanent skeleton key, produced by
	// a caller that merely forgot a branch. This is not the length rule: that one lives in
	// the startup validators and stays there, and "not empty" cannot disagree with
	// "exactly 64 and 32 bytes" (#269).
	if len(pair.AuthenticationKey) == 0 || len(pair.EncryptionKey) == 0 {
		return nil, errors.New("a session key pair needs a non-empty authentication key and a non-empty encryption key")
	}

	cookieKey, err := hkdf.Key(sha256.New, pair.EncryptionKey, pair.AuthenticationKey,
		cookieKeyInfo, sealingKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to derive the session cookie key")
	}

	dataKey, err := hkdf.Key(sha256.New, pair.EncryptionKey, pair.AuthenticationKey,
		dataKeyInfo, sealingKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to derive the session data key")
	}

	cookieAEAD, err := chacha20poly1305.NewX(cookieKey)
	if err != nil {
		return nil, errors.Wrap(err, "unable to build the session cookie cipher")
	}

	dataAEAD, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, errors.Wrap(err, "unable to build the session data cipher")
	}

	return &sealer{cookie: cookieAEAD, data: dataAEAD}, nil
}

// seal encrypts plaintext under aead and returns the envelope as text.
//
// The session name is bound in as associated data, not stored: a value sealed under one
// session name will not open under another, which is what stops an admin console blob from
// being presented as an auth server one even where both were sealed by the same key.
//
// Text rather than raw bytes because both destinations are text. The cookie value has to
// be, and the stored blob crosses the session endpoint as a JSON string and lands in a
// text column on all four engines, so raw ciphertext would not survive PostgreSQL or SQL
// Server. Base64 once, not twice, which is what the codec this replaces did (#270).
func seal(aead cipher.AEAD, name string, plaintext []byte) (string, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return "", errors.Wrap(err, "unable to read from the random number generator")
	}

	envelope := make([]byte, 0, envelopeMinBytes+len(plaintext))
	envelope = append(envelope, envelopeVersion)
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, plaintext, []byte(name))

	return base64.RawURLEncoding.EncodeToString(envelope), nil
}

// open reverses seal. Every failure is one error: the caller's answer to all of them is
// the same fresh session, and telling a caller which part of an envelope it could not
// trust tells an attacker the same thing.
func open(aead cipher.AEAD, name string, encoded string) ([]byte, error) {
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.Wrap(err, "the sealed session value is not valid base64")
	}

	if len(envelope) < envelopeMinBytes {
		return nil, errors.New("the sealed session value is too short to be an envelope")
	}

	if envelope[0] != envelopeVersion {
		return nil, errors.Errorf("unsupported sealed session envelope version %d", envelope[0])
	}

	nonce := envelope[1 : 1+nonceBytes]
	ciphertext := envelope[1+nonceBytes:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(name))
	if err != nil {
		return nil, errors.Wrap(err, "the sealed session value did not open")
	}
	return plaintext, nil
}
