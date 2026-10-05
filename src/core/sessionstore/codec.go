package sessionstore

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"github.com/leodip/goiabada/core/errs"
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

const (
	// authenticationKeyBytes and encryptionKeyBytes are the only lengths ParseKeys accepts
	// for the two halves of a configured pair.
	authenticationKeyBytes = 64
	encryptionKeyBytes     = 32
)

// KeyPair is one deployment's configured session keys: the 64 byte authentication key and
// the 32 byte encryption key.
//
// It stays a plain pair, checking nothing, so a test can build one directly. ParseKeys is the
// one place the length rule lives: both applications build their pairs through it, and a
// second copy of the rule would let the two disagree about what a valid deployment looks like
// (#269, #434).
type KeyPair struct {
	AuthenticationKey []byte
	EncryptionKey     []byte
}

// ConfiguredKey is one session key as a deployment configured it: the hex it carries, and the
// name it was configured under, which is what every refusal quotes so the operator reads the
// variable to fix.
type ConfiguredKey struct {
	Name  string
	Value string
}

// ConfiguredKeys is the four session keys one application is configured with: the current
// pair, and the previous pair a deployment sets only while it rotates them.
type ConfiguredKeys struct {
	Authentication         ConfiguredKey
	Encryption             ConfiguredKey
	PreviousAuthentication ConfiguredKey
	PreviousEncryption     ConfiguredKey
}

// ParseKeys applies the session-key rule both applications share and decodes the pairs it
// accepts: the current pair is required, hex, and 64 and 32 bytes long; the previous pair is
// optional, and when set it is set in full to the same lengths. Every value is trimmed first,
// and every refusal names the variable it concerns. It returns a nil previous pair when the
// deployment configured none.
//
// nil and a zero-value KeyPair are not the same thing here, and the difference is a security
// one. hkdf.Key accepts an empty secret and an empty salt and returns a valid 32 byte key,
// chacha20poly1305.NewX accepts that key, and a value seals and opens under it. A caller that
// built a previous pair out of two empty strings would therefore hand the store a second,
// permanently valid opening key derived from nothing but the two info constants above, which
// anyone holding this source can recompute. Nothing would error and nothing would look wrong.
// newSealer refuses an empty key too, so the state is unreachable from both sides (#269).
//
// Both halves or neither. One alone opens nothing, so it is an error rather than a silent
// no-rotation: an operator who mistypes one variable name would otherwise be told a rotation
// is in place while every session sealed under the old pair is being turned away.
//
// A refusal of the previous pair, the current one having decoded, is a *PreviousKeysError.
func ParseKeys(keys ConfiguredKeys) (KeyPair, *KeyPair, error) {
	authentication := strings.TrimSpace(keys.Authentication.Value)
	encryption := strings.TrimSpace(keys.Encryption.Value)

	if authentication == "" {
		return KeyPair{}, nil, errs.Errorf("%s is required", keys.Authentication.Name)
	}
	if encryption == "" {
		return KeyPair{}, nil, errs.Errorf("%s is required", keys.Encryption.Name)
	}

	authenticationKey, err := hex.DecodeString(authentication)
	if err != nil {
		return KeyPair{}, nil, errs.Errorf("%s must be hex-encoded (error: %w). Generate with: openssl rand -hex 64",
			keys.Authentication.Name, err)
	}
	if len(authenticationKey) != authenticationKeyBytes {
		return KeyPair{}, nil, errs.Errorf("%s must be 64 bytes (128 hex chars), got %d bytes. Generate with: openssl rand -hex 64",
			keys.Authentication.Name, len(authenticationKey))
	}

	encryptionKey, err := hex.DecodeString(encryption)
	if err != nil {
		return KeyPair{}, nil, errs.Errorf("%s must be hex-encoded (error: %w). Generate with: openssl rand -hex 32",
			keys.Encryption.Name, err)
	}
	if len(encryptionKey) != encryptionKeyBytes {
		return KeyPair{}, nil, errs.Errorf("%s must be 32 bytes (64 hex chars), got %d bytes. Generate with: openssl rand -hex 32",
			keys.Encryption.Name, len(encryptionKey))
	}

	current := KeyPair{AuthenticationKey: authenticationKey, EncryptionKey: encryptionKey}

	previous, err := parsePreviousKeys(keys)
	if err != nil {
		return KeyPair{}, nil, &PreviousKeysError{err: err}
	}
	return current, previous, nil
}

// PreviousKeysError is ParseKeys' refusal of the previous pair, the current pair having decoded:
// one half set without the other, or a half that is not hex of its length. It is a key rotation
// applied in part or mistyped, where a refusal of the current pair is a credential the deployment
// lacks, and each application says so in the record it stops on: the advice for one is wrong
// for the other. Its text is the refusal's own, which names the variable.
type PreviousKeysError struct {
	err error
}

func (e *PreviousKeysError) Error() string { return e.err.Error() }

// Unwrap puts the refusal on the chain, and with it the stack errs captured where it was made.
func (e *PreviousKeysError) Unwrap() error { return e.err }

// parsePreviousKeys decodes the optional previous pair: nil when neither half is set, and an
// error naming the variable when one half is missing or either is malformed.
func parsePreviousKeys(keys ConfiguredKeys) (*KeyPair, error) {
	previousAuthentication := strings.TrimSpace(keys.PreviousAuthentication.Value)
	previousEncryption := strings.TrimSpace(keys.PreviousEncryption.Value)

	if previousAuthentication == "" && previousEncryption == "" {
		return nil, nil
	}
	if previousAuthentication == "" {
		return nil, errs.Errorf("%s is required when %s is set: both halves of the previous pair are needed to open a session sealed under it",
			keys.PreviousAuthentication.Name, keys.PreviousEncryption.Name)
	}
	if previousEncryption == "" {
		return nil, errs.Errorf("%s is required when %s is set: both halves of the previous pair are needed to open a session sealed under it",
			keys.PreviousEncryption.Name, keys.PreviousAuthentication.Name)
	}

	previousAuthenticationKey, err := hex.DecodeString(previousAuthentication)
	if err != nil {
		return nil, errs.Errorf("%s must be hex-encoded (error: %w)", keys.PreviousAuthentication.Name, err)
	}
	if len(previousAuthenticationKey) != authenticationKeyBytes {
		return nil, errs.Errorf("%s must be 64 bytes (128 hex chars), got %d bytes",
			keys.PreviousAuthentication.Name, len(previousAuthenticationKey))
	}

	previousEncryptionKey, err := hex.DecodeString(previousEncryption)
	if err != nil {
		return nil, errs.Errorf("%s must be hex-encoded (error: %w)", keys.PreviousEncryption.Name, err)
	}
	if len(previousEncryptionKey) != encryptionKeyBytes {
		return nil, errs.Errorf("%s must be 32 bytes (64 hex chars), got %d bytes",
			keys.PreviousEncryption.Name, len(previousEncryptionKey))
	}

	return &KeyPair{AuthenticationKey: previousAuthenticationKey, EncryptionKey: previousEncryptionKey}, nil
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
	// a caller that merely forgot a branch. This is not the length rule: that one is
	// ParseKeys' and stays there, and "not empty" cannot disagree with "exactly 64 and 32
	// bytes" (#269, #434).
	if len(pair.AuthenticationKey) == 0 || len(pair.EncryptionKey) == 0 {
		return nil, errs.New("a session key pair needs a non-empty authentication key and a non-empty encryption key")
	}

	cookieKey, err := hkdf.Key(sha256.New, pair.EncryptionKey, pair.AuthenticationKey,
		cookieKeyInfo, sealingKeyBytes)
	if err != nil {
		return nil, errs.Wrap(err, "unable to derive the session cookie key")
	}

	dataKey, err := hkdf.Key(sha256.New, pair.EncryptionKey, pair.AuthenticationKey,
		dataKeyInfo, sealingKeyBytes)
	if err != nil {
		return nil, errs.Wrap(err, "unable to derive the session data key")
	}

	cookieAEAD, err := chacha20poly1305.NewX(cookieKey)
	if err != nil {
		return nil, errs.Wrap(err, "unable to build the session cookie cipher")
	}

	dataAEAD, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, errs.Wrap(err, "unable to build the session data cipher")
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
func seal(random io.Reader, aead cipher.AEAD, name string, plaintext []byte) (string, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", errs.Wrap(err, "unable to read from the random number generator")
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
		return nil, errs.Wrap(err, "the sealed session value is not valid base64")
	}

	if len(envelope) < envelopeMinBytes {
		return nil, errs.New("the sealed session value is too short to be an envelope")
	}

	if envelope[0] != envelopeVersion {
		return nil, errs.Errorf("unsupported sealed session envelope version %d", envelope[0])
	}

	nonce := envelope[1 : 1+nonceBytes]
	ciphertext := envelope[1+nonceBytes:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(name))
	if err != nil {
		return nil, errs.Wrap(err, "the sealed session value did not open")
	}
	return plaintext, nil
}
