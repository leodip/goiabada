package dpop

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// NonceLifetime is how long a server nonce is accepted after it is minted (#42 decision 7).
const NonceLifetime = 10 * time.Minute

// nonceClockSkew is how far ahead of an instance's clock the moment a nonce was minted may lie: the
// instance that minted it may run a little ahead of the one judging it. It is the window the
// resources allow a proof's iat (#42 decision 8), so a client is not sent from instance to instance
// retrying a nonce one of them thinks is from the future.
const nonceClockSkew = IssuedAtWindow

// nonceKeyInfo separates the nonce key from every other use of the session authentication key.
const nonceKeyInfo = "goiabada dpop nonce v1"

// nonceLength is a nonce's decoded length: an 8-byte timestamp and a 32-byte HMAC-SHA256 tag.
const nonceLength = 8 + sha256.Size

// Nonces mints and judges the server nonces RFC 9449 section 8 has a client put in its proofs. A
// nonce is the moment it was minted, in Unix seconds, authenticated with HMAC-SHA256 under a key
// derived from the auth server's session authentication key, base64url without padding: it cannot
// be predicted without the key (section 8 MUST), it needs no table, and every instance sharing the
// configuration accepts the nonces of the others (#42 decision 7). After the key is rotated a
// client's old nonce is refused, which costs it one use_dpop_nonce retry.
type Nonces struct {
	key []byte
}

// NewNonces returns the nonces of a server whose session authentication key is given, read as the
// session store reads it.
func NewNonces(sessionAuthenticationKey []byte) *Nonces {
	key, err := hkdf.Key(sha256.New, sessionAuthenticationKey, nil, nonceKeyInfo, sha256.Size)
	if err != nil {
		// hkdf.Key fails only for a key length beyond 255 hashes, never for this one.
		panic(err)
	}
	return &Nonces{key: key}
}

// Mint returns a fresh nonce minted at now. Its characters are base64url's, all of them NQCHAR
// (RFC 9449 section 8.1).
func (n *Nonces) Mint(now time.Time) string {
	raw := make([]byte, 8, nonceLength)
	//nolint:gosec // G115: the timestamp's bit pattern, which Accepts reads back by the inverse conversion
	binary.BigEndian.PutUint64(raw, uint64(now.Unix()))
	return base64.RawURLEncoding.EncodeToString(append(raw, n.tag(raw)...))
}

// Accepts reports whether nonce is one minted under this key that has not expired at now: minted
// no more than NonceLifetime before now, and no more than a minute after it.
func (n *Nonces) Accepts(nonce string, now time.Time) bool {
	minted, ok := n.minted(nonce)
	if !ok {
		return false
	}
	return !now.After(minted.Add(NonceLifetime)) && !now.Before(minted.Add(-nonceClockSkew))
}

// ExpiresAt returns the last moment Accepts takes nonce, NonceLifetime after it was minted, for a
// nonce minted under this key: how long the replay store keeps a proof carrying it (#42 decision
// 8). It reports false for any other value.
func (n *Nonces) ExpiresAt(nonce string) (time.Time, bool) {
	minted, ok := n.minted(nonce)
	if !ok {
		return time.Time{}, false
	}
	return minted.Add(NonceLifetime), true
}

// minted returns the moment nonce was minted, in whole seconds, when it was minted under this key.
func (n *Nonces) minted(nonce string) (time.Time, bool) {
	// Length and alphabet before decoding: the strict decoder still skips CR and LF.
	if len(nonce) != base64.RawURLEncoding.EncodedLen(nonceLength) || !isBase64URL(nonce) {
		return time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(raw) != nonceLength {
		return time.Time{}, false
	}
	if !hmac.Equal(raw[8:], n.tag(raw[:8])) {
		return time.Time{}, false
	}
	//nolint:gosec // G115: the bit pattern Mint wrote, read back as the timestamp it was; a tag under this key proves Mint wrote it
	return time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0), true
}

func (n *Nonces) tag(timestamp []byte) []byte {
	mac := hmac.New(sha256.New, n.key)
	mac.Write(timestamp)
	return mac.Sum(nil)
}
