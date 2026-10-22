package sessionstore

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/leodip/goiabada/core/errs"
)

// MaxCookieValuesBytes bounds a sealed cookie value, on the way in and on the way out. RFC 6265
// section 6.1 asks a browser to keep at least 4096 bytes of a cookie, name and attributes
// included, so a value past this is one some browser drops in silence, which a seal refuses
// rather than discovers at the callback. An open refuses it before decoding anything, so a
// request cannot make the store decrypt more than this (#620).
const MaxCookieValuesBytes = 3072

// ErrCookieValuesTooLong is a seal refused because the sealed value would pass
// MaxCookieValuesBytes, which a caller sealing something a request chose matches with
// errors.Is to seal less rather than fail the request (#620).
//
// A sentinel on stdlib errors.New for the reason ErrNotFound states.
var ErrCookieValuesTooLong = errors.New("the sealed cookie values are too long")

// SealCookieValues seals values into a cookie value under the logical name, for a short-lived
// state a browser carries itself rather than a row it names: the admin console's sign-in
// handshake, which lives from the authorize redirect to the callback and so needs no row, where
// writing one cost the auth server an insert for every anonymous request (#620).
//
// The values key is a third key, derived beside the cookie and data keys, so a session cookie
// value never opens as values and a values cookie never opens as a session identifier, whatever
// names either was sealed under; the name is bound in as associated data on top of that, so two
// values cookies never open as each other. It is sealed with the current keys, as everything this
// store writes is.
//
// The values are encoded without json.Marshal's HTML escaping, which writes each <, > and & as six
// bytes: nothing renders this JSON, and a caller bounds what it seals in bytes. A printable byte
// then costs at most two in the encoding (\" and \\), a byte of invalid UTF-8 three (its
// replacement rune), and only a control character, which no request target carries, six
// (\u0001). A seal past the bound is still refused, with ErrCookieValuesTooLong.
func (s *ServerSideStore) SealCookieValues(name string, values map[string]string) (string, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(values); err != nil {
		return "", errs.Wrap(err, "unable to encode the cookie values")
	}
	plaintext := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	encoded, err := seal(s.random, s.current.values, name, plaintext)
	if err != nil {
		return "", errs.Wrap(err, "unable to seal the cookie values")
	}

	if len(encoded) > MaxCookieValuesBytes {
		return "", errs.Wrapf(ErrCookieValuesTooLong, "unable to seal the cookie values (%d bytes, ceiling %d)",
			len(encoded), MaxCookieValuesBytes)
	}
	return encoded, nil
}

// OpenCookieValues reverses SealCookieValues, with the current keys and then the previous ones,
// so a key rotation does not break a sign-in in flight. Every failure is one error, and the
// caller's answer to all of them is the same: the browser did not bring the values back.
func (s *ServerSideStore) OpenCookieValues(name, value string) (map[string]string, error) {
	if len(value) > MaxCookieValuesBytes {
		return nil, errs.Errorf("the sealed cookie values are too long (%d bytes, ceiling %d)",
			len(value), MaxCookieValuesBytes)
	}

	plaintext, err := s.openWithEither(func(sl *sealer) cipher.AEAD { return sl.values }, name, value)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	if err := json.Unmarshal(plaintext, &values); err != nil {
		return nil, errs.Wrap(err, "unable to decode the cookie values")
	}
	return values, nil
}

// ValuesCookie is the cookie that carries a sealed value under the logical name: this store's
// own attributes and physical name, so it is HttpOnly, Secure and __Host- prefixed on https and
// SameSite as the session cookie is, and it lives PreAuthLifetime, the lifetime of the
// unauthenticated row it replaces. DeletionCookie(CookieName(name)) removes it.
func (s *ServerSideStore) ValuesCookie(name, value string) *http.Cookie {
	opts := *s.options
	opts.MaxAge = int(PreAuthLifetime.Seconds())
	return s.buildCookie(name, value, &opts)
}
