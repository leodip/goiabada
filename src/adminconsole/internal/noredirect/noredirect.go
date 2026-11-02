// Package noredirect refuses, for the admin console's five clients of the auth server, every
// redirect net/http would follow (#715 decision 13).
//
// The auth server's own answers to the console redirect nowhere, so a redirect means the internal
// URL reaches something else: the auth server's plain-HTTP listener redirecting to its https base
// URL, or an edge in between. Followed, a 301 turned a token grant into a GET that failed with no
// word of a redirect, and a 307 or 308 resent the grant's body and, on the same host, its
// Authorization to wherever it pointed. Refused, the call fails with an *Error naming the target's
// origin and the setting to change.
package noredirect

import (
	"fmt"
	"net/http"
)

// Error is a redirect the admin console refused: the status it was answered with, and the origin
// of its target, the scheme, the host and the port, empty when the answer named no target the
// console could read. The target's user information, path, query and fragment are never kept: a
// target built from the console's own request can carry what it sent.
type Error struct {
	StatusCode int
	Origin     string
}

func (e *Error) Error() string {
	target := "a target it could not read"
	if e.Origin != "" {
		target = e.Origin
	}
	return fmt.Sprintf("the auth server answered %d, a redirect to %s, which the admin console does not follow:"+
		" set GOIABADA_AUTHSERVER_INTERNALBASEURL to an address of the auth server that answers directly",
		e.StatusCode, target)
}

// Client returns a copy of client whose every redirect net/http would follow reaches the caller as
// an *Error instead, its body closed and nothing sent to its target; every other answer arrives as
// it was. The copy keeps client's timeout and cookie jar and sends through client's own transport,
// or the default one when it has none; client itself is untouched.
//
// The refusal wraps the transport it is given, so built over a client upstreammetrics records, the
// redirect is still recorded under the status it arrived with.
func Client(client *http.Client) *http.Client {
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	refusing := *client
	refusing.Transport = &transport{next: next}
	return &refusing
}

// transport turns a redirect into an *Error before net/http's client can follow it.
type transport struct {
	next http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil || !followed(resp.StatusCode) {
		return resp, err
	}
	_ = resp.Body.Close()

	refused := &Error{StatusCode: resp.StatusCode}
	// Location resolves a relative target against the request's URL, so a relative one names
	// the request's own origin.
	if target, err := resp.Location(); err == nil && target.Scheme != "" && target.Host != "" {
		refused.Origin = target.Scheme + "://" + target.Host
	}
	return nil, refused
}

// followed reports whether status is one of the redirects net/http's client follows.
func followed(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}
