package sessionstore

import (
	"context"
	"net/http"
)

// Options are the cookie attributes a session is written with. Six fields, which is
// what this repository actually sets: the store's defaults fill them in and two logout
// handlers override MaxAge.
//
// MaxAge below zero is the deletion signal, and that is why this is a struct of its own
// rather than an http.Cookie. An http.Cookie would put Name, Value and Expires in front
// of every handler, and would place the deletion signal beside an Expires that can
// contradict it; here there is one way to say "delete this" and nothing to disagree
// with it (#269).
type Options struct {
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// Session is one browser session: an identifier, the contents, and the cookie options
// it will be written with.
//
// Values is map[string]any because every key in this repository is a string constant.
// The map type is part of the stored wire format, since Values is what gets serialised
// on every save, so it is fixed now while the format is changing anyway rather than
// later behind a compatibility path (#269).
type Session struct {
	// ID is the identifier the backend knows this session by, empty until it is saved.
	ID string

	// Values is the session's contents. Never nil on a session from NewSession.
	Values map[string]any

	// Options are the cookie attributes for this session, a copy of the store's
	// defaults that a handler may override.
	Options *Options

	// IsNew is true for a session nobody has stored yet.
	IsNew bool

	// store is who to save to, so a handler that holds a session can save it without
	// also holding the store.
	store Store

	// name is the logical session name. It is what the sealing binds as associated
	// data and what the storage layer records as the owner, so it is read-only to
	// callers: changing it on a loaded session would ask the store to write a session
	// under a name it was not sealed under.
	name string
}

// Store is what a hundred handler signatures take. Two methods, because that is what
// callers outside this package use: nothing outside the store calls New and no test
// stubs it, so New stays a method on ServerSideStore and its "never a nil session"
// rule stays the store's own rather than an obligation on every implementer (#269).
type Store interface {
	Get(r *http.Request, name string) (*Session, error)
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// NewSession returns a session belonging to the given store, with a non-nil Values and
// a non-nil zero Options. Non-nil Values is the contract every caller relies on: a
// handler writes into Values without checking it first, so a nil map here would be a
// panic at the first write rather than an error anywhere.
func NewSession(store Store, name string) *Session {
	return &Session{
		Values:  make(map[string]any),
		Options: new(Options),
		store:   store,
		name:    name,
	}
}

// Name is the logical session name.
func (s *Session) Name() string {
	return s.name
}

// Save writes this session through the store it came from.
func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
	return s.store.Save(r, w, s)
}

// SetFlash stores a one-shot message under key, to be read once by a later request.
//
// A flash is stored as a plain string in Values, which is the whole of what this
// repository needs: every write here is a notice that a form saved, and every read
// reduces it to a boolean. Storing a string also means the serialiser needs nothing
// registered to encode it, where a slice of interfaces would (#269).
func (s *Session) SetFlash(key, value string) {
	s.Values[key] = value
}

// TakeFlash returns the flash stored under key and removes it, so the next request does
// not see it again. The second result reports whether one was there.
//
// Absence is reported in the boolean rather than by an empty string, so a flash whose
// value is empty is still distinguishable from no flash at all. A value some other
// writer left under the same key is treated as absent rather than asserted, so this
// cannot panic on it.
func (s *Session) TakeFlash(key string) (string, bool) {
	value, ok := s.Values[key].(string)
	if !ok {
		return "", false
	}
	delete(s.Values, key)
	return value, true
}

// registryKey is the context key the per-request session cache is installed under.
type registryKey struct{}

// registryEntry is one memoised answer: the session and the error Get gave for a name.
// Both are kept, because a storage fault has to be answered identically to every
// middleware that asks about the same session on the same request.
type registryEntry struct {
	session *Session
	err     error
}

// registry is the per-request cache, keyed by logical session name. It holds no lock:
// one http.Request is served by one goroutine, and a handler that fans out and calls
// Get concurrently on the same request would be racing on the *Session itself long
// before it raced here.
type registry struct {
	sessions map[string]registryEntry
}

// registryFor returns the request's session cache, installing one if the request does
// not carry it yet.
//
// The installation writes the new context back into the request in place, and that is
// load bearing rather than a convenience. A request is handed to Get by value-ish
// pointer and there is no way to hand a replacement back to the caller, so a cache
// installed on a derived request only would be invisible to every later Get on the same
// request. The JWT middleware depends on exactly that visibility: it obtains the
// session, calls refreshToken, which obtains the session *again* through a second Get,
// writes the refreshed tokens into that object and saves it, and then the outer
// function reads the refreshed tokens back out of *its* object. Without the in-place
// write the second Get loads a second object, the refreshed tokens are written to it,
// and the outer function serves the pre-refresh tokens it still holds (#269).
func registryFor(r *http.Request) *registry {
	if reg, ok := r.Context().Value(registryKey{}).(*registry); ok {
		return reg
	}
	reg := &registry{sessions: make(map[string]registryEntry)}
	*r = *r.WithContext(context.WithValue(r.Context(), registryKey{}, reg))
	return reg
}
