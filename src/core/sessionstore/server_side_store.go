package sessionstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

const (
	// SessionIdBytes is how much entropy the identifier carries, 256 bits, hex encoded
	// to 64 characters. OWASP's session management guidance asks for at least 64 bits
	// and at least 16 hexadecimal characters; this is four times both (#266).
	SessionIdBytes = 32

	// PreAuthLifetime is how long a browser session that has not yet authenticated
	// lives. It is short on purpose: /auth/authorize is not rate limited and writes a
	// session before it validates anything, so every unauthenticated caller costs a row,
	// and this constant is what bounds how many of them can be alive at once. Generous
	// for a first sign-in that includes installing an authenticator app and scanning a
	// code, and far shorter than the day an authenticated session may run for (#266).
	PreAuthLifetime = 30 * time.Minute

	// TouchThreshold is how stale last_accessed may get before a read writes it back.
	// Without it every request would put a write in front of a page render, which on
	// SQLite means an fsync on the single connection the whole process shares. Ten
	// seconds is 0.1% of the default two hour idle window, so no configuration makes
	// the staleness observable to anyone (#266).
	TouchThreshold = 10 * time.Second

	// MaxSessionDataBytes bounds an encoded session blob, and it is the ceiling that
	// actually binds rather than one the store advertises and does not enforce, which is
	// the defect #266 exists to retire. securecookie checks it on the way in and on the
	// way out, so an oversized session fails its save with a clear error instead of being
	// written and then refused somewhere further along.
	//
	// A megabyte, matching what the session endpoint accepts as a request body: the store
	// refuses first, and with a better error, rather than letting a blob be built here and
	// rejected at the wire. The largest real payload is an admin console session holding a
	// full token set, about 13 KB of ciphertext, so nothing a deployment can legitimately
	// produce comes near it.
	MaxSessionDataBytes = 1 << 20

	// MaxCookieDecodeAgeSeconds is the oldest cookie securecookie will decode at all.
	// It is a backstop and not the session's lifetime: the row's expires_at decides
	// whether a session is alive, and a cookie older than its row simply names nothing.
	MaxCookieDecodeAgeSeconds = 86400 * 365

	// hostCookiePrefix is the __Host- prefix, which a browser accepts only on a cookie
	// that is Secure, carries no Domain and has Path=/. What it buys here is that a
	// sibling subdomain can no longer set a cookie this server will receive, which is
	// the practical way an attacker plants a session identifier, and planting one is
	// the attack a server-side store newly exposes (#266).
	hostCookiePrefix = "__Host-"

	// legacyMaxChunks is how many chunk cookies ChunkedCookieStore could have written.
	// It is repeated here rather than referenced because that store is being deleted
	// and this value has to outlive it: browsers are still carrying its cookies and
	// something has to name them to delete them.
	legacyMaxChunks = 50
)

// ErrNotFound is "there is no such session". It is a different answer from any other
// error, and the difference is load bearing: not found means the session is gone, which
// is a fresh session, while any other error means the lookup could not be performed,
// which is a refused request. Collapsing the second into the first would sign everyone
// out during a database interruption and leave nothing to diagnose it by (#266).
var ErrNotFound = errors.New("session not found")

// randReader is crypto/rand in production. It is a variable so a test can make the
// CSPRNG fail, which is the one failure this store must not paper over.
var randReader io.Reader = rand.Reader

// Record is what the storage half knows about a session: the ciphertext, and the two
// timestamps that govern the container it sits in. Nothing here describes the session's
// contents, which the storage half holds no key for (#266).
type Record struct {
	Data         []byte
	LastAccessed time.Time
	ExpiresAt    time.Time
}

// Backend is the storage half of the store. It carries ciphertext and knows nothing
// about session contents, which is what lets one store serve a module that has a
// database and one that does not: the auth server's backend writes rows, the admin
// console's calls an endpoint, and neither can read what it is holding (#266).
//
// No method takes an owner. The owner is fixed when a backend is constructed, so no
// call can name another application's rows however it is composed.
//
// Load, Update and Touch answer ErrNotFound when there is no such session. Every other
// error means the operation could not be performed.
//
// The context is the request's. It carries the settings the auth server's middleware has
// already read, which is what saves the database backend a second read of them, and it
// is what will carry a deadline to the backend that speaks over the network.
type Backend interface {
	Load(ctx context.Context, id string) (*Record, error)
	// Create writes a new session and returns the expires_at it chose, which is what
	// the browser cookie's own expiry is set from.
	Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error)
	// Update replaces an existing session's contents. It never inserts: a session that
	// is gone stays gone, because the request that removed it was most likely rotating
	// the identifier, and re-creating the row would undo that rotation.
	Update(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error)
	Touch(ctx context.Context, id string, authenticated bool) (time.Time, error)
	Delete(ctx context.Context, id string) error
}

// ExpiresAt computes when a browser session stops being usable.
//
// Two phases. A session that has not authenticated gets a flat PreAuthLifetime and
// neither setting is consulted: an idle timeout means "this person stopped using the
// application", which says nothing about a form nobody submitted. Once it has
// authenticated the deployment's own session settings apply unchanged, so the browser
// session and the SSO session never disagree about when a browser stops being signed in.
//
// The maximum lifetime is measured from the row's creation, and that is exact rather
// than approximate: the identifier is rotated at sign-in, so an authenticated session's
// row was created at the moment it authenticated (#266).
func ExpiresAt(now, createdAt time.Time, authenticated bool, idleTimeout, maxLifetime time.Duration) time.Time {
	if !authenticated {
		return now.Add(PreAuthLifetime)
	}

	idleDeadline := now.Add(idleTimeout)
	absoluteDeadline := createdAt.Add(maxLifetime)
	if absoluteDeadline.Before(idleDeadline) {
		return absoluteDeadline
	}
	return idleDeadline
}

// ServerSideStore keeps session contents in a Backend and puts nothing in the browser
// but an opaque, signed identifier. It implements sessions.Store, so the hundred places
// that already take that interface are untouched (#266).
type ServerSideStore struct {
	// Codecs sign and encrypt the identifier in the cookie. What they encode is 64 hex
	// characters, so they keep securecookie's own 4096 byte ceiling: it finally has
	// something to guard, where the store this replaced had to disable it.
	Codecs []securecookie.Codec

	// DataCodecs encrypt the session contents before they reach the backend, with this
	// module's own keys, so a backend that is somebody else's server holds bytes it
	// cannot read.
	//
	// A separate set from Codecs for one reason, and it is not cosmetic: securecookie's
	// length ceiling is a property of the codec, and these two encode values whose sizes
	// differ by four orders of magnitude. Sharing one set means either the cookie's
	// identifier is guarded by a megabyte, which guards nothing, or the session blob is
	// capped at a cookie's 4096 bytes, which is smaller than an ordinary admin console
	// session and would fail every save it made.
	DataCodecs []securecookie.Codec

	// Options are the cookie defaults. MaxAge is not read from here: it is decided per
	// save, from PersistentCookie and the row's own expiry.
	Options *sessions.Options

	// Backend is the storage half.
	Backend Backend

	// AuthenticatedKey is the session.Values key whose presence means this session has
	// authenticated. It differs per module because the two modules keep different things
	// there, and only the store can see inside the blob to check it.
	AuthenticatedKey string

	// Secure drives both the cookie's Secure attribute and the __Host- prefix. A
	// prefixed cookie is rejected by the browser over plain http, so a development
	// deployment gets the bare name.
	Secure bool

	// PersistentCookie decides whether the cookie outlives the browser. The auth server
	// sets it, so single sign-on survives a restart; the admin console does not, so an
	// administrator's tokens are never written to disk. The trade is argued in full in
	// the issue: the cost of no-expiry is paid by everyone every working day, and the
	// gain is paid out once, to whoever loses a laptop (#266).
	PersistentCookie bool

	// now is the clock, replaceable in tests.
	now func() time.Time
}

// NewServerSideStore builds a store over the given backend. keyPairs are the same
// authentication and encryption keys the cookie store used, in the same order.
func NewServerSideStore(backend Backend, authenticatedKey string, secure bool, keyPairs ...[]byte) *ServerSideStore {
	codecs := securecookie.CodecsFromPairs(keyPairs...)
	dataCodecs := securecookie.CodecsFromPairs(keyPairs...)

	// securecookie's own length guard is kept on both sets, unlike the chunked store which
	// had to disable it, and set to what each set actually carries. The cookie's is left at
	// securecookie's 4096 byte default, which is generous for 64 hex characters; the blob's
	// is raised to the size a session is allowed to reach, because the default is a cookie's
	// limit and the blob is no longer in a cookie.
	for _, codec := range codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(MaxCookieDecodeAgeSeconds)
		}
	}
	for _, codec := range dataCodecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(MaxCookieDecodeAgeSeconds)
			sc.MaxLength(MaxSessionDataBytes)
		}
	}

	return &ServerSideStore{
		Codecs:     codecs,
		DataCodecs: dataCodecs,
		Options: &sessions.Options{
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		},
		Backend:          backend,
		AuthenticatedKey: authenticatedKey,
		Secure:           secure,
		now:              func() time.Time { return time.Now().UTC() },
	}
}

// CookieName is the name the cookie physically carries, which is not the name callers
// pass in. The logical name is what the codecs sign under and what the storage layer
// records as the owner, and it stays the same whatever scheme the deployment runs on;
// the physical name gains the __Host- prefix on https. Deriving one from the other would
// make every live session unreadable the moment a deployment moved between the two.
func (s *ServerSideStore) CookieName(logicalName string) string {
	if s.Secure {
		return hostCookiePrefix + logicalName
	}
	return logicalName
}

// StaleCookieNames lists the cookies left behind by the chunked cookie store, for the
// layer that has an http.ResponseWriter to delete them with. Left alone they ride along
// in every request until their own expiry, which is a year on the admin console, so
// nobody would see any improvement until then.
//
// The bare logical name is included only on https, where the live cookie is prefixed.
// On plain http the bare name IS the live cookie, and deleting it would delete the
// session the same response just wrote. Returning only names that are always safe to
// delete is the point of this being a function rather than a comment.
func (s *ServerSideStore) StaleCookieNames(logicalName string) []string {
	names := make([]string, 0, legacyMaxChunks+1)
	if s.Secure {
		names = append(names, logicalName)
	}
	for i := 0; i < legacyMaxChunks; i++ {
		names = append(names, chunkCookieName(logicalName, i))
	}
	return names
}

// Get returns the session for this request, memoised by gorilla's per-request registry
// so the several middlewares that ask for it cost one load between them.
func (s *ServerSideStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New loads the session named by the request's cookie, or returns a fresh one.
//
// Four outcomes, and they are deliberately distinct (#266):
//
//   - no cookie: a fresh session, and the backend is never consulted, so a visitor
//     presenting nothing costs no read at all
//   - a cookie that does not decode: a fresh session, which is what the cookie store did
//     with a corrupt value and what a rotated key or a tampered cookie should do
//   - a valid cookie naming no row: a fresh session. The session expired, was logged out
//     or was reaped, and all three mean the same thing to the browser
//   - a lookup that failed: the error is returned, and the middleware answers 500. This
//     is the one that must not become a fresh session: failing open would discard every
//     session in flight during any database interruption, and would hand anyone who can
//     briefly disrupt the database a way to sign everybody out
func (s *ServerSideStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := s.freshSession(name)

	cookie, err := r.Cookie(s.CookieName(name))
	if err != nil {
		return session, nil
	}

	var id string
	if err := securecookie.DecodeMulti(name, cookie.Value, &id, s.Codecs...); err != nil {
		slog.Debug("browser session cookie did not decode, starting a fresh session",
			"sessionName", name)
		return session, nil
	}

	record, err := s.Backend.Load(requestContext(r), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return session, nil
		}
		// The session goes back beside the error, and it must not be nil. gorilla/sessions
		// documents on Store.New that "New should never return a nil session, even in the
		// case of an error if using the Registry infrastructure to cache the session", and
		// Get is exactly that infrastructure: Registry.Get assigns to session.name without
		// looking at the error, so a nil here is a nil pointer dereference inside the
		// library on the one path that exists to make a storage fault diagnosable.
		//
		// Nothing fails open as a result. This error is not a securecookie.MultiError, so
		// the cookie-reset middleware's decode branch does not fire and it passes the
		// request along; the registry memoises the (session, error) pair, so the next
		// middleware to ask receives the same error and answers 500 with the cause logged,
		// which is the refusal this store owes a lookup it could not perform (#266).
		return session, errors.Wrap(err, "unable to load the browser session")
	}

	if err := securecookie.DecodeMulti(name, string(record.Data), &session.Values, s.DataCodecs...); err != nil {
		slog.Warn("stored browser session data did not decode, starting a fresh session",
			"error", err, "sessionName", name)
		return session, nil
	}

	session.ID = id
	session.IsNew = false

	if err := s.touchIfStale(requestContext(r), session, record); err != nil {
		if errors.Is(err, ErrNotFound) {
			// The row went away between the read and the touch, so the session is gone
			// even though it was there a moment ago. A fresh session is the honest
			// answer, and it has to be a new one: the session read a moment ago is
			// holding the contents that just stopped existing.
			return s.freshSession(name), nil
		}
		// A fresh session rather than the one just loaded, and non-nil for the reason
		// above. The error is what every caller acts on; a caller that somehow did not
		// would get an empty session rather than the live contents of a session whose
		// liveness could not be confirmed.
		return s.freshSession(name), err
	}

	return session, nil
}

// freshSession is a session nobody has stored yet: no identifier, no contents, and the
// store's default cookie options.
func (s *ServerSideStore) freshSession(name string) *sessions.Session {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	return session
}

// touchIfStale records that a live session was used, but only once the stored timestamp
// has gone stale. Writing on every request would put a write in front of every page, and
// on SQLite that is an fsync on the one connection the whole process shares.
func (s *ServerSideStore) touchIfStale(ctx context.Context, session *sessions.Session, record *Record) error {
	if s.now().Sub(record.LastAccessed) <= TouchThreshold {
		return nil
	}

	if _, err := s.Backend.Touch(ctx, session.ID, s.isAuthenticated(session)); err != nil {
		if errors.Is(err, ErrNotFound) {
			return err
		}
		return errors.Wrap(err, "unable to touch the browser session")
	}
	return nil
}

// Save writes the session to the backend and names it with a cookie.
//
// A session that was loaded is updated and never inserted. If the update finds no row,
// the session is gone and Save fails rather than putting it back: the request that
// removed it was most likely rotating the identifier, and re-creating the row here would
// undo the rotation from a request still in flight under the old identifier.
//
// That failure deliberately writes no cookie either, not even a deletion. A deletion
// emitted here would clobber the cookie the rotating request just set, which is exactly
// the outcome the rule above exists to prevent.
func (s *ServerSideStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	ctx := requestContext(r)

	if session.Options != nil && session.Options.MaxAge < 0 {
		return s.deleteSession(ctx, w, session)
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.DataCodecs...)
	if err != nil {
		return errors.Wrap(err, "unable to encode the browser session")
	}

	authenticated := s.isAuthenticated(session)

	if session.ID == "" {
		id, err := newSessionId()
		if err != nil {
			return err
		}

		expiresAt, err := s.Backend.Create(ctx, id, []byte(encoded), authenticated)
		if err != nil {
			return errors.Wrap(err, "unable to create the browser session")
		}

		session.ID = id
		return s.setCookie(w, session, id, expiresAt)
	}

	expiresAt, err := s.Backend.Update(ctx, session.ID, []byte(encoded), authenticated)
	if err != nil {
		return errors.Wrap(err, "unable to update the browser session")
	}

	return s.setCookie(w, session, session.ID, expiresAt)
}

// deleteSession removes the row and expires the cookie. Emptying the values and saving
// is not enough under a server-side store: it would leave a live row holding an empty
// session, where logging out has to actively invalidate both halves.
func (s *ServerSideStore) deleteSession(ctx context.Context, w http.ResponseWriter, session *sessions.Session) error {
	if session.ID != "" {
		if err := s.Backend.Delete(ctx, session.ID); err != nil {
			return errors.Wrap(err, "unable to delete the browser session")
		}
		session.ID = ""
	}

	opts := *session.Options
	opts.MaxAge = -1
	http.SetCookie(w, s.buildCookie(session.Name(), "", &opts))
	return nil
}

// setCookie writes the identifier into the browser.
//
// The cookie's own expiry follows the row's, for the module that keeps one: the browser
// then never holds a handle that outlives what it names, and the operator's session
// timeout governs both halves through one setting. The module that does not keep one
// leaves MaxAge at zero, which net/http renders as neither Max-Age nor Expires, so the
// browser drops the cookie when it closes and the tokens inside never reach disk.
func (s *ServerSideStore) setCookie(w http.ResponseWriter, session *sessions.Session, id string, expiresAt time.Time) error {
	encodedId, err := securecookie.EncodeMulti(session.Name(), id, s.Codecs...)
	if err != nil {
		// The row is already written at this point, so the session exists and the
		// browser is about to be told nothing about it. That is reported rather than
		// logged: a save that returns nil having issued no cookie looks like success
		// and behaves like a silent sign-out on the very next request.
		return errors.Wrap(err, "unable to encode the browser session identifier")
	}

	opts := *session.Options
	opts.MaxAge = 0
	if s.PersistentCookie {
		remaining := int(expiresAt.Sub(s.now()).Seconds())
		if remaining < 1 {
			remaining = 1
		}
		opts.MaxAge = remaining
	}

	http.SetCookie(w, s.buildCookie(session.Name(), encodedId, &opts))
	return nil
}

// DeletionCookie is the cookie that removes name from the browser.
//
// The attributes are not decoration and getting them wrong fails silently, which is why
// this lives on the store rather than at the caller. A browser matches a deletion to the
// cookie it replaces by name, domain and path, so the path must be the one the cookie was
// set with; and a __Host- prefixed cookie is refused outright unless it is Secure, so a
// deletion missing that attribute does nothing at all to the very cookie this store sets
// on an https deployment (#266).
//
// The name is physical and passed in whole, because the two callers name different
// things: CookieName for this store's own cookie, and StaleCookieNames for what the
// chunked cookie store left behind.
func (s *ServerSideStore) DeletionCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:  name,
		Value: "",
		Path:  s.Options.Path,
		// Both, and not one or the other: Max-Age is what a current browser acts on, and
		// the expiry in the past is what one that predates it acts on.
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		Secure:   s.Secure,
		HttpOnly: s.Options.HttpOnly,
		SameSite: s.Options.SameSite,
	}
}

func (s *ServerSideStore) buildCookie(logicalName, value string, options *sessions.Options) *http.Cookie {
	cookie := &http.Cookie{
		Name:     s.CookieName(logicalName),
		Value:    value,
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}
	if options.MaxAge < 0 {
		// A negative MaxAge means this cookie is being removed, and a removal carries both
		// attributes for the reason DeletionCookie states below: Max-Age is what a current
		// browser acts on, and the expiry in the past is what one that predates it acts on.
		// Set here rather than at the caller so the logout path and the stale-cookie sweep
		// cannot drift apart, which they had (#266).
		cookie.Expires = time.Unix(0, 0).UTC()
	}
	return cookie
}

// isAuthenticated reports whether this session has signed in, which decides which of the
// two lifetimes applies to it. Only the store can answer it, because only the store can
// see inside the blob; what it produces is a boolean about the container, not about the
// contents, which is why it can cross a module boundary without telling anyone anything.
func (s *ServerSideStore) isAuthenticated(session *sessions.Session) bool {
	value, ok := session.Values[s.AuthenticatedKey]
	if !ok || value == nil {
		return false
	}
	if str, isString := value.(string); isString {
		return str != ""
	}
	return true
}

// requestContext is the request's context, or a background one when there is no request
// behind the call. Nothing in the store requires a request; the context only ever carries
// what a backend may use to save itself work.
func requestContext(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return r.Context()
}

// chunkCookieName is the name ChunkedCookieStore gave its nth data cookie. It is
// reproduced here so the names survive the store that created them.
func chunkCookieName(logicalName string, n int) string {
	return logicalName + "-chunk-" + strconv.Itoa(n)
}

// newSessionId returns 256 bits from the CSPRNG, hex encoded.
//
// Deliberately not stringutil.GenerateSecurityRandomString: that helper returns "" when
// the CSPRNG fails rather than an error (#211), and a session identifier that silently
// becomes the empty string for every session is the one fail-open this store must not
// have. A failure here fails the save instead.
func newSessionId() (string, error) {
	buf := make([]byte, SessionIdBytes)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", errors.Wrap(err, "unable to read from the random number generator")
	}
	return hex.EncodeToString(buf), nil
}
