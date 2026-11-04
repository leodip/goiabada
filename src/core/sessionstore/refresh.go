package sessionstore

import (
	"net/http"
)

// Refreshing marks every request it wraps as activity on its browser session: the first Get of
// the session on the request touches its row once the row is more than TouchThreshold stale, as it
// always has, and a store whose cookie can outlive the browser sends the session's cookie again on
// the response, so the browser keeps the cookie as long as the row lives: a sign-in in progress for
// its renewed 30 minutes, and a signed-in session as its KeepSignedIn answers, which also stops a
// cookie outliving the browser once the answer changes.
//
// The cookie is held until the response's headers go out, and sent then only while the request
// has written no cookie of that name itself and the row the cookie names still holds what the read
// found. The touch happens when the session is first read, before the handler runs, and while the
// handler works another request of the same browser can rotate the session, end it, or write it
// anew, as a password entry recording a new Keep me signed in answer does, and answer first with a
// cookie of its own. A cookie sent from the read would then reach the browser last: naming a row
// that is gone, it signs the browser out, and built from the older contents, it undoes the newer
// answer, keeping a cookie past the browser's restart that the user just declined. A cookie the
// request writes itself, from a save, a rotation or a sign-out, says more than the refresh and
// stands alone (#743).
//
// On a request it does not wrap, such a store reads the session without moving its idle deadline:
// a touch there would either leave the cookie expiring before its row, or send the cookie on an
// answer that may be cacheable. The auth server mounts it on its page branch alone, whose answers
// are no-store, so a reissued cookie never rides on a client logo, a profile picture, the OpenAPI
// document, discovery or JWKS, which a shared cache could store and replay to other visitors (#743
// decisions 8 and 9). The admin console's store, whose cookie ends with the browser, touches on
// every read as before and mounts nothing.
//
// It must run before anything reads the session on the request: Get memoises its answer, so a
// session read before it is not read again.
func Refreshing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refresh := &refreshWriter{ResponseWriter: w}
		registryFor(r).refresh = refresh
		// A handler that returned without answering leaves net/http to answer on w, beneath this
		// writer, and one that panicked leaves the recoverer above to answer on it, so the held
		// cookie goes onto the headers as the handler ends either way, while they are still unsent.
		defer refresh.release()
		next.ServeHTTP(refresh, r)
	})
}

// refreshWriter is the response a Refreshing request is answered on. It holds the cookies a
// refresh sends until the headers go out.
type refreshWriter struct {
	http.ResponseWriter
	held     []heldCookie
	released bool
}

// heldCookie is one refreshed session cookie, and whether the row it names still holds what the
// refresh read.
type heldCookie struct {
	cookie      *http.Cookie
	stillAsRead func() bool
}

// refreshFor is the writer a refresh on r holds its cookie on, or nil when no Refreshing wraps r.
func refreshFor(r *http.Request) *refreshWriter {
	if r == nil {
		return nil
	}
	if reg, ok := r.Context().Value(registryKey{}).(*registry); ok {
		return reg.refresh
	}
	return nil
}

// hold keeps cookie for the response's headers, to be sent then only while the request wrote no
// cookie of its name and stillAsRead answers true.
func (w *refreshWriter) hold(cookie *http.Cookie, stillAsRead func() bool) {
	w.held = append(w.held, heldCookie{cookie: cookie, stillAsRead: stillAsRead})
}

// release puts the held cookies that still stand onto the headers, once: the first write, status
// or flush of the response, or the end of the request when the handler wrote none.
func (w *refreshWriter) release() {
	if w.released {
		return
	}
	w.released = true
	for _, held := range w.held {
		if wroteCookie(w.Header(), held.cookie.Name) || !held.stillAsRead() {
			continue
		}
		http.SetCookie(w.ResponseWriter, held.cookie)
	}
	w.held = nil
}

// wroteCookie reports whether header already sets a cookie called name.
func wroteCookie(header http.Header, name string) bool {
	for _, line := range header.Values("Set-Cookie") {
		if cookie, err := http.ParseSetCookie(line); err == nil && cookie.Name == name {
			return true
		}
	}
	return false
}

// WriteHeader releases the held cookies before the headers of the final answer go out. An
// informational status passes on and leaves them held: net/http sends the headers with it and keeps
// them for the final answer, which may come after another request rotated the session. 101 is
// final, since the connection is the handler's after it.
func (w *refreshWriter) WriteHeader(code int) {
	if code < 100 || code > 199 || code == http.StatusSwitchingProtocols {
		w.release()
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write releases the held cookies before the headers go out with the body's first bytes.
func (w *refreshWriter) Write(b []byte) (int, error) {
	w.release()
	return w.ResponseWriter.Write(b)
}

// FlushError releases the held cookies before a flush sends the headers. http.ResponseController
// asks for it before it unwraps, so a flush through the controller cannot pass this writer by.
func (w *refreshWriter) FlushError() error {
	w.release()
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap answers the writer beneath, which is how http.ResponseController reaches its Hijack and
// deadlines through this one.
func (w *refreshWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
