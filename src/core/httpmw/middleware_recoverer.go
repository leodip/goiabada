package httpmw

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recoverer answers a panic beneath it with an empty 500 and writes one ERROR record of it through
// the process's handler, carrying the request id, the panic value and the stack it was raised on.
// It replaces chi's Recoverer, which answered the same 500 but wrote a coloured, multi-line trace
// to standard error, outside the log stream and with no request id to find it by (#462).
//
// http.ErrAbortHandler is raised again, unanswered and unrecorded: it is how a handler aborts its
// response on purpose, and net/http recovers it quietly. A request asking to upgrade its connection
// is recorded but not answered, as chi's was, since the connection may already be the handler's.
//
// Both servers mount it beneath the request logger and the HTTP metrics, so the 500 it writes goes
// through their writer and both record the status the client received (#203). Each JSON branch
// recovers on its own beneath this, so its client gets the branch's JSON 500 instead (#435).
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(recovered)
			}

			// Taken here, in the deferred call, while the panicking frames are still on the stack.
			slog.ErrorContext(r.Context(), "a request handler panicked",
				"panic", fmt.Sprint(recovered),
				"stack", string(debug.Stack()))

			if r.Header.Get("Connection") != "Upgrade" {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
