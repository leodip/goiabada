package middleware

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/core/errs"
)

// ServerFaults is how one application branch answers a fault that stops a request before its
// handler can answer it: the settings row or the session could not be read, or something on the
// branch panicked. Each branch answers in the format its handlers answer every other fault in, so a
// client parsing the protocol endpoints or the APIs as JSON gets JSON on these paths too, where it
// used to get text/plain from the settings and session middleware and an empty body from a panic.
// server.go builds one branch per format and routes.go registers each route on the branch of its
// handler's format, so the format is fixed at construction and never read off the request path, as
// the bearer guards' refusals are (#435).
type ServerFaults struct {
	// write answers err at 500 and writes the one record a 500 owes. Nil on the page branch, whose
	// middleware answers in text/plain itself.
	write func(w http.ResponseWriter, r *http.Request, err error)
}

// PageFaults answers as the page routes always have: text/plain from the middleware that failed,
// since the settings being read are what the error page's layout reads, and a panic left to the
// root Recoverer.
func PageFaults() ServerFaults {
	return ServerFaults{}
}

// ProtocolFaults answers RFC 6749 section 5.2's {error, error_description} with server_error at 500
// through jsonWriter, the writer the token, userinfo, JWKS and discovery handlers answer through.
// Dynamic client registration's error body, RFC 7591 section 3.2.2, is the same two members.
func ProtocolFaults(jsonWriter jsonErrorWriter) ServerFaults {
	return ServerFaults{write: jsonWriter.JsonError}
}

// APIFaults answers the admin and account API's documented {error_code, error_description} envelope
// at 500, through the writer every API handler's own 500 goes through.
func APIFaults() ServerFaults {
	return ServerFaults{write: func(w http.ResponseWriter, r *http.Request, err error) {
		apiresponse.WriteInternalServerError(w, r, err)
	}}
}

// answered writes err through the branch's writer and reports true, or reports false on the page
// branch, whose caller answers in text/plain itself.
func (f ServerFaults) answered(w http.ResponseWriter, r *http.Request, err error) bool {
	if f.write == nil {
		return false
	}
	f.write(w, r, err)
	return true
}

// Recoverer answers a panic on the branch in the branch's format, where the root Recoverer answers an
// empty 500 no JSON client can parse. It re-panics http.ErrAbortHandler, which a handler raises to
// abort a response on purpose, as the root one does. On the page branch it is the next handler
// itself, and the root Recoverer answers.
func (f ServerFaults) Recoverer(next http.Handler) http.Handler {
	if f.write == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(recovered)
				}
				f.write(w, r, errs.Errorf("recovered from a panic: %v", recovered))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
