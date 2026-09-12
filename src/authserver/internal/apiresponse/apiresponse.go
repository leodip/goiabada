// Package apiresponse writes the admin and account API's JSON envelope, and owns the API's one
// 500. It sits below both `apihandlers` and `authserver/internal/middleware` because both answer
// 500 on that surface and `apihandlers` imports the middleware, so a primitive living beside the
// handlers could not be reached from the bearer middleware without a cycle (#279 decisions 7, 8).
package apiresponse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// internalServerErrorCode is the one code every unexpected failure on this surface answers with.
// The REST API page documents it as the category; the seven per-site spellings it replaced
// (INTERNAL_ERROR, ENCODING_ERROR, SAVE_ERROR, READ_ERROR, DELETE_ERROR, USER_CREATION_FAILED,
// EMAIL_SEND_FAILED and friends) named one condition several ways and no caller acted on the
// difference (#279 decision 7).
const internalServerErrorCode = "INTERNAL_SERVER_ERROR"

// internalServerErrorDescription repeats HttpHelper.JsonError's sentence, so a request that fails
// on the API reads the same as one that fails on the web surface and carries the same request id.
// Until now the API's 500 body named no request id at all, which left an operator no way to join a
// caller's report to a log line (#279 decision 7).
const internalServerErrorDescription = "An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v"

// WriteJSON encodes v into a buffer before it writes anything, then writes the status and the body.
//
// The order is the whole point. The 113 sites this replaces set Content-Type, committed the status
// with WriteHeader, and only then encoded straight onto the wire, so a failing encoder left a
// half-written body under a 200 that could no longer be taken back; 34 of them then called a 500
// writer, which could do nothing but log a superfluous WriteHeader. Buffering first makes an encode
// failure a real 500 (#279 decision 8).
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	buf, err := encode(v)
	if err != nil {
		WriteInternalServerError(w, r, errs.Wrap(err, "unable to encode the API response"))
		return
	}
	write(w, status, buf)
}

// WriteError emits the admin/account API error envelope with the caller-supplied UPPER_SNAKE code
// and message. Consumers route on the HTTP status code, not on the body.
//
// It buffers like WriteJSON but takes no request, because it needs no 500 fallback to reach for: an
// api.ErrorResponse is two strings and a nil map, which encoding/json cannot fail on. Keeping the
// request out of the signature is what lets the ~700 4xx call sites stay as they are.
func WriteError(w http.ResponseWriter, message, code string, statusCode int) {
	buf, err := encode(api.ErrorResponse{
		ErrorCode:        code,
		ErrorDescription: message,
	})
	if err != nil {
		// Unreachable, per the comment above. Answer bare rather than pretend.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	write(w, statusCode, buf)
}

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// WriteInternalServerError logs err once, structured, with a stack and the request id the body
// shows, then answers the one 500 envelope. attrs are the caller's own slog attributes, appended to
// that single record: the sites this replaces logged "userId", "clientId", "permissionId" and
// friends beside the error, and folding them into a message string to fit a fixed signature would
// have traded structure for brevity at 140 sites (#279 decisions 7 and 9).
//
// errs.WithStack is applied here rather than at the call sites, exactly as HttpHelper.JsonError
// does it: it is the identity on anything this tree constructed, so the only value it changes is a
// bare error from the standard library or a dependency, which would otherwise log with no frames.
func WriteInternalServerError(w http.ResponseWriter, r *http.Request, err error, attrs ...any) {
	requestId := LogInternalServerError(r, err, attrs...)
	WriteError(w, fmt.Sprintf(internalServerErrorDescription, requestId),
		internalServerErrorCode, http.StatusInternalServerError)
}

// LogInternalServerError writes the one record and returns the request id, for a surface that
// answers 500 in an envelope of its own that this change does not touch. Dynamic client
// registration is that surface: RFC 7591 section 3.2.2 fixes its body, so it takes the logging half
// and keeps the shape on the wire (#279, plan finding 9).
func LogInternalServerError(r *http.Request, err error, attrs ...any) string {
	requestId := middleware.GetReqID(r.Context())
	// No request_id attribute: the installed handler reads it off the context this call
	// passes it, so naming it here would write it twice. requestId is still read, because
	// the caller puts it on the wire for whoever hit the error (#320 decision 2).
	record := make([]any, 0, len(attrs)+2)
	record = append(record, "error", errs.WithStack(err))
	record = append(record, attrs...)
	slog.ErrorContext(r.Context(), "internal server error", record...)
	return requestId
}
