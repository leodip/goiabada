package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging"
	// Aliased because this file's own package is named middleware.
	custom_middleware "github.com/leodip/goiabada/core/middleware"
)

const (
	// A body larger than this is never parsed or logged: the map round-trip below
	// costs roughly 12x what json.Indent did, so an unauthenticated caller could
	// otherwise make the server spend hundreds of milliseconds and hundreds of
	// megabytes formatting one request. 256 KB sits well above anything this API
	// produces: the list endpoints cap at size=200, an audit page of about 100 KB.
	maxLoggedBody = 256 * 1024

	// Indentation cost grows as the square of the nesting depth, so a small but
	// deeply nested body expands into a log line hundreds of megabytes long.
	// 32 is four times the deepest body any endpoint here returns (UpdateUserResponse,
	// at 8 levels), so nothing legitimate is refused.
	maxLoggedDepth = 32

	redactedValue = "[redacted]"
)

// Keys whose values are credentials, written in their struct-tag spelling and
// folded at startup. logoutUrl is here because POST /api/v1/account/logout-request
// returns a URL carrying a signed id_token_hint that /auth/logout accepts: the name
// says nothing about that, so dropping the entry would log a usable token in the
// clear (#145).
var sensitiveKeys = foldKeySet(
	"password", "currentPassword", "newPassword",
	"otpCode", "secretKey", "base64Image",
	"smtpPassword", "clientSecret", "client_secret",
	"verificationCode", "logoutUrl",
)

// The backstop for credential fields nobody remembers to add above. It over-redacts
// about fourteen harmless keys on this surface (otpEnabled, tokenExpirationInSeconds
// and the like), which is accepted: none of them is a value anyone debugs with, and
// every one is visible in the admin UI (#145).
var sensitiveKeySubstrings = foldKeyList("password", "secret", "otp", "token")

// foldRune maps a rune to the smallest rune it is case-equivalent to, which is what
// encoding/json's own foldName does to struct-tag names. Lowercasing is not the same
// thing and is a bypass rather than a rough edge: the decoder accepts
// {"paſſword": ...} into the Password field, and a strings.ToLower matcher
// returns false for it, so that request's password would be logged in the clear (#145).
func foldRune(r rune) rune {
	for {
		folded := unicode.SimpleFold(r)
		if folded <= r {
			return folded
		}
		r = folded
	}
}

// foldKey folds every rune of s, so foldKey(a) == foldKey(b) exactly when
// strings.EqualFold(a, b).
func foldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

func foldKeySet(keys ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[foldKey(key)] = struct{}{}
	}
	return set
}

func foldKeyList(keys ...string) []string {
	folded := make([]string, 0, len(keys))
	for _, key := range keys {
		folded = append(folded, foldKey(key))
	}
	return folded
}

// isSensitiveKey reports whether a JSON key's value must be redacted, matching the
// named set and the substring net against the folded form of the key.
func isSensitiveKey(key string) bool {
	folded := foldKey(key)
	if _, ok := sensitiveKeys[folded]; ok {
		return true
	}
	for _, substring := range sensitiveKeySubstrings {
		if strings.Contains(folded, substring) {
			return true
		}
	}
	return false
}

// redact returns v with the value of every sensitive key replaced by redactedValue,
// recursing through objects and arrays. A sensitive value is replaced whole, without
// recursing into it, so an object-valued secret leaves nothing behind. The top-level
// value is depth 1; a container nested deeper than maxLoggedDepth returns an error and
// the caller logs a placeholder instead of the body.
func redact(v any, depth int) (any, error) {
	switch value := v.(type) {
	case map[string]any:
		if depth > maxLoggedDepth {
			return nil, errs.Errorf("nested deeper than %d levels", maxLoggedDepth)
		}
		for key, element := range value {
			if isSensitiveKey(key) {
				value[key] = redactedValue
				continue
			}
			redacted, err := redact(element, depth+1)
			if err != nil {
				return nil, err
			}
			value[key] = redacted
		}
		return value, nil
	case []any:
		if depth > maxLoggedDepth {
			return nil, errs.Errorf("nested deeper than %d levels", maxLoggedDepth)
		}
		for i, element := range value {
			redacted, err := redact(element, depth+1)
			if err != nil {
				return nil, err
			}
			value[i] = redacted
		}
		return value, nil
	}
	return v, nil
}

// capturedBody is what the middleware kept of one body for the log: at most
// maxLoggedBody+1 bytes of it, which is enough to know a body is too large to log
// without holding the rest in memory, and what is known of the whole (#426).
type capturedBody struct {
	head []byte
	// size is the whole body's length in bytes, or -1 when it is not known: a request
	// body larger than head that declared no Content-Length.
	size int64
	// err is the read error that ended the capture before the body did, if one did.
	err error
}

// wholeBody is a body captured in full.
func wholeBody(body []byte) capturedBody {
	return capturedBody{head: body, size: int64(len(body))}
}

// bodyForLog returns the text to log for one request or response body: the body
// pretty-printed with every credential replaced, or a one-line placeholder giving the
// byte count and the reason. No part of a body that could not be parsed, that is too
// large, that is nested too deeply, or whose read failed is ever returned.
func bodyForLog(body capturedBody) string {
	// A read that failed leaves a prefix, and a prefix can be valid JSON on its own:
	// {"a":1} followed by padding a limit cut off parses, and logging it would present
	// a cut body as the whole one (#426).
	if body.err != nil {
		return fmt.Sprintf("%d bytes read, not logged (unable to read the whole body: %v)", len(body.head), body.err)
	}

	size := fmt.Sprintf("%d bytes", body.size)
	if body.size < 0 {
		size = fmt.Sprintf("more than %d bytes", maxLoggedBody)
	}
	notLogged := func(reason any) string {
		return fmt.Sprintf("%s, not logged (%v)", size, reason)
	}

	if len(body.head) > maxLoggedBody {
		return notLogged(fmt.Sprintf("larger than %d bytes", maxLoggedBody))
	}

	decoder := json.NewDecoder(bytes.NewReader(body.head))
	// UseNumber keeps integers exact. Without it an int64 such as 9223372036854775807
	// round-trips through float64 and is logged as 9223372036854776000, which reads
	// like a real value and is not one (#145).
	decoder.UseNumber()

	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		return notLogged(err)
	}
	// A second Decode that ends in io.EOF is what proves the body was one complete
	// value and nothing else. Decoder.More cannot do this job: it answers "is there
	// another element in the container I am inside", so at the top level it reports
	// no-more-input for a stray ] or }, and {"a":1}] would be logged as though the
	// body were valid JSON. Requiring io.EOF accepts exactly what json.Indent accepts,
	// trailing whitespace included (#145).
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return notLogged("unexpected trailing content after the top-level value")
	}

	redacted, err := redact(parsed, 1)
	if err != nil {
		return notLogged(err)
	}

	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	// SetEscapeHTML(false) keeps the body readable. With the default on, every "&" in
	// a URL is rewritten as its backslash-u escape, u0026, and every "<" as u003c, so
	// a websiteUrl in the log stops matching the one the client sent (#145).
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(redacted); err != nil {
		return notLogged(err)
	}
	return strings.TrimRight(out.String(), "\n")
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	// body keeps at most maxLoggedBody+1 bytes of the response, and size counts all of
	// them. Nothing above that is ever logged, so a copy of a whole large response
	// would only hold memory for the length of the request (#426).
	body *bytes.Buffer
	size int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	if room := maxLoggedBody + 1 - rw.body.Len(); room > 0 {
		rw.body.Write(b[:min(n, room)])
	}
	rw.size += int64(n)
	return n, err
}

// captured is the response as the log sees it.
func (rw *responseWriter) captured() capturedBody {
	return capturedBody{head: rw.body.Bytes(), size: rw.size}
}

// replayedBody is the request body handed on to the handler: the prefix the middleware
// read, then whatever of the original it did not.
type replayedBody struct {
	io.Reader
	original io.Closer
}

func (b replayedBody) Close() error {
	return b.original.Close()
}

// errorReader answers every read with the error that ended the middleware's own read.
type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

// captureRequestBody reads at most maxLoggedBody+1 bytes of r's body, enough to know
// whether it can be logged, and puts back a body that reads that prefix followed by the
// unread remainder (#426).
//
// A read error is handed on rather than dropped: the replacement returns it where the
// prefix ends, so a body cut short by the request-body limit, or by a client that went
// away, reaches the handler as the failed read it is. Discarding it, as this function's
// io.ReadAll once did, handed the handler a truncated body as though it were whole.
func captureRequestBody(r *http.Request) capturedBody {
	if r.Body == nil {
		return capturedBody{}
	}

	head, err := io.ReadAll(io.LimitReader(r.Body, maxLoggedBody+1))

	var rest io.Reader = r.Body
	if err != nil {
		rest = errorReader{err: err}
	}
	r.Body = replayedBody{Reader: io.MultiReader(bytes.NewReader(head), rest), original: r.Body}

	size := int64(len(head))
	if len(head) > maxLoggedBody {
		// Only the declared length says how large the rest is. A chunked body declares
		// none, and bodyForLog then says it was larger than the cap and no more.
		size = -1
		if r.ContentLength > maxLoggedBody {
			size = r.ContentLength
		}
	}
	return capturedBody{head: head, size: size, err: err}
}

// APIDebugMiddleware logs detailed information about API requests and responses when debug is enabled
func APIDebugMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !config.GetAuthServer().DebugAPIRequests {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			reqBody := captureRequestBody(r)

			// Wrap the response writer to capture response
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				body:           &bytes.Buffer{},
			}

			// Process the request
			next.ServeHTTP(rw, r)

			duration := time.Since(start)

			// Log the request and response. The target goes through the same
			// redaction the HTTP request log uses: r.URL.String() carries the query
			// string verbatim, which is the same defect under a second flag, and
			// these routes carry a user search string in `query` (#159).
			debugLog(r.Method, custom_middleware.RequestTargetForLog(r.URL), reqBody, rw.statusCode, rw.captured(), duration, r)
		})
	}
}

func debugLog(method, url string, reqBody capturedBody, statusCode int, respBody capturedBody, duration time.Duration, r *http.Request) {
	// Sanitize auth header for logging. "None" stays as it is, so a request that
	// carried no credential is still distinguishable from one whose credential
	// was removed here.
	authHeader := "None"
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			authHeader = "Bearer " + redactedValue
		} else {
			authHeader = redactedValue + " (unknown type)"
		}
	}

	// One record for the whole exchange, in place of the six this used to write.
	// Six records meant a reader joined them by adjacency, which is wrong the
	// moment two requests are in flight, and it cost the log five copies of the
	// [DEBUG API] prefix to say what one message says (#320 decision 9).
	//
	// Both bodies go through bodyForLog, which is the only path from a body to the
	// log: there is no fallback that writes raw bytes, so a body that cannot be
	// parsed produces a placeholder rather than appearing in the clear (#145).
	// They are always present, empty when there was no body, so the record has one
	// shape and a bodyless request is still distinguishable from a refused one.
	//
	// method goes through FieldForLog because it is client-chosen and this
	// middleware is mounted ahead of authentication: a request line carrying a
	// 900000-byte method reaches here, and the request logger already bounds the
	// same value for the same reason (#159).
	slog.InfoContext(r.Context(), "api exchange",
		"method", logging.FieldForLog(method),
		"target", url,
		"authorization", authHeader,
		"status", statusCode,
		"duration", duration,
		"request_body", bodyAttrForLog(reqBody),
		"response_body", bodyAttrForLog(respBody))
}

// bodyAttrForLog is bodyForLog with the no-body case answered as an empty string.
//
// json.Decoder reports io.EOF for zero bytes, so bodyForLog on an absent body
// returns "0 bytes, not logged (EOF)", which reads like a body that was there and
// could not be shown. The attribute is always written, so this is what keeps a
// bodyless request distinguishable from a refused body (#320).
func bodyAttrForLog(body capturedBody) string {
	if len(body.head) == 0 && body.err == nil {
		return ""
	}
	return bodyForLog(body)
}
