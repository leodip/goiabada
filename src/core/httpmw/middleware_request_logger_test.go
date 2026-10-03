package httpmw

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
)

// jwtLike is the three-segment shape an id_token_hint arrives in, short enough to
// keep the table readable. It is the sentinel every leak assertion looks for.
const jwtLike = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlBST0JFIn0." +
	"eyJzdWIiOiJVU0VSLVNVQiIsInNpZCI6IlNFU1NJT04tSUQifQ.U0lHTkFUVVJF"

// -----------------------------------------------------------------------------
// RequestLogger
//
// The target's rendering, its redaction and its bounds, is logging's and is tested
// beside RequestTargetForLog in core/logging. These own what the middleware adds.
// -----------------------------------------------------------------------------

// okHandler answers 200 with no body and records that it ran.
func okHandler(ran *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
	})
}

// records counts the log records in the captured output.
func records(capture *logtest.SlogCapture) int {
	return strings.Count(capture.Text(), `msg="http request"`)
}

func TestRequestLogger_DisabledWritesNothingAndStillServes(t *testing.T) {
	buf := logtest.CaptureSlog(t)
	ran := false

	handler := RequestLogger(false)(okHandler(&ran))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=c", nil))

	assert.Equal(t, 0, records(buf), "nothing is logged when the flag is off")
	// The other half: a pass-through that dropped the request would also log
	// nothing.
	assert.True(t, ran, "the handler must still run")
}

func TestRequestLogger_SkipList(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantLines int
	}{
		{name: "/health is skipped", path: "/health", wantLines: 0},
		{name: "/healthz is not, one character away", path: "/healthz", wantLines: 1},
		{name: "/static/ is skipped", path: "/static/app.css", wantLines: 0},
		{name: "/static with no trailing slash is not", path: "/static", wantLines: 1},
		{name: "/favicon.ico is skipped", path: "/favicon.ico", wantLines: 0},
		{name: "/favicon.ico.map is not", path: "/favicon.ico.map", wantLines: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := logtest.CaptureSlog(t)
			ran := false

			handler := RequestLogger(true)(okHandler(&ran))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, test.path, nil))

			assert.Equal(t, test.wantLines, records(buf))
			// A skip list tested only by its members passes when it skips everything,
			// and a skipped path must still be served.
			assert.True(t, ran, "the handler must run either way")
		})
	}
}

func TestRequestLogger_LogsExactlyOneRecord(t *testing.T) {
	buf := logtest.CaptureSlog(t)
	ran := false

	handler := RequestLogger(true)(okHandler(&ran))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=c", nil))

	assert.Equal(t, 1, records(buf))
	// Quoted by slog's text handler, which is a property of the handler rather than
	// of the target: the value itself is printable ASCII by construction.
	assert.Contains(t, buf.Text(), `target="/auth/authorize?client_id=c"`)
}

// The goal sentence of the change: the reported defect, at both endpoints.
func TestRequestLogger_DoesNotLogTheIdTokenHint(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{
			name: "authorize",
			target: "/auth/authorize?client_id=admin-console&response_type=code&scope=openid+profile" +
				"&redirect_uri=" + url.QueryEscape("https://app.example/cb") +
				"&id_token_hint=" + jwtLike,
		},
		{
			name: "logout",
			target: "/auth/logout?id_token_hint=" + jwtLike +
				"&post_logout_redirect_uri=" + url.QueryEscape("https://app.example/done"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := logtest.CaptureSlog(t)
			ran := false

			handler := RequestLogger(true)(okHandler(&ran))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, test.target, nil))

			assert.Equal(t, 1, records(buf))
			assert.NotContains(t, buf.Text(), jwtLike, "the hint must not reach the log")
			assert.Contains(t, buf.Text(), "id_token_hint=[redacted]")
		})
	}
}

func TestRequestLogger_RecordsStatusAndBytes(t *testing.T) {
	buf := logtest.CaptureSlog(t)

	handler := RequestLogger(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope!"))
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

	assert.Contains(t, buf.Text(), "status=403")
	assert.Contains(t, buf.Text(), "bytes=5")
}

// The two halves of #203 at this seam, which is where the ordering rule actually lives: the
// middleware reports whatever the writer beneath it wrote, so it says 500 for a panic only when
// Recoverer is beneath it. Both servers mount it that way and their own cases pin that; this owns
// the property those cases depend on.
func TestRequestLogger_RecordsThePanicStatusFromBeneath(t *testing.T) {
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a handler panicked")
	})

	t.Run("Recoverer beneath the logger", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)

		handler := RequestLogger(true)(chimiddleware.Recoverer(panicking))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Contains(t, buf.Text(), "status=500")
	})

	// The order this change replaced, kept as a case because it is the whole reason the change
	// exists: Recoverer's WriteHeader goes to the writer above the logger's wrapper, so the
	// wrapper is asked for a status nobody ever set through it.
	t.Run("Recoverer above the logger", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)

		handler := chimiddleware.Recoverer(RequestLogger(true)(panicking))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

		assert.Equal(t, http.StatusInternalServerError, recorder.Code,
			"the client is answered 500 either way; only the record differs")
		assert.Contains(t, buf.Text(), "status=0")
	})
}

func TestRequestLogger_RequestId(t *testing.T) {
	t.Run("present when chi's RequestID ran ahead of the logger", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)
		ran := false

		handler := chimiddleware.RequestID(RequestLogger(true)(okHandler(&ran)))
		request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
		request.Header.Set(chimiddleware.RequestIDHeader, "REQUEST-ID-SENTINEL")
		handler.ServeHTTP(httptest.NewRecorder(), request)

		assert.Contains(t, buf.Text(), "request_id=REQUEST-ID-SENTINEL")
	})

	t.Run("the attribute is absent altogether when it did not", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)
		ran := false

		handler := RequestLogger(true)(okHandler(&ran))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

		assert.Equal(t, 1, records(buf))
		assert.NotContains(t, buf.Text(), "request_id",
			"an empty request id is omitted rather than logged as empty")
	})
}

// The three client-chosen scalar attributes. Each can arrive at 900000 bytes: the
// method and X-Request-Id straight from the request, and r.RemoteAddr because
// RealIP copies an X-Forwarded-For entry into it.
func TestRequestLogger_ClipsTheClientChosenFields(t *testing.T) {
	const huge = 900000

	tests := []struct {
		name       string
		setup      func(r *http.Request)
		wantMarker string
	}{
		{
			name:       "a 900000-byte method",
			setup:      func(r *http.Request) { r.Method = strings.Repeat("M", huge) },
			wantMarker: "[truncated, 128 of 900000 bytes]",
		},
		{
			name: "a 900000-byte X-Request-Id",
			setup: func(r *http.Request) {
				r.Header.Set(chimiddleware.RequestIDHeader, strings.Repeat("R", huge))
			},
			wantMarker: "[truncated, 128 of 900000 bytes]",
		},
		{
			name:       "a 900000-byte r.RemoteAddr",
			setup:      func(r *http.Request) { r.RemoteAddr = strings.Repeat("I", huge) },
			wantMarker: "[truncated, 128 of 900000 bytes]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := logtest.CaptureSlog(t)
			ran := false

			handler := chimiddleware.RequestID(RequestLogger(true)(okHandler(&ran)))
			request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
			test.setup(request)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			assert.Equal(t, 1, records(buf))
			assert.Contains(t, buf.Text(), test.wantMarker)
			assert.Less(t, len(buf.Text()), 5*1024,
				"one oversized header must not become one oversized log line")
		})
	}
}

func TestRequestLogger_TheClipIsLossy(t *testing.T) {
	// Pinned rather than left to be discovered: two request ids of equal length
	// that differ only after byte 128 log identically, truncation marker included.
	// This is the accepted cost of the 128-byte bound. Nothing reads as a complete
	// identifier that is not, because every clipped value carries its own marker
	// giving the true length, so the failure is an operator seeing two records they
	// cannot tell apart rather than one they wrongly believe they can.
	//
	// The bound itself is a deferred decision in the run's closing record, section
	// 8: preserve long correlation ids in full, keep the clip, or append a digest.
	// If that answer changes, this row changes with it.
	first := strings.Repeat("p", 128) + "AAAAAAAA"
	second := strings.Repeat("p", 128) + "BBBBBBBB"
	assert.Equal(t, len(first), len(second), "the two must be the same length to collide")

	logged := make([]string, 0, 2)
	for _, requestId := range []string{first, second} {
		buf := logtest.CaptureSlog(t)
		ran := false

		handler := chimiddleware.RequestID(RequestLogger(true)(okHandler(&ran)))
		request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
		request.Header.Set(chimiddleware.RequestIDHeader, requestId)
		handler.ServeHTTP(httptest.NewRecorder(), request)

		// request_id is the last attribute on the line now, because the installed handler
		// appends it to the record rather than the call site naming it first (#320
		// decision 2). So the value runs to the end of the line.
		line := strings.TrimRight(buf.Text(), "\n")
		start := strings.Index(line, "request_id=")
		assert.NotEqual(t, -1, start)
		logged = append(logged, line[start:])
	}

	assert.Equal(t, logged[0], logged[1], "the two distinct ids render to one logged value")
	assert.Contains(t, logged[0], "[truncated, 128 of 136 bytes]",
		"and the marker says so, so neither record claims to be complete")
}

func TestRequestLogger_EscapesTheClientChosenFields(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(r *http.Request)
		wantIn   string
		wantOut  string
		rawIsBad string
	}{
		{
			name: "U+2028 in the request id",
			setup: func(r *http.Request) {
				r.Header.Set(chimiddleware.RequestIDHeader, "before\u2028after")
			},
			wantIn:   "before%E2%80%A8after",
			rawIsBad: "\u2028",
		},
		{
			name:     "U+0085 in the IP",
			setup:    func(r *http.Request) { r.RemoteAddr = "192.0.2.1\u0085injected" },
			wantIn:   "192.0.2.1%C2%85injected",
			rawIsBad: "\u0085",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := logtest.CaptureSlog(t)
			ran := false

			handler := chimiddleware.RequestID(RequestLogger(true)(okHandler(&ran)))
			request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
			test.setup(request)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			// Both halves. Asserting only that the escape is present would pass with
			// the raw rune sitting in the record beside it.
			assert.Contains(t, buf.Text(), test.wantIn)
			assert.NotContains(t, buf.Text(), test.rawIsBad, "the raw rune must be gone")
		})
	}
}

func TestRequestLogger_RendersTheTargetBeforeDownstreamRewritesIt(t *testing.T) {
	// The one attribute whose value depends on WHEN it is read. Both servers
	// register chi's StripSlashes immediately after this middleware, and it edits
	// r.URL.Path in place, so a logger that rendered the target on the way out
	// would record a path the client never sent. Every other assertion in this file
	// passes either way, which is what makes this case worth its own test rather
	// than a comment.
	buf := logtest.CaptureSlog(t)

	var seenByHandler string
	chain := RequestLogger(true)(
		chimiddleware.StripSlashes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenByHandler = r.URL.Path
			w.WriteHeader(http.StatusOK)
		})))

	chain.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/auth/authorize/?client_id=c", nil))

	assert.Equal(t, "/auth/authorize", seenByHandler, "StripSlashes really does rewrite the path")
	// Quoted because slog's text handler quotes any value holding an "="".
	assert.Contains(t, buf.Text(), `target="/auth/authorize/?client_id=c"`,
		"the log must carry the target that arrived, trailing slash and all")
}

func TestRequestLogger_LogsARequestThatPanics(t *testing.T) {
	// This is what pins the deferred write, which is otherwise invisible: chi's
	// logger produced a line for a panicking request and so must this one.
	buf := logtest.CaptureSlog(t)

	handler := RequestLogger(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("handler exploded")
	}))

	assert.Panics(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=c", nil))
	})

	assert.Equal(t, 1, records(buf), "the line must survive the panic")
	// status=0 because Recoverer, which is registered outside this middleware, has
	// not written anything yet when the deferred record runs. That is what chi
	// logged too, and it is #203 rather than this change.
	assert.Contains(t, buf.Text(), "status=0")
}
