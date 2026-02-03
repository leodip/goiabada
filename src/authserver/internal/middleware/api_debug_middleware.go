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

	"github.com/leodip/goiabada/core/config"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
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

			// Read and store the request body
			var reqBody []byte
			if r.Body != nil {
				reqBody, _ = io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
			}

			// Wrap the response writer to capture response
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				body:           &bytes.Buffer{},
			}

			// Process the request
			next.ServeHTTP(rw, r)

			duration := time.Since(start)

			// Log the request and response
			debugLog(r.Method, r.URL.String(), reqBody, rw.statusCode, rw.body.Bytes(), duration, r)
		})
	}
}

func debugLog(method, url string, reqBody []byte, statusCode int, respBody []byte, duration time.Duration, r *http.Request) {
	// Sanitize auth header for logging
	authHeader := "None"
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			authHeader = "Bearer ***"
		} else {
			authHeader = "*** (unknown type)"
		}
	}

	// Log request
	slog.Info(fmt.Sprintf("[DEBUG API] → %s %s", method, url))
	slog.Info(fmt.Sprintf("[DEBUG API]   Headers: Authorization: %s", authHeader))

	// Log request body (if applicable)
	if len(reqBody) > 0 {
		var prettyReq bytes.Buffer
		if json.Indent(&prettyReq, reqBody, "", "  ") == nil {
			slog.Info(fmt.Sprintf("[DEBUG API]   Request Body:\n%s", prettyReq.String()))
		}
	}

	// Log response
	status := http.StatusText(statusCode)
	slog.Info(fmt.Sprintf("[DEBUG API] ← %d %s (%s)", statusCode, status, duration))

	// Log response body
	if len(respBody) > 0 {
		var prettyResp bytes.Buffer
		if json.Indent(&prettyResp, respBody, "", "  ") == nil {
			slog.Info(fmt.Sprintf("[DEBUG API]   Response Body:\n%s", prettyResp.String()))
		} else {
			slog.Info(fmt.Sprintf("[DEBUG API]   Response Body: %s", string(respBody)))
		}
	}

	slog.Info("[DEBUG API]") // Empty line for separation
}
