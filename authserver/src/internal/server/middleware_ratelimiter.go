package server

import (
	"net/http"
	"time"

	"github.com/go-chi/httprate"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/lib"
)

func MiddlewareRateLimiter(sessionStore sessions.Store, maxRequests int, windowSizeInSeconds int) func(next http.Handler) http.Handler {
	return httprate.Limit(
		maxRequests, // max requests
		time.Duration(windowSizeInSeconds)*time.Second, // per window (seconds)
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			sess, err := sessionStore.Get(r, common.SessionName)
			if err == nil {
				// if the user has a session identifier, use that as the key
				if sess.Values[common.SessionKeySessionIdentifier] != nil {
					sessionIdentifier := sess.Values[common.SessionKeySessionIdentifier].(string)
					return sessionIdentifier, nil
				}

				// if the user does not have a session identifier, but has an auth context,
				// use the auth context as the key
				if sess.Values[common.SessionKeyAuthContext] != nil {
					authContextJson := sess.Values[common.SessionKeyAuthContext].(string)
					authContextHash, err := lib.HashString(authContextJson)
					if err == nil {
						return authContextHash, nil
					}
				}
			}

			// default to the IP address
			return httprate.KeyByIP(r)
		}),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "HTTP 429 - Too many requests. You've reached the maximum number of requests allowed. Please wait a moment before trying again.", http.StatusTooManyRequests)
		}),
	)
}
