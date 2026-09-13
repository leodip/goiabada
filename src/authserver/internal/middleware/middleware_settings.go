package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
)

func MiddlewareSettings(database data.Database) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			settings, err := database.GetSettingsById(nil, 1)
			if err != nil {
				// Plain text, because this runs before any helper that could render a page:
				// the settings it is fetching are what the error page's layout reads. The
				// sentence is unchanged; the log line is decision 9's shape, with the stack
				// riding inside the error attribute rather than formatted into the message
				// (#279).
				requestId := middleware.GetReqID(r.Context())
				// No request_id attribute: the installed handler takes it off the context this
				// call passes it (#320 decision 2). requestId is still read for the body below,
				// which is what gives whoever hit this something to quote to an operator.
				slog.ErrorContext(r.Context(), "unable to load the settings", "error", err)
				http.Error(w, fmt.Sprintf("fatal failure in GetSettings() middleware. For additional information, refer to the server logs. Request Id: %v", requestId), http.StatusInternalServerError)
				return
			}
			ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
