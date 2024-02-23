package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/data"
)

func MiddlewareSettings(database data.Database) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			settings, err := database.GetSettingsById(nil, 1)
			if err != nil {
				slog.Error(fmt.Sprintf("%+v\nrequest-id: %v", err, middleware.GetReqID(r.Context())))
				http.Error(w, fmt.Sprintf("fatal failure in GetSettings() middleware. For additional information, refer to the server logs. Request Id: %v", middleware.GetReqID(r.Context())), http.StatusInternalServerError)
			} else {
				ctx = context.WithValue(ctx, common.ContextKeySettings, settings)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		}
		return http.HandlerFunc(fn)
	}
}
