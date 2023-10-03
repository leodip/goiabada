package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/sessionstore"
)

func MiddlewareJwt(next http.Handler, database *data.Database, sessionStore *sessionstore.MySQLStore, tokenValidator tokenValidator) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		sess, err := sessionStore.Get(r, common.SessionName)
		if err != nil {
			http.Error(w, fmt.Sprintf("unable to get the session in JwtMiddleware: %v", err.Error()), http.StatusInternalServerError)
			return
		}

		if sess.Values[common.SessionKeyJwt] != nil {
			jsonStr := sess.Values[common.SessionKeyJwt].(string)
			var tokenResponse dtos.TokenResponse
			if err := json.Unmarshal([]byte(jsonStr), &tokenResponse); err != nil {
				http.Error(w, fmt.Sprintf("unable to unmarhsall token response: %v", err.Error()), http.StatusInternalServerError)
				return
			}

			jwtInfo, err := tokenValidator.ValidateJwtSignature(r.Context(), &tokenResponse)
			if err == nil {
				ctx = context.WithValue(ctx, common.ContextKeyJwtInfo, *jwtInfo)
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
