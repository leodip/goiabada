package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/requestid"
)

// pageLanguageCeremonies is what the page-language middleware reads of the sign-in a page belongs
// to: its user, once it has verified the password or adopted a session.
type pageLanguageCeremonies interface {
	SignInUserId(r *http.Request) int64
}

// pageLanguageDatabase is what the page-language middleware reads: the browser's signed-in session,
// and the user whose page language it applies.
type pageLanguageDatabase interface {
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// PageLanguage draws a page for a known user in the page language they chose, over the ui_locales
// and Accept-Language the locale middleware resolved, and over the ui_locales an authorize or
// sign-out handler applies afterwards (i18n.WithPageLanguage, #631 decision 4). The known user is
// the user of the sign-in the page belongs to once it has verified the password or adopted a
// session, else the user of the browser's signed-in session (decision 5). A page with neither, and
// a user on Automatic, keep the language the request resolved (decision 6).
//
// The choice is read from the user's row on every request, and nothing is copied into the browser
// session or the sign-in's stored state, so a change saved in the console shows on the next page.
// The address typed on the sign-in page never selects a language: the sign-in knows no user until
// the password is verified, which would otherwise disclose an account's language to anyone typing
// its address. The reset page, whose user the link names, applies that user's language itself.
//
// It is mounted on the page branch alone, beneath the session identifier and locale middleware:
// the Account and admin APIs answer in the language their request asks for. A failure to read the
// session or the user answers 500 in text/plain, as the session identifier middleware does on that
// branch.
func PageLanguage(ceremonies pageLanguageCeremonies, database pageLanguageDatabase) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			userId, err := knownUserId(r, ceremonies, database)
			if err == nil && userId != 0 {
				var user *record.User
				user, err = database.GetUserById(ctx, nil, userId)
				if err != nil {
					err = errs.Wrap(err, "unable to get the user")
				} else if user != nil {
					ctx = i18n.WithPageLanguage(ctx, user.PageLanguage)
				}
			}
			if err != nil {
				slog.ErrorContext(ctx, "unable to read the page language", "error", err)
				http.Error(w, fmt.Sprintf("fatal failure in page language middleware. For additional information, refer to the server logs. Request Id: %v",
					requestid.FromContext(ctx)), http.StatusInternalServerError)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// knownUserId is the user a page is drawn for: the sign-in's, else the signed-in session's, else
// zero. The sign-in's wins when the two differ, being the person signing in now.
func knownUserId(r *http.Request, ceremonies pageLanguageCeremonies, database pageLanguageDatabase) (int64, error) {
	if userId := ceremonies.SignInUserId(r); userId != 0 {
		return userId, nil
	}
	sessionIdentifier, ok := reqctx.SessionIdentifierFrom(r.Context())
	if !ok {
		return 0, nil
	}
	userSession, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
	if err != nil {
		return 0, errs.Wrap(err, "unable to get the user session")
	}
	if userSession == nil {
		return 0, nil
	}
	return userSession.UserId, nil
}
