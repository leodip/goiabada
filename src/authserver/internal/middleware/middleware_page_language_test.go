package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// signInUser is the sign-in a page belongs to, as the page-language middleware reads it: its user
// once it has verified the password or adopted a session, else zero.
type signInUser int64

func (u signInUser) SignInUserId(*http.Request) int64 { return int64(u) }

// When the page-language middleware cannot read the browser's session or the known user, it stops
// the page: 500 in text/plain naming the request, the cause in the log and not in the response,
// and the page itself never reached. The user is read through either identity source, the
// sign-in's and the browser session's.
func TestPageLanguage_ADatabaseFailureStopsThePage(t *testing.T) {
	cases := []struct {
		name   string
		signIn signInUser
		expect func(db *datamocks.Database, cause error)
	}{
		{"the session read fails", 0, func(db *datamocks.Database, cause error) {
			db.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "the-session").Return(nil, cause).Once()
		}},
		{"the sign-in's user read fails", 7, func(db *datamocks.Database, cause error) {
			db.On("GetUserById", mock.Anything, mock.Anything, int64(7)).Return(nil, cause).Once()
		}},
		{"the session's user read fails", 0, func(db *datamocks.Database, cause error) {
			db.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "the-session").
				Return(&record.UserSession{UserId: 7}, nil).Once()
			db.On("GetUserById", mock.Anything, mock.Anything, int64(7)).Return(nil, cause).Once()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			db := datamocks.NewDatabase(t)
			cause := errors.New("the database is unavailable")
			tc.expect(db, cause)

			req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
			req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), "the-session"))
			reached := false
			rr := httptest.NewRecorder()
			PageLanguage(tc.signIn, db)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				reached = true
			})).ServeHTTP(rr, req)

			assert.False(t, reached, "the page is not drawn")
			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			assert.Contains(t, rr.Body.String(), "fatal failure in page language middleware")
			assert.NotContains(t, rr.Body.String(), cause.Error(), "the cause stays out of the response")

			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelError, records[0].Level)
			assert.Equal(t, "unable to read the page language", records[0].Message)
			assert.Contains(t, fmt.Sprint(records[0].Attrs["error"]), cause.Error(), "the cause is logged")
		})
	}
}
