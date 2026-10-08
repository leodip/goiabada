package apihandlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every /api/v1/account/* route runs the bearer middleware first, which refuses a missing token
// with ACCESS_TOKEN_REQUIRED and an empty subject with INVALID_TOKEN, so no request a client can
// send reaches an account handler without both. A handler reached without them is a route mounted
// without its middleware: a wiring fault, answered as the API's 500 and logged as an error, rather
// than a request run as nobody or a 401 naming a code nothing else writes (#522 decision 4).
func TestAccountHandlers_ACallerWithoutATokenOrSubjectIsAWiringFault(t *testing.T) {
	handlers := map[string]func(t *testing.T) http.HandlerFunc{
		"HandleAccountAddressPut": func(t *testing.T) http.HandlerFunc {
			return HandleAccountAddressPut(datamocks.NewDatabase(t), nil, handlersmocks.NewAuditLogger(t))
		},
		"HandleAccountConsentsGet": func(t *testing.T) http.HandlerFunc {
			return HandleAccountConsentsGet(datamocks.NewDatabase(t))
		},
		"HandleAccountConsentDelete": func(t *testing.T) http.HandlerFunc {
			return HandleAccountConsentDelete(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t))
		},
		"HandleAccountEmailPut": func(t *testing.T) http.HandlerFunc {
			return HandleAccountEmailPut(nil, datamocks.NewDatabase(t), nil, nil, handlersmocks.NewAuditLogger(t), nil, nil)
		},
		"HandleAccountEmailVerificationSendPost": func(t *testing.T) http.HandlerFunc {
			return HandleAccountEmailVerificationSendPost(nil, datamocks.NewDatabase(t), nil,
				handlersmocks.NewAuditLogger(t), testDataCipher, "https://console.example")
		},
		"HandleAccountEmailVerificationPost": func(t *testing.T) http.HandlerFunc {
			return HandleAccountEmailVerificationPost(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), nil, testDataCipher)
		},
		"HandleAccountLogoutRequestPost": func(t *testing.T) http.HandlerFunc {
			return HandleAccountLogoutRequestPost(datamocks.NewDatabase(t), testDataCipher, testBaseURL)
		},
		"HandleAccountOTPEnrollmentGet": func(t *testing.T) http.HandlerFunc {
			return HandleAccountOTPEnrollmentGet(datamocks.NewDatabase(t), nil, testDataCipher)
		},
		"HandleAccountOTPPut": func(t *testing.T) http.HandlerFunc {
			return HandleAccountOTPPut(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), nil, testDataCipher)
		},
		"HandleAccountPasswordPut": func(t *testing.T) http.HandlerFunc {
			return HandleAccountPasswordPut(datamocks.NewDatabase(t), nil, handlersmocks.NewAuditLogger(t), nil)
		},
		"HandleAccountPhonePut": func(t *testing.T) http.HandlerFunc {
			return HandleAccountPhonePut(datamocks.NewDatabase(t), nil, handlersmocks.NewAuditLogger(t))
		},
		"HandleAccountProfileGet": func(t *testing.T) http.HandlerFunc {
			return HandleAccountProfileGet(datamocks.NewDatabase(t))
		},
		"HandleAccountProfilePut": func(t *testing.T) http.HandlerFunc {
			return HandleAccountProfilePut(datamocks.NewDatabase(t), nil, handlersmocks.NewAuditLogger(t))
		},
		"HandleAccountProfilePicturePost": func(t *testing.T) http.HandlerFunc {
			return HandleAccountProfilePicturePost(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), testBaseURL, testMaxUploadBytes)
		},
		"HandleAccountProfilePictureDelete": func(t *testing.T) http.HandlerFunc {
			return HandleAccountProfilePictureDelete(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t))
		},
		"HandleAccountProfilePictureGet": func(t *testing.T) http.HandlerFunc {
			return HandleAccountProfilePictureGet(datamocks.NewDatabase(t), testBaseURL)
		},
		"HandleAccountSessionsGet": func(t *testing.T) http.HandlerFunc {
			return HandleAccountSessionsGet(datamocks.NewDatabase(t))
		},
		"HandleAccountSessionDelete": func(t *testing.T) http.HandlerFunc {
			return HandleAccountSessionDelete(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t))
		},
	}
	// The account API is these eighteen handlers, one per route in routes.go's /api/v1/account group.
	require.Len(t, handlers, 18)

	callers := map[string]func(r *http.Request) *http.Request{
		"no validated token": func(r *http.Request) *http.Request { return r },
		"no sub claim": func(r *http.Request) *http.Request {
			return r.WithContext(reqctx.WithValidatedToken(r.Context(), oauth.JwtToken{Claims: map[string]interface{}{}}))
		},
		"an empty subject": func(r *http.Request) *http.Request {
			return setTokenContext(r, "")
		},
		"a blank subject": func(r *http.Request) *http.Request {
			return setTokenContext(r, "  \t")
		},
	}

	for name, newHandler := range handlers {
		for caller, withCaller := range callers {
			t.Run(name+"/"+caller, func(t *testing.T) {
				// The mocks hold no expectations, so a database read, a write or an audit record
				// fails the test: the handler stops before it acts as anyone.
				handler := newHandler(t)
				capture := logtest.CaptureSlog(t)

				req := withCaller(httptest.NewRequest(http.MethodPost, "/api/v1/account/x",
					strings.NewReader(`{}`)))
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				assertWiringFault(t, rr, capture)
			})
		}
	}
}

// assertWiringFault asserts the answer an account handler gives when it is reached without the
// validated token or subject its middleware guarantees: the API's 500, and one error record.
func assertWiringFault(t *testing.T, rr *httptest.ResponseRecorder, capture *logtest.SlogCapture) {
	t.Helper()
	assertJSONInternalServerError(t, rr)
	records := capture.Records()
	require.Len(t, records, 1, capture.Text())
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, "internal server error", records[0].Message)
	assert.NotEmpty(t, records[0].Attrs["error"])
}
