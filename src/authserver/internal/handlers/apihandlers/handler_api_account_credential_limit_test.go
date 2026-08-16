package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	core_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// unlimitedCredentials stands in for the limiter wherever a case invokes one of these
// handlers directly instead of through its middleware. Marking a failure means converting a
// reservation the middleware placed on the request, and a bare httptest request carries
// none, so the real middleware would be a no-op at those call sites too. Naming it says so
// rather than leaving a reader to work it out; the wiring itself is what this file pins.
type unlimitedCredentials struct{}

func (unlimitedCredentials) RecordCredentialFailure(*http.Request) {}

// credentialEnv is the two handlers that verify the account password, each behind the one
// LimitAccountPassword middleware that routes.go wraps them both in. One middleware instance
// is what makes the budget shared, and driving the handlers through it is the point of this
// seam: the reservation lives in the request context, so a handler called directly has
// nothing to convert and every assertion below would pass while proving nothing (#219).
type credentialEnv struct {
	password http.Handler
	otp      http.Handler
	database *mocks_data.Database
}

const (
	credentialSubject  = "66666666-6666-6666-6666-666666666666"
	credentialPassword = "C0rrect!Pass"
)

func newCredentialEnv(t *testing.T) *credentialEnv {
	t.Helper()

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	hash, err := hashutil.HashPassword(credentialPassword)
	require.NoError(t, err)
	// OTPEnabled false, so the OTP route's enable branch is the one reached past the password
	// check. Nothing here gets as far as a write.
	user := &models.User{Id: 91, Enabled: true, PasswordHash: hash, OTPEnabled: false}

	database.On("GetUserBySubject", (*sql.Tx)(nil), credentialSubject).Return(user, nil).Maybe()
	auditLogger.On("Log", mock.Anything, mock.Anything).Return().Maybe()

	rateLimiter := core_middleware.NewRateLimiterMiddleware(nil, unusedRenderer{t}, nil, true)

	return &credentialEnv{
		password: rateLimiter.LimitAccountPassword(
			HandleAPIAccountPasswordPut(database, validators.NewPasswordValidator(), auditLogger, rateLimiter)),
		otp: rateLimiter.LimitAccountPassword(
			HandleAPIAccountOTPPut(database, auditLogger, rateLimiter)),
		database: database,
	}
}

// putPassword submits one password change and reports the response.
func (e *credentialEnv) putPassword(t *testing.T, current, next string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"currentPassword": current, "newPassword": next})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5000"
	// The password validator reads the policy straight off the context and panics on the type
	// assertion without it, and MiddlewareSettings puts it there in production.
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{PasswordPolicy: enums.PasswordPolicyLow})
	req = setTokenContextWithClaims(req.WithContext(ctx),
		map[string]interface{}{"sub": credentialSubject})

	rr := httptest.NewRecorder()
	e.password.ServeHTTP(rr, req)
	return rr
}

// putOTP submits one OTP enable attempt and reports the response. The code is what the enable
// branch checks after the password, and it is deliberately outside the budget.
func (e *credentialEnv) putOTP(t *testing.T, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"enabled":   true,
		"password":  password,
		"otpCode":   code,
		"secretKey": otpTestSecret,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/otp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5000"
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": credentialSubject})

	rr := httptest.NewRecorder()
	e.otp.ServeHTTP(rr, req)
	return rr
}

// TestAccountCredentialBudget_SharedAcrossPasswordAndOTP is seam 2 for decision 10's one
// bucket. The budget itself is pinned at seam 1 in core/middleware; what is new here is that
// both handlers reach that one bucket, and that only the password check does.
func TestAccountCredentialBudget_SharedAcrossPasswordAndOTP(t *testing.T) {
	const budget = 5 // password failures per 15 minutes per token subject

	t.Run("five failures split across the two routes refuse the sixth", func(t *testing.T) {
		env := newCredentialEnv(t)

		// Alternating deliberately. Two buckets would give each route its own five, so this
		// run would never be refused at all: that is the ten guesses by alternation the one
		// bucket exists to deny.
		for i := 0; i < budget; i++ {
			var rr *httptest.ResponseRecorder
			if i%2 == 0 {
				rr = env.putPassword(t, "wrong-password", "N3wP4ss!word")
			} else {
				rr = env.putOTP(t, "wrong-password", wrongButWellFormedCode(t))
			}
			require.Equal(t, http.StatusBadRequest, rr.Code, "failure %d should reach the handler", i+1)
			assert.Equal(t, "AUTHENTICATION_FAILED", errorCodeOf(t, rr))
		}

		rr := env.putOTP(t, "wrong-password", wrongButWellFormedCode(t))
		assert.Equal(t, http.StatusTooManyRequests, rr.Code,
			"attempt %d, at the OTP route, should be refused", budget+1)
		assert.Equal(t, "TOO_MANY_REQUESTS", errorCodeOf(t, rr))

		// And the password route is refused by the same exhausted bucket.
		rr = env.putPassword(t, "wrong-password", "N3wP4ss!word")
		assert.Equal(t, http.StatusTooManyRequests, rr.Code,
			"the password route should be refused by the bucket the OTP route helped exhaust")

		// The two refused requests never reached a handler, so they never looked the account
		// up: 5 lookups for 7 attempts.
		env.database.AssertNumberOfCalls(t, "GetUserBySubject", budget)
	})

	t.Run("a correct password spends nothing, on either route", func(t *testing.T) {
		env := newCredentialEnv(t)

		// Well past the budget, and every one of them refused for a reason that is not the
		// password: a wrong OTP code at the enable branch, which decision 10 leaves unbounded
		// because it is checked against the secret the caller supplied in the same request,
		// and a new password the policy rejects. A tier that counted every request, or a
		// handler that charged either of these branches, would refuse the sixth.
		for i := 0; i < budget*2; i++ {
			rr := env.putOTP(t, credentialPassword, wrongButWellFormedCode(t))
			require.Equal(t, http.StatusBadRequest, rr.Code, "OTP attempt %d", i+1)
			assert.Equal(t, "INVALID_OTP_CODE", errorCodeOf(t, rr))
		}
		for i := 0; i < budget*2; i++ {
			rr := env.putPassword(t, credentialPassword, "short")
			require.Equal(t, http.StatusBadRequest, rr.Code, "password attempt %d", i+1)
			assert.NotEqual(t, "AUTHENTICATION_FAILED", errorCodeOf(t, rr),
				"the current password was correct, so this must be the new password being refused")
		}

		// And the whole budget is still there.
		for i := 0; i < budget; i++ {
			require.Equal(t, http.StatusBadRequest,
				env.putPassword(t, "wrong-password", "N3wP4ss!word").Code,
				"failure %d should still reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests,
			env.putPassword(t, "wrong-password", "N3wP4ss!word").Code)
	})
}
