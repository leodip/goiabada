package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/encryption"
	core_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// unusedRenderer satisfies the ErrorRenderer the limiter's constructor takes. The API reject
// class writes JSON and never renders, so a call here is a wiring defect rather than an
// outcome to assert on.
type unusedRenderer struct{ t *testing.T }

func (u unusedRenderer) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string,
	templateName string, data map[string]interface{}) error {

	u.t.Errorf("the API reject class rendered %s instead of writing JSON", templateName)
	return nil
}

// verificationEnv is one handler wired to its limiter the way routes.go wires them, plus the
// user row the database hands back. The row is shared rather than rebuilt per request
// because the handler mutates it on success, exactly as the real row is mutated: a case
// driving repeated verifications resets it, which in production is a fresh code each time.
type verificationEnv struct {
	handler  http.Handler
	database *mocks_data.Database
	user     *models.User
}

const (
	verificationSubject = "33333333-3333-3333-3333-333333333333"
	verificationCode    = "ABCD1234"
)

// newVerificationEnv builds the handler behind a live, enabled RateLimiterMiddleware.
//
// Through the middleware rather than called directly, and that is the point of this seam:
// the reservation the handler converts is placed by the limiter and lives in the request
// context, so a handler invoked on a bare request has nothing to convert and
// RecordCredentialFailure is a no-op. A case written that way passes while proving nothing
// (#219).
func newVerificationEnv(t *testing.T) *verificationEnv {
	t.Helper()

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	encrypted, err := encryption.EncryptData(verificationCode)
	require.NoError(t, err)

	user := &models.User{
		Id:                             7,
		Enabled:                        true,
		Email:                          "someone@example.com",
		EmailVerificationCodeEncrypted: encrypted,
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	database.On("GetUserBySubject", (*sql.Tx)(nil), verificationSubject).Return(user, nil).Maybe()
	database.On("UpdateUser", (*sql.Tx)(nil), user).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, mock.Anything).Return().Maybe()

	rateLimiter := core_middleware.NewRateLimiterMiddleware(nil, unusedRenderer{t}, nil, true)
	handler := HandleAPIAccountEmailVerificationPost(database, auditLogger, rateLimiter)

	return &verificationEnv{
		handler:  rateLimiter.LimitEmailVerification(handler),
		database: database,
		user:     user,
	}
}

// reset puts the row back to "a code was sent and is still pending", which the handler
// clears on a successful verification.
func (e *verificationEnv) reset(t *testing.T) {
	t.Helper()
	encrypted, err := encryption.EncryptData(verificationCode)
	require.NoError(t, err)
	e.user.EmailVerified = false
	e.user.EmailVerificationCodeEncrypted = encrypted
	e.user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
}

// post submits one verification attempt and reports the status.
func (e *verificationEnv) post(t *testing.T, submitted string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(api.VerifyAccountEmailRequest{VerificationCode: submitted})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5000"
	// The handler reads SMTPEnabled straight off the context and panics on the type
	// assertion without it, and MiddlewareSettings puts it there in production.
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{SMTPEnabled: true})
	req = setTokenContextWithClaims(req.WithContext(ctx),
		map[string]interface{}{"sub": verificationSubject})

	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// TestHandleAPIAccountEmailVerificationPost_SpendsTheLimiterBudgetOnFailuresOnly is seam 2
// for the email verification check. The budget itself is pinned at seam 1 in core/middleware;
// what is new here is the wiring, that a wrong code reaches the counter at all and that a
// right one does not.
func TestHandleAPIAccountEmailVerificationPost_SpendsTheLimiterBudgetOnFailuresOnly(t *testing.T) {
	const budget = 5 // failures per 15 minutes per token subject

	t.Run("wrong codes fill the budget and the next attempt is refused", func(t *testing.T) {
		env := newVerificationEnv(t)
		for i := 0; i < budget; i++ {
			rr := env.post(t, "ZZZZ9999")
			assert.Equal(t, http.StatusBadRequest, rr.Code, "attempt %d should reach the handler", i+1)
		}

		rr := env.post(t, "ZZZZ9999")
		assert.Equal(t, http.StatusTooManyRequests, rr.Code,
			"attempt %d should be refused by the limiter", budget+1)

		var body api.ErrorResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		assert.Equal(t, "TOO_MANY_REQUESTS", body.ErrorCode)

		// The refused request never reached the handler, so it never looked the account
		// up: 5 lookups for 6 attempts.
		env.database.AssertNumberOfCalls(t, "GetUserBySubject", budget)
	})

	t.Run("a correct code spends nothing", func(t *testing.T) {
		env := newVerificationEnv(t)
		// Well past the budget. A tier that counted every request would refuse the sixth,
		// which is a user locked out of verifying their own address by verifying it.
		for i := 0; i < budget*2; i++ {
			env.reset(t)
			assert.Equal(t, http.StatusOK, env.post(t, verificationCode).Code,
				"verification %d should succeed", i+1)
		}
		// And the whole budget is still there.
		env.reset(t)
		for i := 0; i < budget; i++ {
			assert.Equal(t, http.StatusBadRequest, env.post(t, "ZZZZ9999").Code,
				"failure %d should still reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, env.post(t, "ZZZZ9999").Code)
	})
}

// TestHandleAPIAccountEmailVerificationPost_CodeComparison pins what the move from
// strings.EqualFold to subtle.ConstantTimeCompare kept and what it narrowed.
//
// Kept: a code submitted in the wrong case still verifies, which the single-case alphabet
// relies on. Narrowed: an empty submission no longer verifies against a stored code that
// failed to decrypt, which EqualFold("", "") accepted (#219).
func TestHandleAPIAccountEmailVerificationPost_CodeComparison(t *testing.T) {
	t.Run("a lowercase submission still verifies", func(t *testing.T) {
		env := newVerificationEnv(t)
		rr := env.post(t, strings.ToLower(verificationCode))
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, env.user.EmailVerified, "the address should have been verified")
	})

	t.Run("surrounding whitespace still verifies", func(t *testing.T) {
		env := newVerificationEnv(t)
		assert.Equal(t, http.StatusOK, env.post(t, "  "+verificationCode+"\t").Code)
	})

	t.Run("an empty submission is refused when the stored code cannot be decrypted", func(t *testing.T) {
		env := newVerificationEnv(t)
		// A ciphertext this process cannot read, with a code issued a moment ago: the
		// shape a data-key rotation leaves behind. The stored code decrypts to "", and an
		// empty submission compared with EqualFold matched it, so the two checks behind
		// the comparison were the only thing left refusing the request, and both pass here.
		env.user.EmailVerificationCodeEncrypted = []byte("not a ciphertext this key can read")
		env.user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

		rr := env.post(t, "")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.False(t, env.user.EmailVerified, "an empty code must never verify an address")
	})

	t.Run("an empty submission is refused against a readable stored code", func(t *testing.T) {
		env := newVerificationEnv(t)
		assert.Equal(t, http.StatusBadRequest, env.post(t, "").Code)
		assert.False(t, env.user.EmailVerified)
	})
}
