package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// changeBeforeDeletion runs change, a real committed credential change, after the deletion handler
// has checked the credentials and before its deletion transaction begins: the second transaction it
// opens, the first being the early last-administrator check.
type changeBeforeDeletion struct {
	data.Database
	transactions int
	change       func()
}

func (d *changeBeforeDeletion) RunInTransaction(ctx context.Context, body func(*sql.Tx) error) error {
	d.transactions++
	if d.transactions == 2 {
		d.change()
	}
	return d.Database.RunInTransaction(ctx, body)
}

type uncountedFailures struct{}

func (uncountedFailures) RecordCredentialFailure(*http.Request) {}

// A deletion whose password, or whose authenticator, was replaced and committed between the
// request's checks and its deletion transaction is refused, and the account is kept (#783 decision
// 1): the row read under the deletion's lock no longer holds the credentials the request carried.
// An isolated database, so the early check counts only this test's holders of manage.
func TestAccountDeletion_RefusesCredentialsReplacedBeforeTheDeletion(t *testing.T) {
	const password = "D3letion-test-password!"
	for _, tc := range []struct {
		name     string
		wantCode string
	}{
		{"password replaced", "AUTHENTICATION_FAILED"},
		{"authenticator replaced", "INVALID_OTP_CODE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := migratedIsolatedDB(t)
			resource := &record.Resource{ResourceIdentifier: builtin.AuthServerResourceIdentifier}
			require.NoError(t, h.DB.CreateResource(ctx, nil, resource))
			manage := &record.Permission{ResourceId: resource.Id, PermissionIdentifier: builtin.ManagePermissionIdentifier}
			require.NoError(t, h.DB.CreatePermission(ctx, nil, manage))
			user := newHolder(t, h.DB, true)
			hash, err := passwordhash.Hash(password)
			require.NoError(t, err)
			require.NoError(t, h.DB.SetUserPasswordHash(ctx, nil, user.Id, hash))
			user, err = h.DB.GetUserById(ctx, nil, user.Id)
			require.NoError(t, err)

			body := map[string]string{"password": password}
			if tc.name == "authenticator replaced" {
				secret := otptest.NewSecret(t)
				_, _, _, established, establishErr := otpcredential.Establish(ctx, h.DB, dataCipher, user, secret)
				require.NoError(t, establishErr)
				require.True(t, established)
				body["otpCode"] = otptest.Code(t, secret, time.Now())
			}

			db := &changeBeforeDeletion{Database: h.DB, change: func() {
				if tc.name == "password replaced" {
					replacement, hashErr := passwordhash.Hash("A-new-current-password-123!")
					require.NoError(t, hashErr)
					require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
						if setErr := h.DB.SetUserPasswordHash(ctx, tx, user.Id, replacement); setErr != nil {
							return setErr
						}
						_, incrementErr := h.DB.IncrementUserAuthStateGeneration(ctx, tx, user.Id)
						return incrementErr
					}))
					return
				}
				current, readErr := h.DB.GetUserById(ctx, nil, user.Id)
				require.NoError(t, readErr)
				removed, removedOK, removeErr := otpcredential.Remove(ctx, h.DB, current)
				require.NoError(t, removeErr)
				require.True(t, removedOK)
				_, _, _, reenrolled, reenrollErr := otpcredential.Establish(ctx, h.DB, dataCipher, removed, otptest.NewSecret(t))
				require.NoError(t, reenrollErr)
				require.True(t, reenrolled)
			}}

			encoded, err := json.Marshal(body)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/account/deletion", bytes.NewReader(encoded))
			req.Header.Set("Content-Type", "application/json")
			reqCtx := reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, AccountDeletionEnabled: true})
			reqCtx = reqctx.WithValidatedToken(reqCtx, oauth.JwtToken{Claims: map[string]interface{}{
				"sub": user.Subject, "scope": "authserver:manage-account", "auth_time": float64(1),
			}})
			rr := httptest.NewRecorder()
			apihandlers.HandleAccountDeletionPost(db, &countingAuditLogger{}, uncountedFailures{}, dataCipher, noNotices{}).
				ServeHTTP(rr, req.WithContext(reqCtx))

			require.Equal(t, 2, db.transactions, "the change ran before the deletion's transaction")
			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			var refusal api.ErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refusal))
			assert.Equal(t, tc.wantCode, refusal.ErrorCode)
			kept, err := h.DB.GetUserById(ctx, nil, user.Id)
			require.NoError(t, err)
			assert.NotNil(t, kept, "the account is kept")
		})
	}
}
