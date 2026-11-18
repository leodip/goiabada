package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/backchannel"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both deletions of a user, the administrator's and the user's own, tell every app the existing
// rules owe a logout token, including an app whose session or refresh token a sign-in committed
// while the deletion waited for the user's row (#796). Each deletion takes the administrators' lock
// and then the user's row; on MySQL an ordinary read in the lock fixed the snapshot before that
// wait, so the deletion's lists of sessions and refresh tokens missed what committed during it, and
// those apps were never told.
//
// SQLite's one connection cannot overlap two transactions, so these run on the three other engines.

// recordedLogoutTokens keeps the deliveries a write hands the sender.
type recordedLogoutTokens struct {
	mu         sync.Mutex
	deliveries []backchannel.Delivery
}

func (s *recordedLogoutTokens) Send(_ context.Context, _ string, deliveries []backchannel.Delivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries = append(s.deliveries, deliveries...)
}

func (s *recordedLogoutTokens) toldClientIds() map[int64]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	told := map[int64]bool{}
	for _, delivery := range s.deliveries {
		told[delivery.ClientId] = true
	}
	return told
}

// userRowTakenAtTheWrite has the holder take the user's row as the write's transaction comes to take
// it: after every read the handler makes before its transaction has answered, and after the
// administrators' lock. A wait before the transaction would prove nothing, since on SQL Server the
// handler's first read of the user waits behind a holder of the row too. reached is the
// blocked-party harness's signal, given on the line before the transaction's own acquisition.
type userRowTakenAtTheWrite struct {
	data.Database
	take    func() error
	reached func()
	taken   bool
}

func (d *userRowTakenAtTheWrite) GetUserByIdForUpdate(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error) {
	if tx != nil && !d.taken {
		d.taken = true
		if err := d.take(); err != nil {
			d.reached()
			return nil, err
		}
		d.reached()
	}
	return d.Database.GetUserByIdForUpdate(ctx, tx, userId)
}

// serveDeletion serves one deletion request through handler, with the settings's session lifetimes
// positive, as a deployment's are, and a validated token with sub and scope.
func serveDeletion(handler http.HandlerFunc, method, target string, params map[string]string, body []byte,
	sub, scope string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range params {
		req.SetPathValue(key, value)
	}
	ctx := reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, AccountDeletionEnabled: true,
		UserSessionIdleTimeoutInSeconds: 3600, UserSessionMaxLifetimeInSeconds: 86400})
	ctx = reqctx.WithValidatedToken(ctx, oauth.JwtToken{Claims: map[string]interface{}{
		"sub": sub, "scope": scope, "auth_time": float64(1),
	}})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req.WithContext(ctx))
	return rr
}

func TestUserDeletion_TellsTheAppOfStateCommittedWhileItWaitedForTheUsersRow(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	const password = "Deletion-wait-796-password!"
	manageScope := builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier

	for _, deletion := range []string{"the administrator's deletion", "the own-account deletion"} {
		for _, state := range []string{"a new session with an app", "a refresh token for an app on no session"} {
			t.Run(deletion+"/"+state, func(t *testing.T) {
				ctx := context.Background()
				other := secondDatabase(t)
				managePermissionRow(t)

				user := newHolder(t, database, true)
				hash, err := passwordhash.Hash(password)
				require.NoError(t, err)
				require.NoError(t, database.SetUserPasswordHash(ctx, nil, user.Id, hash))

				// The existing rules owe this app a token: it has a back-channel logout URI and
				// doesn't require a session identifier.
				app := createTestClient(t)
				require.NoError(t, database.SetClientBackchannelLogout(ctx, nil, app.Id, "https://app.example/backchannel", false))

				// The sign-in's writes, uncommitted.
				holder := beginTx(t)
				now := time.Now().UTC().Truncate(time.Microsecond)
				var session *record.UserSession
				var grant *record.RefreshToken
				if state == "a new session with an app" {
					session = &record.UserSession{
						SessionIdentifier: fake.UUID(), Started: now, LastAccessed: now, AuthMethods: "pwd",
						AcrLevel: record.AcrLevel1, AuthTime: now, PasswordAuthTime: now, IpAddress: "127.0.0.1",
						DeviceName: "deletion-wait", DeviceType: "desktop", DeviceOS: "Linux", UserAgent: testUserAgent,
						DeviceId: testDeviceId, UserId: user.Id, AuthStateGeneration: user.AuthStateGeneration,
					}
					require.NoError(t, database.CreateUserSession(ctx, holder, session))
					require.NoError(t, database.CreateUserSessionClient(ctx, holder, &record.UserSessionClient{
						UserSessionId: session.Id, ClientId: app.Id, Started: now, LastAccessed: now,
					}))
				} else {
					grant = &record.RefreshToken{
						UserId:          sql.NullInt64{Int64: user.Id, Valid: true},
						ClientId:        sql.NullInt64{Int64: app.Id, Valid: true},
						RefreshTokenJti: fake.UUID(), RefreshTokenType: "Offline", Scope: "openid offline_access",
						IssuedAt:            sql.NullTime{Time: now, Valid: true},
						ExpiresAt:           sql.NullTime{Time: now.Add(time.Hour), Valid: true},
						MaxLifetime:         sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
						AuthStateGeneration: user.AuthStateGeneration,
					}
					grant.FirstRefreshTokenJti = grant.RefreshTokenJti
					require.NoError(t, database.CreateRefreshToken(ctx, holder, grant))
				}

				sender := &recordedLogoutTokens{}
				db := &userRowTakenAtTheWrite{Database: other, take: func() error {
					return database.AcquireUserRow(ctx, holder, user.Id)
				}}
				id := strconv.FormatInt(user.Id, 10)
				body, err := json.Marshal(map[string]string{"password": password})
				require.NoError(t, err)
				party := goBlocked(t, deletion, holder, func(reached func()) *httptest.ResponseRecorder {
					db.reached = reached
					if deletion == "the administrator's deletion" {
						return serveDeletion(apihandlers.HandleUserDelete(db, &countingAuditLogger{}, noNotices{}, sender),
							http.MethodDelete, "/api/v1/admin/users/"+id, map[string]string{"id": id}, nil,
							"deletion-wait-test", manageScope)
					}
					return serveDeletion(apihandlers.HandleAccountDeletionPost(db, &countingAuditLogger{}, uncountedFailures{}, dataCipher, noNotices{}, sender),
						http.MethodPost, "/api/v1/account/deletion", nil, body, user.Subject, "authserver:manage-account")
				})
				party.requireBlocked(t)
				party.requireStillWaiting(t)
				require.True(t, db.taken, "the deletion waits at its transaction's acquisition of the user's row")
				require.NoError(t, database.CommitTransaction(ctx, holder))
				rr := party.await(t)
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

				gone, err := database.GetUserById(ctx, nil, user.Id)
				require.NoError(t, err)
				assert.Nil(t, gone, "the user is deleted")
				assert.True(t, sender.toldClientIds()[app.Id],
					"the app of %s the sign-in committed while the deletion waited is among the logout-token deliveries", state)
			})
		}
	}
}
