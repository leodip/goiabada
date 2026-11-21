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

	"github.com/leodip/goiabada/authserver/internal/audit"
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

// Both deletions of a user, the administrator's and the user's own, and the administrator's
// disable tell every app the existing rules owe a logout token, including an app whose session or
// refresh token a sign-in committed while the write waited for the user's row (#796). Each write
// takes the administrators' lock and then the user's row; on MySQL an ordinary read before that
// wait fixed the snapshot, so the write's lists of sessions and refresh tokens missed what committed
// during it, and those apps were never told. The disable also left that session and token in place.
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

func (s *recordedLogoutTokens) toldClientIDs() map[int64]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	told := map[int64]bool{}
	for _, delivery := range s.deliveries {
		told[delivery.ClientID] = true
	}
	return told
}

// toldAbout reports whether a recorded delivery goes to the app clientID and names the user subject
// as its sub, the user whose sessions the app ends.
func (s *recordedLogoutTokens) toldAbout(clientID int64, subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, delivery := range s.deliveries {
		if delivery.ClientID == clientID && delivery.Subject == subject {
			return true
		}
	}
	return false
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

func (d *userRowTakenAtTheWrite) GetUserByIDForUpdate(ctx context.Context, tx *sql.Tx, userID int64) (*record.User, error) {
	if err := d.takeOnce(tx); err != nil {
		return nil, err
	}
	return d.Database.GetUserByIDForUpdate(ctx, tx, userID)
}

// TrySetUserEnabled is where a disable that writes before it reads the user's row under its lock
// acquires that row. The holder takes it there then, so such a disable is still measured waiting
// inside its transaction, rather than never reaching the wait.
func (d *userRowTakenAtTheWrite) TrySetUserEnabled(ctx context.Context, tx *sql.Tx, userID int64, expected, desired bool) (bool, error) {
	if err := d.takeOnce(tx); err != nil {
		return false, err
	}
	return d.Database.TrySetUserEnabled(ctx, tx, userID, expected, desired)
}

// takeOnce has the holder take the user's row at the transaction's first acquisition of it, and
// signals the harness on the line before that acquisition.
func (d *userRowTakenAtTheWrite) takeOnce(tx *sql.Tx) error {
	if tx == nil || d.taken {
		return nil
	}
	d.taken = true
	err := d.take()
	d.reached()
	return err
}

// serveUserWrite serves one request of a write that ends a user's sessions through handler, under
// ctx so the test's deadline bounds the handler's queries, with the settings's session lifetimes
// positive, as a deployment's are, and a validated token with sub and scope.
func serveUserWrite(ctx context.Context, handler http.HandlerFunc, method, target string, params map[string]string,
	body []byte, sub, scope string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range params {
		req.SetPathValue(key, value)
	}
	ctx = reqctx.WithSettings(req.Context(), &record.Settings{ID: 1, AccountDeletionEnabled: true,
		UserSessionIdleTimeoutInSeconds: 3600, UserSessionMaxLifetimeInSeconds: 86400})
	ctx = reqctx.WithValidatedToken(ctx, oauth.JWTToken{Claims: map[string]interface{}{
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
				require.NoError(t, database.SetUserPasswordHash(ctx, nil, user.ID, hash))

				// The existing rules owe this app a token: it has a back-channel logout URI and
				// doesn't require a session identifier.
				app := createTestClient(t)
				require.NoError(t, database.SetClientBackchannelLogout(ctx, nil, app.ID, "https://app.example/backchannel", false))

				// The sign-in's writes, uncommitted.
				holder := beginTx(t)
				now := time.Now().UTC().Truncate(time.Microsecond)
				var session *record.UserSession
				var grant *record.RefreshToken
				if state == "a new session with an app" {
					session = &record.UserSession{
						SessionIdentifier: fake.UUID(), Started: now, LastAccessed: now, AuthMethods: "pwd",
						ACRLevel: record.ACRLevel1, AuthTime: now, PasswordAuthTime: now, IPAddress: "127.0.0.1",
						DeviceName: "deletion-wait", DeviceType: "desktop", DeviceOS: "Linux", UserAgent: testUserAgent,
						DeviceID: testDeviceID, UserID: user.ID, AuthStateGeneration: user.AuthStateGeneration,
					}
					require.NoError(t, database.CreateUserSession(ctx, holder, session))
					require.NoError(t, database.CreateUserSessionClient(ctx, holder, &record.UserSessionClient{
						UserSessionID: session.ID, ClientID: app.ID, Started: now, LastAccessed: now,
					}))
				} else {
					grant = &record.RefreshToken{
						UserID:          sql.NullInt64{Int64: user.ID, Valid: true},
						ClientID:        sql.NullInt64{Int64: app.ID, Valid: true},
						RefreshTokenJTI: fake.UUID(), RefreshTokenType: "Offline", Scope: "openid offline_access",
						IssuedAt:            sql.NullTime{Time: now, Valid: true},
						ExpiresAt:           sql.NullTime{Time: now.Add(time.Hour), Valid: true},
						MaxLifetime:         sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
						AuthStateGeneration: user.AuthStateGeneration,
					}
					grant.FirstRefreshTokenJTI = grant.RefreshTokenJTI
					require.NoError(t, database.CreateRefreshToken(ctx, holder, grant))
				}

				sender := &recordedLogoutTokens{}
				db := &userRowTakenAtTheWrite{Database: other, take: func() error {
					return database.AcquireUserRow(ctx, holder, user.ID)
				}}
				id := strconv.FormatInt(user.ID, 10)
				body, err := json.Marshal(map[string]string{"password": password})
				require.NoError(t, err)
				party := goBlocked(t, deletion, holder, func(reached func()) *httptest.ResponseRecorder {
					db.reached = reached
					if deletion == "the administrator's deletion" {
						return serveUserWrite(ctx, apihandlers.HandleUserDelete(db, &countingAuditLogger{}, noNotices{}, sender),
							http.MethodDelete, "/api/v1/admin/users/"+id, map[string]string{"id": id}, nil,
							"deletion-wait-test", manageScope)
					}
					return serveUserWrite(ctx, apihandlers.HandleAccountDeletionPost(db, &countingAuditLogger{}, uncountedFailures{}, dataCipher, noNotices{}, sender),
						http.MethodPost, "/api/v1/account/deletion", nil, body, user.Subject, "authserver:manage-account")
				})
				party.requireBlocked(t)
				party.requireStillWaiting(t)
				require.True(t, db.taken, "the deletion waits at its transaction's acquisition of the user's row")
				require.NoError(t, database.CommitTransaction(ctx, holder))
				rr := party.await(t)
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

				gone, err := database.GetUserByID(ctx, nil, user.ID)
				require.NoError(t, err)
				assert.Nil(t, gone, "the user is deleted")
				assert.True(t, sender.toldAbout(app.ID, user.Subject),
					"the app of %s the sign-in committed while the deletion waited is told the deleted user's subject", state)
			})
		}
	}
}

// The administrator's disable ends the session and revokes the refresh token a sign-in committed
// while it waited for the user's row, lists them in its audit event, and tells their apps (#796
// decisions 1 and 2).
func TestUserDisable_EndsAndTellsStateCommittedWhileItWaitedForTheUsersRow(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	manageScope := builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier

	for _, state := range []string{"a new session with an app", "a refresh token for an app on no session"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			other := secondDatabase(t)
			managePermissionRow(t)

			user := newHolder(t, database, true)

			// The existing rules owe this app a token: it has a back-channel logout URI and
			// doesn't require a session identifier.
			app := createTestClient(t)
			require.NoError(t, database.SetClientBackchannelLogout(ctx, nil, app.ID, "https://app.example/backchannel", false))

			// The sign-in's writes, uncommitted.
			holder := beginTx(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			var session *record.UserSession
			var grant *record.RefreshToken
			if state == "a new session with an app" {
				session = &record.UserSession{
					SessionIdentifier: fake.UUID(), Started: now, LastAccessed: now, AuthMethods: "pwd",
					ACRLevel: record.ACRLevel1, AuthTime: now, PasswordAuthTime: now, IPAddress: "127.0.0.1",
					DeviceName: "disable-wait", DeviceType: "desktop", DeviceOS: "Linux", UserAgent: testUserAgent,
					DeviceID: testDeviceID, UserID: user.ID, AuthStateGeneration: user.AuthStateGeneration,
				}
				require.NoError(t, database.CreateUserSession(ctx, holder, session))
				require.NoError(t, database.CreateUserSessionClient(ctx, holder, &record.UserSessionClient{
					UserSessionID: session.ID, ClientID: app.ID, Started: now, LastAccessed: now,
				}))
			} else {
				grant = &record.RefreshToken{
					UserID:          sql.NullInt64{Int64: user.ID, Valid: true},
					ClientID:        sql.NullInt64{Int64: app.ID, Valid: true},
					RefreshTokenJTI: fake.UUID(), RefreshTokenType: "Offline", Scope: "openid offline_access",
					IssuedAt:            sql.NullTime{Time: now, Valid: true},
					ExpiresAt:           sql.NullTime{Time: now.Add(time.Hour), Valid: true},
					MaxLifetime:         sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
					AuthStateGeneration: user.AuthStateGeneration,
				}
				grant.FirstRefreshTokenJTI = grant.RefreshTokenJTI
				require.NoError(t, database.CreateRefreshToken(ctx, holder, grant))
			}

			take := func() error { return database.AcquireUserRow(ctx, holder, user.ID) }
			if state == "a new session with an app" && dbType() == data.Postgres {
				// On PostgreSQL a password-only sign-in holds the user's row through its session
				// insert alone: the insert's user_id foreign-key check takes FOR KEY SHARE on it.
				// The holder takes nothing more, so the disable's lookup is measured waiting for
				// that lock, which FOR UPDATE conflicts with and FOR NO KEY UPDATE does not (#796
				// decision 1).
				take = func() error { return nil }
			}
			sender := &recordedLogoutTokens{}
			recorder := &recoveryAuditRecorder{}
			db := &userRowTakenAtTheWrite{Database: other, take: take}
			id := strconv.FormatInt(user.ID, 10)
			party := goBlocked(t, "the disable", holder, func(reached func()) *httptest.ResponseRecorder {
				db.reached = reached
				return serveUserWrite(ctx, apihandlers.HandleUserEnabledPut(db, recorder, sender),
					http.MethodPut, "/api/v1/admin/users/"+id+"/enabled", map[string]string{"id": id},
					[]byte(`{"enabled":false}`), "disable-wait-test", manageScope)
			})
			party.requireBlocked(t)
			party.requireStillWaiting(t)
			require.True(t, db.taken, "the disable waits at its transaction's acquisition of the user's row")
			require.NoError(t, database.CommitTransaction(ctx, holder))
			rr := party.await(t)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			disabled, err := database.GetUserByID(ctx, nil, user.ID)
			require.NoError(t, err)
			require.NotNil(t, disabled)
			assert.False(t, disabled.Enabled, "the user is disabled")

			require.Equal(t, []string{audit.EventUpdatedUserDetails, audit.EventRevokedUserAuthState}, recorder.events)
			revoked := recorder.details[1]
			if state == "a new session with an app" {
				left, err := database.GetUserSessionByID(ctx, nil, session.ID)
				require.NoError(t, err)
				assert.Nil(t, left, "the session started while the disable waited is ended")
				assert.Equal(t, []string{session.SessionIdentifier}, revoked["terminated_session_identifiers"])
			} else {
				assertTokenRevoked(t, grant.ID, true, "the refresh token issued while the disable waited")
				assert.Equal(t, []string{grant.RefreshTokenJTI}, revoked["revoked_refresh_token_jtis"])
			}
			assert.True(t, sender.toldAbout(app.ID, user.Subject),
				"the app of %s the sign-in committed while the disable waited is told the disabled user's subject", state)
		})
	}
}
