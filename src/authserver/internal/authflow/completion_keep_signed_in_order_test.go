package authflow

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Two password entries of one user can both be held by the browser and both bind the session it
// arrived with, and the reuse arm's bind and its record of the Keep me signed in answer are separate
// writes. The newer password entry's answer replaces the older one's (#743 decision 2) whatever
// order the two completions' writes land in, so an older ticked box cannot make the cookie outlive
// the browser after a newer unticked one.

// orderBrowser is the handler's per-request adapter over the real ceremony store, for one request.
type orderBrowser struct {
	store *ceremony.Store
	w     http.ResponseWriter
	r     *http.Request
}

func (b *orderBrowser) SaveAuthContext(ac *ceremony.AuthContext) error {
	return b.store.SaveAuthContext(b.w, b.r, ac)
}
func (b *orderBrowser) ClearAuthContext(id string) error {
	return b.store.ClearAuthContext(b.w, b.r, id)
}
func (b *orderBrowser) RegenerateSession(id string, user int64) error {
	return b.store.RegenerateSession(b.w, b.r, id, user)
}
func (b *orderBrowser) ConfirmCeremony(id string) error { return b.store.ConfirmCeremony(b.w, b.r, id) }
func (b *orderBrowser) RegenerateSessionAndBind(id string, user int64, sid string, keep *bool) error {
	return b.store.RegenerateSessionAndBind(b.w, b.r, id, user, sid, keep)
}
func (b *orderBrowser) RecordKeepSignedIn(id string, keep *bool) error {
	return b.store.RecordKeepSignedIn(b.w, b.r, id, keep)
}
func (*orderBrowser) Device() usersession.Device    { return usersession.Device{} }
func (*orderBrowser) WriteDeviceCookie(string, int) {}

// afterBindAudit runs afterBind once, at the first audit event: the reuse arm's bump, which it logs
// after its bind has committed and before it records the answer.
type afterBindAudit struct{ afterBind func() }

func (a *afterBindAudit) Log(context.Context, string, map[string]interface{}) {
	if f := a.afterBind; f != nil {
		a.afterBind = nil
		f()
	}
}

func TestBindReusedSession_AnOlderCompletionLeavesTheNewerPasswordEntrysAnswer(t *testing.T) {
	ticked, unticked := true, false
	for _, tc := range []struct {
		name          string
		older, newer  *bool
		wantPersisted bool
	}{
		{"unticked after ticked", &ticked, &unticked, false},
		{"no box after ticked", &ticked, nil, false},
		{"ticked after unticked", &unticked, &ticked, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := sessiontest.NewMemoryBackend()
			keep := func(_ context.Context, v map[string]any) (bool, error) {
				answer, _ := v[sessionkeys.KeepSignedIn].(bool)
				return answer, nil
			}
			base, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
				sessionstore.PersistentCookie(keep), sessionstore.KeyPair{
					AuthenticationKey: []byte("12345678901234567890123456789012"),
					EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
				}, nil)
			require.NoError(t, err)
			store, err := sessionstore.NewConditionalStore(base, backend)
			require.NoError(t, err)
			ceremonies := ceremony.NewStore(store, sessionkeys.AuthServerSessionName)

			olderAt := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
			newerAt := olderAt.Add(time.Minute)
			completed := func(id string, at time.Time, answer *bool) *ceremony.AuthContext {
				return &ceremony.AuthContext{CeremonyId: id, ClientId: "the-client", UserId: 1,
					AuthState: ceremony.AuthStateAuthenticationCompleted, AuthMethods: "pwd",
					Level1AuthCompleted: true, AuthenticatedAt: &at, PasswordVerifiedAt: &at, KeepSignedIn: answer}
			}
			older := completed("ceremony-older", olderAt, tc.older)
			newer := completed("ceremony-newer", newerAt, tc.newer)

			// A browser session signed in to the-user-session, holding both ceremonies.
			seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
			seedRec := httptest.NewRecorder()
			require.NoError(t, ceremonies.AddAuthContext(seedRec, seedReq, older))
			require.NoError(t, ceremonies.AddAuthContext(seedRec, seedReq, newer))
			session, err := store.Get(seedReq, sessionkeys.AuthServerSessionName)
			require.NoError(t, err)
			session.Values[sessionkeys.SessionIdentifier] = "the-user-session"
			require.NoError(t, session.Save(seedReq, seedRec))
			seeded := seedRec.Result().Cookies()
			cookie := seeded[len(seeded)-1]
			browser := func() *orderBrowser {
				r := httptest.NewRequest(http.MethodGet, "/auth/completed", nil)
				r.AddCookie(cookie)
				return &orderBrowser{store: ceremonies, r: r, w: httptest.NewRecorder()}
			}

			// The real binding over a database that runs each transaction body on one tx and keeps the
			// row each bind writes.
			database := datamocks.NewDatabase(t)
			tx := &sql.Tx{}
			datamocks.ExpectRunInTransaction(database, tx)
			datamocks.ExpectRunInTransaction(database, tx)
			row := record.UserSession{Id: 1, UserId: 1, SessionIdentifier: "the-user-session",
				AcrLevel: record.AcrLevel1, AuthMethods: "pwd", AuthTime: olderAt.Add(-time.Hour),
				Clients: []record.UserSessionClient{{Id: 1, ClientId: 1, UserSessionId: 1}}}
			database.On("AcquireUserSessionRow", mock.Anything, tx, "the-user-session").Return(true, nil)
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, tx, "the-user-session").
				Return(func(context.Context, *sql.Tx, string) *record.UserSession { copied := row; return &copied }, nil)
			database.On("UserSessionLoadClients", mock.Anything, tx, mock.Anything).Return(nil)
			database.On("UpdateUserSession", mock.Anything, tx, mock.Anything).Return(nil).
				Run(func(args mock.Arguments) { row = *args.Get(2).(*record.UserSession) })
			database.On("UpdateUserSessionClient", mock.Anything, tx, mock.Anything).Return(nil)

			// The newer completion runs whole between the older one's bind and its record: bind older,
			// bind newer, record newer, record older.
			audit := &afterBindAudit{}
			op := &Completion{sessions: usersession.NewManager(database), auditLogger: audit}
			plan := reuseSession(false, true, true, false)
			client := &record.Client{Id: 1}
			newerBrowser := browser()
			audit.afterBind = func() {
				_, bindErr := op.bindReusedSession(context.Background(), newerBrowser, plan, newer, client,
					"the-user-session", record.AcrLevel1, "")
				require.NoError(t, bindErr)
			}
			_, err = op.bindReusedSession(context.Background(), browser(), plan, older, client,
				"the-user-session", record.AcrLevel1, "")
			require.NoError(t, err)
			require.True(t, row.AuthTime.Equal(newerAt), "the session row holds the newer authentication")

			readReq := httptest.NewRequest(http.MethodGet, "/", nil)
			readReq.AddCookie(cookie)
			stored, err := store.Get(readReq, sessionkeys.AuthServerSessionName)
			require.NoError(t, err)
			if tc.newer == nil {
				assert.NotContains(t, stored.Values, sessionkeys.KeepSignedIn, "the newer entry showed no box")
			} else {
				assert.Equal(t, *tc.newer, stored.Values[sessionkeys.KeepSignedIn], "the newer entry's answer")
			}

			nextWrite := httptest.NewRecorder()
			require.NoError(t, stored.Save(readReq, nextWrite))
			next := nextWrite.Result().Cookies()
			require.Len(t, next, 1)
			if tc.wantPersisted {
				assert.Positive(t, next[0].MaxAge, "the newer ticked box keeps the cookie past the browser")
			} else {
				assert.Zero(t, next[0].MaxAge, "the cookie ends with the browser, as the newer entry asked")
				assert.True(t, next[0].Expires.IsZero())
			}
		})
	}
}
