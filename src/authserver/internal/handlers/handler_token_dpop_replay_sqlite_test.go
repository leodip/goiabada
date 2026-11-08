package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// The token endpoint's replay store over a real SQLite database migrated to head, for what a double
// can only say was asked for: that one proof sent many times at once is accepted exactly once, that
// a second instance sharing the database refuses a proof the first accepted, and that the sweep
// never opens a window in which a recorded proof is accepted again (#42 decision 9). The data tier
// shows the same insert on all four engines; this runs it in process, under the race detector in
// the race tier.

func newReplaySQLiteDB(t *testing.T) *sqlitedb.Database {
	t.Helper()
	db, err := sqlitedb.New(context.Background(), "file:"+filepath.Join(t.TempDir(), "dpop_replay_test.db"), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	if err := m.Up(context.Background()); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head")
	}
	return db
}

// newDPoPTokenInstance is one auth server instance's token endpoint, under dpopSessionKey, storing
// proofs in replays, with a validator that accepts every request as a client credentials grant.
func newDPoPTokenInstance(t *testing.T, replays *sqlitedb.Database) *dpopTokenEndpoint {
	t.Helper()
	checker, err := dpop.NewChecker(dpopPublicBaseURL)
	require.NoError(t, err)
	e := &dpopTokenEndpoint{
		database:    datamocks.NewDatabase(t),
		issuer:      handlersmocks.NewTokenIssuer(t),
		validator:   handlersmocks.NewTokenValidator(t),
		auditLogger: handlersmocks.NewAuditLogger(t),
		registry:    metrics.NewRegistry(),
		now:         dpopNow,
	}
	proofs := TokenProofs{Checker: checker, Nonces: dpop.NewNonces(dpopSessionKey), Replays: replays, Now: func() time.Time { return e.now }}
	e.handler = TokenDPoPNonce(proofs)(HandleTokenPost(render.New(nil, nil), e.database, e.issuer, e.validator, e.auditLogger,
		&countingCredentialFailures{}, tokenmetrics.Register(e.registry), &recordingLogoutTokens{}, proofs)).ServeHTTP
	e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
		Return(&protocolvalidation.ClientCredentialsGrant{Client: &record.Client{Id: 1}, Scope: "r:p"}, nil)
	e.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
	return e
}

// issues has the instance's issuer mint a bound token, times times.
func (e *dpopTokenEndpoint) issues(key dpoptest.Key, times int) {
	e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, mock.Anything, "r:p", key.Thumbprint).
		Return(&oauth.TokenResponse{AccessToken: "a", TokenType: "DPoP"}, nil).Times(times)
}

// Simultaneous requests carrying one proof: exactly one is answered with tokens, and every other is
// refused as a replay. The issuer, a strict double, mints once.
func TestTokenDPoP_OfSimultaneousRequestsWithOneProofExactlyOneSucceeds(t *testing.T) {
	const requests = 16
	key := dpoptest.RFC7517Key(t)
	e := newDPoPTokenInstance(t, newReplaySQLiteDB(t))
	nonce := e.freshNonce(t)
	e.issues(key, 1)
	proof := key.Proof(t, "POST", dpopTokenHTU, e.now, nonce)

	start := make(chan struct{})
	var wg sync.WaitGroup
	answers := make([]*httptest.ResponseRecorder, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(clientCredentialsForm))
			req = withSettings(req, &record.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("DPoP", proof)
			answers[i] = httptest.NewRecorder()
			e.handler.ServeHTTP(answers[i], req)
		}(i)
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for _, rr := range answers {
		if rr.Code == http.StatusOK {
			succeeded++
			continue
		}
		assertTokenError(t, rr, "invalid_dpop_proof", "The DPoP proof is invalid.")
	}
	assert.Equal(t, 1, succeeded, "exactly one request with the proof is answered with tokens")
}

// A proof accepted at one instance is refused at a second sharing the database, as at the first,
// while that second instance accepts a proof of its own.
func TestTokenDPoP_AProofAcceptedAtOneInstanceIsAReplayAtAnother(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	db := newReplaySQLiteDB(t)
	first := newDPoPTokenInstance(t, db)
	second := newDPoPTokenInstance(t, db)
	nonce := first.freshNonce(t)
	first.issues(key, 1)
	second.issues(key, 1)
	proof := key.Proof(t, "POST", dpopTokenHTU, first.now, nonce)

	rr := first.post(t, "/auth/token", clientCredentialsForm, proof)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	assertTokenError(t, second.post(t, "/auth/token", clientCredentialsForm, proof), "invalid_dpop_proof", "The DPoP proof is invalid.")
	assertTokenError(t, first.post(t, "/auth/token", clientCredentialsForm, proof), "invalid_dpop_proof", "The DPoP proof is invalid.")

	rr = second.post(t, "/auth/token", clientCredentialsForm, key.Proof(t, "POST", dpopTokenHTU, second.now, nonce))
	assert.Equal(t, http.StatusOK, rr.Code, "a new proof with the same nonce is another proof: %s", rr.Body.String())
}

// The record outlives the last moment its proof could be accepted, and the sweep never deletes it
// before then: a sweep at the nonce's expiry keeps the record, so a replay at that moment is still
// refused as one, and once a sweep has deleted it, past the grace, the proof is refused for its
// expired nonce, never accepted.
func TestTokenDPoP_TheSweepNeverLetsAProofBeAcceptedTwice(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	db := newReplaySQLiteDB(t)
	e := newDPoPTokenInstance(t, db)
	nonce := e.freshNonce(t) // minted at dpopNow, good until dpopNow plus ten minutes
	e.issues(key, 1)
	proof := key.Proof(t, "POST", dpopTokenHTU, e.now, nonce)
	expiresAt := dpopNow.Add(10 * time.Minute)
	recordExpiresAt := expiresAt.Add(dpop.ReplayRecordGrace)

	require.Equal(t, http.StatusOK, e.post(t, "/auth/token", clientCredentialsForm, proof).Code)

	require.NoError(t, db.DeleteExpiredDPoPProofs(context.Background(), nil, expiresAt.UTC()))
	e.now = expiresAt
	assertTokenError(t, e.post(t, "/auth/token", clientCredentialsForm, proof), "invalid_dpop_proof", "The DPoP proof is invalid.")

	require.NoError(t, db.DeleteExpiredDPoPProofs(context.Background(), nil, recordExpiresAt.UTC()))
	assertTokenError(t, e.post(t, "/auth/token", clientCredentialsForm, proof), "invalid_dpop_proof", "The DPoP proof is invalid.")

	require.NoError(t, db.DeleteExpiredDPoPProofs(context.Background(), nil, recordExpiresAt.Add(time.Microsecond).UTC()))
	e.now = recordExpiresAt.Add(time.Microsecond)
	assertTokenError(t, e.post(t, "/auth/token", clientCredentialsForm, proof), "use_dpop_nonce", "Authorization server requires nonce in DPoP proof.")
}

// A proof accepted late in its nonce's life stays refused at an instance whose clock runs 30
// seconds behind, after another instance swept the table the moment the nonce expired by its own
// clock: the record is kept past the nonce's expiry by the grace (RFC 9449 section 11.1).
func TestTokenDPoP_ASweepByAnotherClockNeverLetsAProofBeAcceptedTwice(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	db := newReplaySQLiteDB(t)
	first := newDPoPTokenInstance(t, db)
	behind := newDPoPTokenInstance(t, db)
	nonce := first.freshNonce(t) // minted at dpopNow
	proof := key.Proof(t, "POST", dpopTokenHTU, dpopNow, nonce)
	first.issues(key, 1)

	first.now = dpopNow.Add(9*time.Minute + 45*time.Second)
	require.Equal(t, http.StatusOK, first.post(t, "/auth/token", clientCredentialsForm, proof).Code)

	sweeperNow := dpopNow.Add(10*time.Minute + time.Second)
	require.NoError(t, db.DeleteExpiredDPoPProofs(context.Background(), nil, sweeperNow.UTC()))
	behind.now = sweeperNow.Add(-30 * time.Second)
	behind.auditLogger.ExpectedCalls[0].Maybe() // it mints nothing, so audits nothing

	assertTokenError(t, behind.post(t, "/auth/token", clientCredentialsForm, proof), "invalid_dpop_proof", "The DPoP proof is invalid.")
}

// A request validated across its nonce's expiry, while another instance sweeps the table, cannot
// record the proof another request already spent as new: it is judged again at the record point and
// refused, and the record is still there.
func TestTokenDPoP_AnInFlightRequestAcrossTheExpiryCannotSpendAProofAgain(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	db := newReplaySQLiteDB(t)
	first := newDPoPTokenInstance(t, db)
	nonce := first.freshNonce(t) // minted at dpopNow
	proof := usedOnceProof(t, key, dpopNow, nonce)
	first.issues(key, 1)

	first.now = dpopNow.Add(599 * time.Second)
	require.Equal(t, http.StatusOK, first.post(t, "/auth/token", clientCredentialsForm, proof).Code)

	second := newDPoPTokenInstance(t, db)
	second.now = first.now
	second.auditLogger.ExpectedCalls[0].Maybe() // it mints nothing, so audits nothing
	second.validator.ExpectedCalls[0].Run(func(mock.Arguments) {
		second.now = dpopNow.Add(601 * time.Second)
		require.NoError(t, db.DeleteExpiredDPoPProofs(context.Background(), nil, second.now.UTC()))
	})

	rr := second.post(t, "/auth/token", clientCredentialsForm, proof)

	assertTokenError(t, rr, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof.")
	recorded, err := db.RecordDPoPProof(context.Background(), nil, usedOnceReplayKey, dpopNow)
	require.NoError(t, err)
	assert.False(t, recorded, "the first request's record outlived the sweep")
}
