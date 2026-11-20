package datatests

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A disconnect ends everything the user holds with the client when it commits, whatever its
// transaction read before its sweep (#135 decisions 1 and 2). Its first read, of the client, fixes
// MySQL's REPEATABLE READ snapshot; a grant and a consent committed after it, and before the sweep,
// must still be revoked and deleted. And two disconnects that overlap must not both report, and so
// audit, the one token only one of them revoked.
//
// SQLite's single connection cannot interleave a second writer inside the disconnect's transaction,
// so these run on the three engines with row locks.

// hookAfterDisconnectRead runs its hook once, right after the named read of the disconnect's
// transaction: the client's (GetClientsByIds) or the refresh tokens' (GetRefreshTokensByUserIdAndClientId).
type hookAfterDisconnectRead struct {
	data.Database
	afterClientRead func()
	afterTokenRead  func()
}

func (d *hookAfterDisconnectRead) GetClientsByIds(ctx context.Context, tx *sql.Tx, clientIds []int64) ([]record.Client, error) {
	clients, err := d.Database.GetClientsByIds(ctx, tx, clientIds)
	if err == nil && tx != nil && d.afterClientRead != nil {
		hook := d.afterClientRead
		d.afterClientRead = nil
		hook()
	}
	return clients, err
}

func (d *hookAfterDisconnectRead) GetRefreshTokensByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64,
	clientId int64) ([]*record.RefreshToken, error) {
	tokens, err := d.Database.GetRefreshTokensByUserIdAndClientId(ctx, tx, userId, clientId)
	if err == nil && d.afterTokenRead != nil {
		hook := d.afterTokenRead
		d.afterTokenRead = nil
		hook()
	}
	return tokens, err
}

// liveCodeGrant stores, on db, a redeemed code of the user with the client and the live refresh
// token it issued, the shape a completed authorization-code sign-in leaves, and returns the token.
func liveCodeGrant(t *testing.T, db data.Database, userId int64, clientId int64) *record.RefreshToken {
	t.Helper()
	ctx := context.Background()
	code := &record.Code{
		ClientId:            clientId,
		UserId:              userId,
		Code:                "code_" + fake.LetterN(8),
		CodeHash:            "hash_" + fake.LetterN(8),
		CodeChallenge:       sql.NullString{String: "chal_" + fake.LetterN(8), Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		IpAddress:           "127.0.0.1",
		UserAgent:           "test",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   "sess_" + fake.LetterN(8),
		AcrLevel:            "1",
		AuthMethods:         "pwd",
		Used:                true,
	}
	require.NoError(t, db.CreateCode(ctx, nil, code), "CreateCode")
	jti := fake.UUID()
	token := &record.RefreshToken{
		CodeId:               sql.NullInt64{Int64: code.Id, Valid: true},
		RefreshTokenJti:      jti,
		FirstRefreshTokenJti: jti,
		SessionIdentifier:    code.SessionIdentifier,
		RefreshTokenType:     "Refresh",
		Scope:                "openid",
		IssuedAt:             sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:            sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	require.NoError(t, db.CreateRefreshToken(ctx, nil, token), "CreateRefreshToken")
	return token
}

// TestDisconnect_RevokesAGrantAndAConsentCommittedAfterItsFirstRead drives the Account DELETE
// handler. After the disconnect's transaction reads the client, its first read, another connection
// commits a new grant and a consent of the user with the client. The disconnect must revoke the
// grant it already held and the new one, and delete the consent: neither was in the snapshot that
// first read fixed on MySQL.
func TestDisconnect_RevokesAGrantAndAConsentCommittedAfterItsFirstRead(t *testing.T) {
	skipOnSQLite(t)
	ctx := context.Background()
	user := createTestUser(t)
	client := createTestClient(t)
	before := liveCodeGrant(t, database, user.Id, client.Id)

	var after *record.RefreshToken
	db := &hookAfterDisconnectRead{Database: database, afterClientRead: func() {
		after = liveCodeGrant(t, database, user.Id, client.Id)
		require.NoError(t, database.CreateUserConsent(ctx, nil, &record.UserConsent{
			UserId: user.Id, ClientId: client.Id, Scope: "openid",
			GrantedAt: sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		}), "CreateUserConsent")
	}}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/account/connected-clients/"+strconv.FormatInt(client.Id, 10), nil)
	req.SetPathValue("clientId", strconv.FormatInt(client.Id, 10))
	reqCtx := reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, Issuer: "https://issuer.example"})
	reqCtx = reqctx.WithValidatedToken(reqCtx, oauth.JwtToken{Claims: map[string]interface{}{
		"sub": user.Subject, "scope": "authserver:manage-account", "auth_time": float64(1),
	}})
	audits := &countingAuditLogger{}
	rr := httptest.NewRecorder()
	apihandlers.HandleAccountConnectedClientDelete(db, audits, noLogoutTokens{}).ServeHTTP(rr, req.WithContext(reqCtx))

	require.NotNil(t, after, "the hook ran inside the disconnect's transaction")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, 2, audits.count(), "deleted_own_user_consent and disconnected_client")

	grants, err := database.GetLiveGrantsByUserId(ctx, nil, user.Id, time.Now().UTC())
	require.NoError(t, err)
	assert.Empty(t, grants, "no grant of the user with the client survives the disconnect")
	consent, err := database.GetConsentByUserIdAndClientId(ctx, nil, user.Id, client.Id)
	require.NoError(t, err)
	assert.Nil(t, consent, "the consent given after the disconnect's first read is deleted")
	for _, token := range []*record.RefreshToken{before, after} {
		stored, err := database.GetRefreshTokenByJti(ctx, nil, token.RefreshTokenJti)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.True(t, stored.Revoked, "token %s revoked", token.RefreshTokenJti)
		recorded, err := database.IsRefreshTokenFamilyRevoked(ctx, nil, token.FirstRefreshTokenJti)
		require.NoError(t, err)
		assert.True(t, recorded, "family %s recorded", token.FirstRefreshTokenJti)
	}
}

// TestDisconnect_OverlappingCallsReportOneRevocation runs a second disconnect of the same user and
// client while the first is between its read of the refresh tokens and its writes. Whichever
// commits its writes first reports the token and the family; the other changed nothing and reports
// nothing, so its caller answers 404 and audits nothing (#135 decision 2). On PostgreSQL and SQL
// Server the second runs to its commit inside the hook; on MySQL the first's locking read makes it
// wait until the first commits, so the hook gives up waiting and lets the first go on.
func TestDisconnect_OverlappingCallsReportOneRevocation(t *testing.T) {
	skipOnSQLite(t)
	ctx := context.Background()
	user := createTestUser(t)
	client := createTestClient(t)
	token := liveCodeGrant(t, database, user.Id, client.Id)

	type outcome struct {
		result revocation.DisconnectResult
		err    error
	}
	second := make(chan outcome, 1)
	db := &hookAfterDisconnectRead{Database: database, afterTokenRead: func() {
		go func() {
			result, err := revocation.DisconnectClientTx(ctx, database, user.Id, client.Id, nil, nil)
			second <- outcome{result, err}
		}()
		select {
		case done := <-second:
			second <- done
		case <-time.After(2 * time.Second):
		}
	}}

	first, err := revocation.DisconnectClientTx(ctx, db, user.Id, client.Id, nil, nil)
	require.NoError(t, err, "the first disconnect")
	other := <-second
	require.NoError(t, other.err, "the second disconnect")

	changed := 0
	reported := 0
	for _, result := range []revocation.DisconnectResult{first, other.result} {
		if result.Changed() {
			changed++
		}
		for _, jti := range result.RevokedRefreshTokenJtis {
			if jti == token.RefreshTokenJti {
				reported++
			}
		}
	}
	assert.Equal(t, 1, changed, "exactly one disconnect changed something: first %+v, second %+v", first, other.result)
	assert.Equal(t, 1, reported, "the token is reported by the one call that revoked it")
	assert.Equal(t, 1, first.RecordedFamilyCount+other.result.RecordedFamilyCount, "the family is recorded once")

	stored, err := database.GetRefreshTokenByJti(ctx, nil, token.RefreshTokenJti)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Revoked)
}
