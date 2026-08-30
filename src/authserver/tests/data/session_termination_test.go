package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/models"
)

// TestTerminateUserSessionTx_SweepsAfterTheSessionRowIsDeleted is the data half of #139 decision 2.
//
// The delete moved to the FRONT of the termination transaction, because it is the statement that
// takes the user_sessions row and that row is what makes an authorization ceremony minting a code
// wait for this transaction, or this transaction wait for it. The unit test in the handlers
// package pins the order; what it cannot pin is that the two sweeps still find their rows once the
// session row is gone, because a mock returns whatever it was told to whichever order the calls
// arrive in.
//
// That question is only answerable against a real catalog, and it has to be asked on every engine:
// the argument for safety is that neither sweep reads user_sessions and that codes carries no
// foreign key to it, and a foreign key or a cascade present on one engine and not another is
// exactly the kind of divergence #282 found shipping for months.
//
// The offline token is the load-bearing row. Its own session_identifier is empty, so only the join
// through codes ties it to this session, and that join is the one thing a deleted session row could
// plausibly have disturbed.
func TestTerminateUserSessionTx_SweepsAfterTheSessionRowIsDeleted(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	session := createTestUserSession(t, user.Id)
	sessionBoundCode := createTestCodeInSession(t, client.Id, user.Id, session.SessionIdentifier)
	offlineCode := createTestCodeInSession(t, client.Id, user.Id, session.SessionIdentifier)

	// Session-bound: the row carries the identifier itself.
	sessionBoundToken := createTokenOfCode(t, client.Id, user.Id, sessionBoundCode.Id, session.SessionIdentifier)
	// Offline: the row carries NO identifier, and is reachable only through its code.
	offlineToken := createTokenOfCode(t, client.Id, user.Id, offlineCode.Id, "")

	// The negative control, on a session of its own. Without it this test passes against a
	// termination that revokes every code and every token in the table, which would sign out
	// every other device of every user.
	otherSession := createTestUserSession(t, user.Id)
	otherCode := createTestCodeInSession(t, client.Id, user.Id, otherSession.SessionIdentifier)
	otherToken := createTokenOfCode(t, client.Id, user.Id, otherCode.Id, otherSession.SessionIdentifier)

	result, err := handlers.TerminateUserSessionTx(database, session)
	if err != nil {
		t.Fatalf("TerminateUserSessionTx returned error: %v", err)
	}

	if result.RevokedCodeCount != 2 {
		t.Errorf("RevokedCodeCount = %d, want 2", result.RevokedCodeCount)
	}
	if len(result.RevokedRefreshTokenJtis) != 2 {
		t.Errorf("RevokedRefreshTokenJtis = %v, want the two tokens of this session",
			result.RevokedRefreshTokenJtis)
	}

	// The row is gone, which is what the first statement did.
	gone, err := database.GetUserSessionById(nil, session.Id)
	if err != nil {
		t.Fatalf("GetUserSessionById after terminating: %v", err)
	}
	if gone != nil {
		t.Error("the terminated session row must be gone")
	}

	// And the two sweeps still ran, against a session row that no longer existed when they did.
	assertCodeRevoked(t, sessionBoundCode.Id, true, "the code of the terminated session")
	assertCodeRevoked(t, offlineCode.Id, true, "the offline grant's code of the terminated session")
	assertTokenRevoked(t, sessionBoundToken.Id, true, "the session-bound token of the terminated session")
	assertTokenRevoked(t, offlineToken.Id, true, "the offline token of the terminated session")

	assertCodeRevoked(t, otherCode.Id, false, "a code of an unrelated session")
	assertTokenRevoked(t, otherToken.Id, false, "a token of an unrelated session")

	stillThere, err := database.GetUserSessionById(nil, otherSession.Id)
	if err != nil {
		t.Fatalf("GetUserSessionById for the unrelated session: %v", err)
	}
	if stillThere == nil {
		t.Error("an unrelated session must survive the termination")
	}
}

// createTokenOfCode makes a refresh token descending from one code. sessionIdentifier is the
// token's OWN column, which an offline token leaves empty: the sid its grant came from lives on
// the codes row, and the sid-scoped sweep reaches it through that join alone.
func createTokenOfCode(t *testing.T, clientId, userId, codeId int64, sessionIdentifier string) *models.RefreshToken {
	t.Helper()
	tokenType := "Refresh"
	if sessionIdentifier == "" {
		tokenType = "Offline"
	}
	token := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: codeId, Valid: true},
		UserId:            sql.NullInt64{Int64: userId, Valid: true},
		ClientId:          sql.NullInt64{Int64: clientId, Valid: true},
		RefreshTokenJti:   gofakeit.UUID(),
		SessionIdentifier: sessionIdentifier,
		RefreshTokenType:  tokenType,
		Scope:             "openid profile offline_access",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, token); err != nil {
		t.Fatalf("Failed to create test refresh token: %v", err)
	}
	return token
}

// assertTokenRevoked reloads a refresh token and checks the marker, for the same reason
// assertCodeRevoked reloads a code: what the column says on a later read is the whole point of
// writing it.
func assertTokenRevoked(t *testing.T, tokenId int64, want bool, what string) {
	t.Helper()
	token, err := database.GetRefreshTokenById(nil, tokenId)
	if err != nil {
		t.Fatalf("Failed to reload refresh token %d: %v", tokenId, err)
	}
	if token == nil {
		t.Fatalf("Refresh token %d disappeared", tokenId)
	}
	if token.Revoked != want {
		t.Errorf("%s: Revoked = %v, want %v", what, token.Revoked, want)
	}
}
