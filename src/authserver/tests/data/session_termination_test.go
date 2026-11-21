package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
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

	session := createTestUserSession(t, user.ID)
	sessionBoundCode := createTestCodeInSession(t, client.ID, user.ID, session.SessionIdentifier)
	offlineCode := createTestCodeInSession(t, client.ID, user.ID, session.SessionIdentifier)

	// Session-bound: the row carries the identifier itself.
	sessionBoundToken := createTokenOfCode(t, client.ID, user.ID, sessionBoundCode.ID, session.SessionIdentifier)
	// Offline: the row carries NO identifier, and is reachable only through its code.
	offlineToken := createTokenOfCode(t, client.ID, user.ID, offlineCode.ID, "")

	// The negative control, on a session of its own. Without it this test passes against a
	// termination that revokes every code and every token in the table, which would sign out
	// every other device of every user.
	otherSession := createTestUserSession(t, user.ID)
	otherCode := createTestCodeInSession(t, client.ID, user.ID, otherSession.SessionIdentifier)
	otherToken := createTokenOfCode(t, client.ID, user.ID, otherCode.ID, otherSession.SessionIdentifier)

	result, err := revocation.TerminateUserSessionTx(context.Background(), database, session, false)
	if err != nil {
		t.Fatalf("revocation.TerminateUserSessionTx returned error: %v", err)
	}

	if result.RevokedCodeCount != 2 {
		t.Errorf("RevokedCodeCount = %d, want 2", result.RevokedCodeCount)
	}
	if len(result.RevokedRefreshTokenJTIs) != 2 {
		t.Errorf("RevokedRefreshTokenJtis = %v, want the two tokens of this session",
			result.RevokedRefreshTokenJTIs)
	}

	// The row is gone, which is what the first statement did.
	gone, err := database.GetUserSessionByID(context.Background(), nil, session.ID)
	if err != nil {
		t.Fatalf("GetUserSessionByID after terminating: %v", err)
	}
	if gone != nil {
		t.Error("the terminated session row must be gone")
	}

	// And the two sweeps still ran, against a session row that no longer existed when they did.
	assertCodeRevoked(t, sessionBoundCode.ID, true, "the code of the terminated session")
	assertCodeRevoked(t, offlineCode.ID, true, "the offline grant's code of the terminated session")
	assertTokenRevoked(t, sessionBoundToken.ID, true, "the session-bound token of the terminated session")
	assertTokenRevoked(t, offlineToken.ID, true, "the offline token of the terminated session")

	assertCodeRevoked(t, otherCode.ID, false, "a code of an unrelated session")
	assertTokenRevoked(t, otherToken.ID, false, "a token of an unrelated session")

	stillThere, err := database.GetUserSessionByID(context.Background(), nil, otherSession.ID)
	if err != nil {
		t.Fatalf("GetUserSessionByID for the unrelated session: %v", err)
	}
	if stillThere == nil {
		t.Error("an unrelated session must survive the termination")
	}
}

// createTokenOfCode makes a refresh token descending from one code. sessionIdentifier is the
// token's OWN column, which an offline token leaves empty: the sid its grant came from lives on
// the codes row, and the sid-scoped sweep reaches it through that join alone.
func createTokenOfCode(t *testing.T, clientID, userID, codeID int64, sessionIdentifier string) *record.RefreshToken {
	return createTokenOfCodeOn(t, database, clientID, userID, codeID, sessionIdentifier)
}

// createTokenOfCodeOn takes the handle, for the reason createTestUserOn does.
func createTokenOfCodeOn(t *testing.T, db data.Database, clientID, userID, codeID int64, sessionIdentifier string) *record.RefreshToken {
	t.Helper()
	tokenType := "Refresh"
	if sessionIdentifier == "" {
		tokenType = "Offline"
	}
	token := &record.RefreshToken{
		CodeID:            sql.NullInt64{Int64: codeID, Valid: true},
		UserID:            sql.NullInt64{Int64: userID, Valid: true},
		ClientID:          sql.NullInt64{Int64: clientID, Valid: true},
		RefreshTokenJTI:   fake.UUID(),
		SessionIdentifier: sessionIdentifier,
		RefreshTokenType:  tokenType,
		Scope:             "openid profile offline_access",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := db.CreateRefreshToken(context.Background(), nil, token); err != nil {
		t.Fatalf("Failed to create test refresh token: %v", err)
	}
	return token
}

// assertTokenRevoked reloads a refresh token and checks the marker, for the same reason
// assertCodeRevoked reloads a code: what the column says on a later read is the whole point of
// writing it.
func assertTokenRevoked(t *testing.T, tokenID int64, want bool, what string) {
	t.Helper()
	assertTokenRevokedOn(t, database, tokenID, want, what)
}

// assertTokenRevokedOn reloads through the handle it is given, for the reason assertCodeRevokedOn
// does.
func assertTokenRevokedOn(t *testing.T, db data.Database, tokenID int64, want bool, what string) {
	t.Helper()
	token, err := db.GetRefreshTokenByID(context.Background(), nil, tokenID)
	if err != nil {
		t.Fatalf("Failed to reload refresh token %d: %v", tokenID, err)
	}
	if token == nil {
		t.Fatalf("Refresh token %d disappeared", tokenID)
	}
	if token.Revoked != want {
		t.Errorf("%s: Revoked = %v, want %v", what, token.Revoked, want)
	}
}
