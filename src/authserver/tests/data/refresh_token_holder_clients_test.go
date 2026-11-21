package datatests

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// TestGetUsableRefreshTokenClientIDsByUserID: the clients holding one of a user's refresh tokens
// that is still unrevoked and unexpired, through either linkage shape: the code's client for an
// authorization-code token, the token's own for a password grant. A user-wide end tells each of them
// (#784 decision 3). Each client is named once, however many such tokens it holds.
func TestGetUsableRefreshTokenClientIDsByUserID(t *testing.T) {
	user := createTestUser(t)
	otherUser := createTestUser(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	viaCode := createTestClient(t)        // an authorization-code token, live
	viaCodeTwice := createTestClient(t)   // two live authorization-code tokens
	direct := createTestClient(t)         // a password-grant token, live
	revoked := createTestClient(t)        // only a revoked token
	expired := createTestClient(t)        // only an expired token
	othersOnly := createTestClient(t)     // only another user's live tokens
	revokedAndLive := createTestClient(t) // a revoked token and a live one

	newCode := func(client *record.Client, owner *record.User) *record.Code {
		code := &record.Code{
			ClientID: client.ID, UserID: owner.ID,
			Code: "code_" + fake.LetterN(8), CodeHash: "hash_" + fake.LetterN(8),
			CodeChallenge:       sql.NullString{String: "chal_" + fake.LetterN(8), Valid: true},
			CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
			RedirectURI:         "https://example.com/callback", Scope: "openid", IPAddress: "127.0.0.1",
			UserAgent: "test", ResponseMode: "query", AuthenticatedAt: now,
			SessionIdentifier: "sess_" + fake.LetterN(8), ACRLevel: "1", AuthMethods: "pwd", Used: true,
		}
		if err := database.CreateCode(context.Background(), nil, code); err != nil {
			t.Fatalf("Failed to create code: %v", err)
		}
		return code
	}
	viaCodeToken := func(client *record.Client, owner *record.User, isRevoked bool, expiresAt time.Time) {
		code := newCode(client, owner)
		rt := &record.RefreshToken{
			CodeID:           sql.NullInt64{Int64: code.ID, Valid: true},
			RefreshTokenJTI:  fake.UUID(),
			RefreshTokenType: "Offline",
			Scope:            "openid",
			IssuedAt:         sql.NullTime{Time: now.Add(-2 * time.Hour), Valid: true},
			ExpiresAt:        sql.NullTime{Time: expiresAt, Valid: true},
			Revoked:          isRevoked,
		}
		if err := database.CreateRefreshToken(context.Background(), nil, rt); err != nil {
			t.Fatalf("Failed to create refresh token: %v", err)
		}
	}
	directToken := func(client *record.Client, owner *record.User, isRevoked bool, expiresAt time.Time) {
		rt := &record.RefreshToken{
			UserID:           sql.NullInt64{Int64: owner.ID, Valid: true},
			ClientID:         sql.NullInt64{Int64: client.ID, Valid: true},
			RefreshTokenJTI:  fake.UUID(),
			RefreshTokenType: "Offline",
			Scope:            "openid",
			IssuedAt:         sql.NullTime{Time: now.Add(-2 * time.Hour), Valid: true},
			ExpiresAt:        sql.NullTime{Time: expiresAt, Valid: true},
			Revoked:          isRevoked,
		}
		if err := database.CreateRefreshToken(context.Background(), nil, rt); err != nil {
			t.Fatalf("Failed to create refresh token: %v", err)
		}
	}

	later := now.Add(time.Hour)
	earlier := now.Add(-time.Minute)
	viaCodeToken(viaCode, user, false, later)
	viaCodeToken(viaCodeTwice, user, false, later)
	viaCodeToken(viaCodeTwice, user, false, later)
	directToken(direct, user, false, later)
	viaCodeToken(revoked, user, true, later)
	directToken(revoked, user, true, later)
	viaCodeToken(expired, user, false, earlier)
	directToken(expired, user, false, earlier)
	viaCodeToken(othersOnly, otherUser, false, later)
	directToken(othersOnly, otherUser, false, later)
	directToken(revokedAndLive, user, true, later)
	viaCodeToken(revokedAndLive, user, false, later)

	got, err := database.GetUsableRefreshTokenClientIDsByUserID(context.Background(), nil, user.ID, now)
	if err != nil {
		t.Fatalf("GetUsableRefreshTokenClientIDsByUserID failed: %v", err)
	}
	slices.Sort(got)
	want := []int64{viaCode.ID, viaCodeTwice.ID, direct.ID, revokedAndLive.ID}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("expected the clients %v, got %v", want, got)
	}

	// Inside a transaction too, which is where a user-wide end reads it.
	err = database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		inTx, txErr := database.GetUsableRefreshTokenClientIDsByUserID(context.Background(), tx, user.ID, now)
		if txErr != nil {
			return txErr
		}
		slices.Sort(inTx)
		if !slices.Equal(inTx, want) {
			t.Errorf("in a transaction: expected the clients %v, got %v", want, inTx)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RunInTransaction failed: %v", err)
	}

	// The instant decides expiry: judged two hours on, every token has expired.
	got, err = database.GetUsableRefreshTokenClientIDsByUserID(context.Background(), nil, user.ID, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("GetUsableRefreshTokenClientIDsByUserID failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no clients once every token expired, got %v", got)
	}
}

// TestGetUsableRefreshTokenClientIDsByUserID_NoTokens: a user with no refresh token, and the zero
// id, name no client.
func TestGetUsableRefreshTokenClientIDsByUserID_NoTokens(t *testing.T) {
	user := createTestUser(t)
	for _, userID := range []int64{user.ID, 0} {
		got, err := database.GetUsableRefreshTokenClientIDsByUserID(context.Background(), nil, userID, time.Now().UTC())
		if err != nil {
			t.Fatalf("GetUsableRefreshTokenClientIDsByUserID(%d) failed: %v", userID, err)
		}
		if len(got) != 0 {
			t.Errorf("expected no clients for user %d, got %v", userID, got)
		}
	}
}
