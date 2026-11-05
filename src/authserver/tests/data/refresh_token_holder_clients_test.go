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

// TestGetUsableRefreshTokenClientIdsByUserId: the clients holding one of a user's refresh tokens
// that is still unrevoked and unexpired, through either linkage shape: the code's client for an
// authorization-code token, the token's own for a password grant. A user-wide end tells each of them
// (#784 decision 3). Each client is named once, however many such tokens it holds.
func TestGetUsableRefreshTokenClientIdsByUserId(t *testing.T) {
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
			ClientId: client.Id, UserId: owner.Id,
			Code: "code_" + fake.LetterN(8), CodeHash: "hash_" + fake.LetterN(8),
			CodeChallenge:       sql.NullString{String: "chal_" + fake.LetterN(8), Valid: true},
			CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
			RedirectURI:         "https://example.com/callback", Scope: "openid", IpAddress: "127.0.0.1",
			UserAgent: "test", ResponseMode: "query", AuthenticatedAt: now,
			SessionIdentifier: "sess_" + fake.LetterN(8), AcrLevel: "1", AuthMethods: "pwd", Used: true,
		}
		if err := database.CreateCode(context.Background(), nil, code); err != nil {
			t.Fatalf("Failed to create code: %v", err)
		}
		return code
	}
	viaCodeToken := func(client *record.Client, owner *record.User, isRevoked bool, expiresAt time.Time) {
		code := newCode(client, owner)
		rt := &record.RefreshToken{
			CodeId:           sql.NullInt64{Int64: code.Id, Valid: true},
			RefreshTokenJti:  fake.UUID(),
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
			UserId:           sql.NullInt64{Int64: owner.Id, Valid: true},
			ClientId:         sql.NullInt64{Int64: client.Id, Valid: true},
			RefreshTokenJti:  fake.UUID(),
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

	got, err := database.GetUsableRefreshTokenClientIdsByUserId(context.Background(), nil, user.Id, now)
	if err != nil {
		t.Fatalf("GetUsableRefreshTokenClientIdsByUserId failed: %v", err)
	}
	slices.Sort(got)
	want := []int64{viaCode.Id, viaCodeTwice.Id, direct.Id, revokedAndLive.Id}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("expected the clients %v, got %v", want, got)
	}

	// Inside a transaction too, which is where a user-wide end reads it.
	err = database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		inTx, txErr := database.GetUsableRefreshTokenClientIdsByUserId(context.Background(), tx, user.Id, now)
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
	got, err = database.GetUsableRefreshTokenClientIdsByUserId(context.Background(), nil, user.Id, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("GetUsableRefreshTokenClientIdsByUserId failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no clients once every token expired, got %v", got)
	}
}

// TestGetUsableRefreshTokenClientIdsByUserId_NoTokens: a user with no refresh token, and the zero
// id, name no client.
func TestGetUsableRefreshTokenClientIdsByUserId_NoTokens(t *testing.T) {
	user := createTestUser(t)
	for _, userId := range []int64{user.Id, 0} {
		got, err := database.GetUsableRefreshTokenClientIdsByUserId(context.Background(), nil, userId, time.Now().UTC())
		if err != nil {
			t.Fatalf("GetUsableRefreshTokenClientIdsByUserId(%d) failed: %v", userId, err)
		}
		if len(got) != 0 {
			t.Errorf("expected no clients for user %d, got %v", userId, got)
		}
	}
}
