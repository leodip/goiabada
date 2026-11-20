package datatests

import (
	"context"
	"database/sql"
	"sort"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// liveGrantFixture writes refresh tokens for the live-grant read, through either linkage shape: an
// authorization-code token reaches its user and client through its code, a password-grant token
// through its own columns.
type liveGrantFixture struct {
	t   *testing.T
	now time.Time
}

// liveGrantToken is one token to write: its owner and client, its scope, whether it is revoked,
// its expiry (nil for none) and whether its rotation family has a revocation record.
type liveGrantToken struct {
	owner          *record.User
	client         *record.Client
	viaCode        bool
	scope          string
	revoked        bool
	expiresAt      *time.Time
	familyRecorded bool
}

// write stores the token and answers its id.
func (f liveGrantFixture) write(token liveGrantToken) int64 {
	f.t.Helper()
	// A rotated member of its family, so the family's identifier is not the token's own.
	firstJti := fake.UUID()
	rt := &record.RefreshToken{
		RefreshTokenJti:      fake.UUID(),
		FirstRefreshTokenJti: firstJti,
		RefreshTokenType:     "Refresh",
		Scope:                token.scope,
		IssuedAt:             sql.NullTime{Time: f.now.Add(-2 * time.Hour), Valid: true},
		Revoked:              token.revoked,
	}
	if token.expiresAt != nil {
		rt.ExpiresAt = sql.NullTime{Time: *token.expiresAt, Valid: true}
	}
	if token.viaCode {
		code := &record.Code{
			ClientId: token.client.Id, UserId: token.owner.Id,
			Code: "code_" + fake.LetterN(8), CodeHash: "hash_" + fake.LetterN(8),
			CodeChallenge:       sql.NullString{String: "chal_" + fake.LetterN(8), Valid: true},
			CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
			RedirectURI:         "https://example.com/callback", Scope: token.scope, IpAddress: "127.0.0.1",
			UserAgent: "test", ResponseMode: "query", AuthenticatedAt: f.now,
			SessionIdentifier: "sess_" + fake.LetterN(8), AcrLevel: "1", AuthMethods: "pwd", Used: true,
		}
		if err := database.CreateCode(context.Background(), nil, code); err != nil {
			f.t.Fatalf("Failed to create code: %v", err)
		}
		rt.CodeId = sql.NullInt64{Int64: code.Id, Valid: true}
	} else {
		rt.UserId = sql.NullInt64{Int64: token.owner.Id, Valid: true}
		rt.ClientId = sql.NullInt64{Int64: token.client.Id, Valid: true}
	}
	if err := database.CreateRefreshToken(context.Background(), nil, rt); err != nil {
		f.t.Fatalf("Failed to create refresh token: %v", err)
	}
	if token.familyRecorded {
		if _, err := database.RecordRefreshTokenFamilyRevoked(context.Background(), nil, firstJti, "test"); err != nil {
			f.t.Fatalf("Failed to record the family: %v", err)
		}
	}
	return rt.Id
}

// sortedLiveGrants orders the rows by refresh token id, so two reads compare as lists.
func sortedLiveGrants(grants []record.LiveGrant) []record.LiveGrant {
	sorted := append([]record.LiveGrant(nil), grants...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RefreshTokenId < sorted[j].RefreshTokenId })
	return sorted
}

// TestGetLiveGrantsByUserId: one row for each live refresh token a user holds, naming its client
// and the scope it records, through either linkage shape: the code's client for an
// authorization-code token, the token's own for a password grant. A live token is one whose row is
// not revoked, whose expiry is set and after the instant, and whose rotation family has no
// revocation record (#135 decision 4). Another user's tokens are not the user's.
func TestGetLiveGrantsByUserId(t *testing.T) {
	user := createTestUser(t)
	otherUser := createTestUser(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := liveGrantFixture{t: t, now: now}
	later := now.Add(time.Hour)
	earlier := now.Add(-time.Minute)

	viaCode := createTestClient(t)
	direct := createTestClient(t)
	twoGrants := createTestClient(t)
	revoked := createTestClient(t)
	expired := createTestClient(t)
	noExpiry := createTestClient(t)
	recorded := createTestClient(t)
	othersOnly := createTestClient(t)

	viaCodeId := f.write(liveGrantToken{owner: user, client: viaCode, viaCode: true, scope: "openid profile", expiresAt: &later})
	directId := f.write(liveGrantToken{owner: user, client: direct, scope: "openid email", expiresAt: &later})
	twoGrantsCodeId := f.write(liveGrantToken{owner: user, client: twoGrants, viaCode: true, scope: "openid", expiresAt: &later})
	twoGrantsDirectId := f.write(liveGrantToken{owner: user, client: twoGrants, scope: "openid offline_access", expiresAt: &later})
	for _, viaCodeShape := range []bool{true, false} {
		f.write(liveGrantToken{owner: user, client: revoked, viaCode: viaCodeShape, scope: "openid", revoked: true, expiresAt: &later})
		f.write(liveGrantToken{owner: user, client: expired, viaCode: viaCodeShape, scope: "openid", expiresAt: &earlier})
		f.write(liveGrantToken{owner: user, client: noExpiry, viaCode: viaCodeShape, scope: "openid"})
		f.write(liveGrantToken{owner: user, client: recorded, viaCode: viaCodeShape, scope: "openid", expiresAt: &later, familyRecorded: true})
		f.write(liveGrantToken{owner: otherUser, client: othersOnly, viaCode: viaCodeShape, scope: "openid", expiresAt: &later})
	}

	want := sortedLiveGrants([]record.LiveGrant{
		{RefreshTokenId: viaCodeId, ClientId: viaCode.Id, Scope: "openid profile"},
		{RefreshTokenId: directId, ClientId: direct.Id, Scope: "openid email"},
		{RefreshTokenId: twoGrantsCodeId, ClientId: twoGrants.Id, Scope: "openid"},
		{RefreshTokenId: twoGrantsDirectId, ClientId: twoGrants.Id, Scope: "openid offline_access"},
	})

	got, err := database.GetLiveGrantsByUserId(context.Background(), nil, user.Id, now)
	if err != nil {
		t.Fatalf("GetLiveGrantsByUserId failed: %v", err)
	}
	assertLiveGrants(t, want, got)

	// Inside a transaction too.
	err = database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		inTx, txErr := database.GetLiveGrantsByUserId(context.Background(), tx, user.Id, now)
		if txErr != nil {
			return txErr
		}
		assertLiveGrants(t, want, inTx)
		return nil
	})
	if err != nil {
		t.Fatalf("RunInTransaction failed: %v", err)
	}

	// The instant decides expiry: judged two hours on, every token has expired.
	got, err = database.GetLiveGrantsByUserId(context.Background(), nil, user.Id, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("GetLiveGrantsByUserId failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no live grant once every token expired, got %v", got)
	}

	// The other user holds the two live tokens with othersOnly, and nothing of the user's.
	got, err = database.GetLiveGrantsByUserId(context.Background(), nil, otherUser.Id, now)
	if err != nil {
		t.Fatalf("GetLiveGrantsByUserId failed: %v", err)
	}
	if len(got) != 2 || got[0].ClientId != othersOnly.Id || got[1].ClientId != othersOnly.Id {
		t.Errorf("expected the other user's two tokens with client %d, got %v", othersOnly.Id, got)
	}
}

// TestGetLiveGrantsByUserId_NoTokens: a user with no refresh token, and the zero id, hold no live
// grant.
func TestGetLiveGrantsByUserId_NoTokens(t *testing.T) {
	user := createTestUser(t)
	for _, userId := range []int64{user.Id, 0} {
		got, err := database.GetLiveGrantsByUserId(context.Background(), nil, userId, time.Now().UTC())
		if err != nil {
			t.Fatalf("GetLiveGrantsByUserId(%d) failed: %v", userId, err)
		}
		if len(got) != 0 {
			t.Errorf("expected no live grant for user %d, got %v", userId, got)
		}
	}
}

func assertLiveGrants(t *testing.T, want []record.LiveGrant, got []record.LiveGrant) {
	t.Helper()
	got = sortedLiveGrants(got)
	if len(got) != len(want) {
		t.Fatalf("expected the live grants %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("live grant %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}
}
