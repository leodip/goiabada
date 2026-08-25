package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateRefreshToken(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	if refreshToken.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !refreshToken.CreatedAt.Valid || refreshToken.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !refreshToken.UpdatedAt.Valid || refreshToken.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedRefreshToken, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created refresh token: %v", err)
	}

	compareRefreshTokens(t, refreshToken, retrievedRefreshToken)
}

func TestUpdateRefreshToken(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	client := createTestClient(t)
	user := createTestUser(t)
	updatedCode := createTestCode(t, client.Id, user.Id)

	refreshToken.CodeId = sql.NullInt64{Int64: updatedCode.Id, Valid: true}
	refreshToken.RefreshTokenJti = "updated_jti"
	refreshToken.PreviousRefreshTokenJti = "previous_jti"
	refreshToken.FirstRefreshTokenJti = "first_jti"
	refreshToken.SessionIdentifier = "updated_session"
	refreshToken.RefreshTokenType = "updated_type"
	refreshToken.Scope = "updated_scope"
	refreshToken.IssuedAt = sql.NullTime{Time: time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Microsecond), Valid: true}
	refreshToken.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond), Valid: true}
	refreshToken.MaxLifetime = sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true}
	refreshToken.Revoked = true

	time.Sleep(timestampTick)

	err := database.UpdateRefreshToken(nil, refreshToken)
	if err != nil {
		t.Fatalf("Failed to update refresh token: %v", err)
	}

	updatedRefreshToken, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated refresh token: %v", err)
	}

	// Compare all properties
	if updatedRefreshToken.CodeId != refreshToken.CodeId {
		t.Errorf("Expected CodeId %v, got %v", refreshToken.CodeId, updatedRefreshToken.CodeId)
	}
	if updatedRefreshToken.RefreshTokenJti != refreshToken.RefreshTokenJti {
		t.Errorf("Expected RefreshTokenJti %s, got %s", refreshToken.RefreshTokenJti, updatedRefreshToken.RefreshTokenJti)
	}
	if updatedRefreshToken.PreviousRefreshTokenJti != refreshToken.PreviousRefreshTokenJti {
		t.Errorf("Expected PreviousRefreshTokenJti %s, got %s", refreshToken.PreviousRefreshTokenJti, updatedRefreshToken.PreviousRefreshTokenJti)
	}
	if updatedRefreshToken.FirstRefreshTokenJti != refreshToken.FirstRefreshTokenJti {
		t.Errorf("Expected FirstRefreshTokenJti %s, got %s", refreshToken.FirstRefreshTokenJti, updatedRefreshToken.FirstRefreshTokenJti)
	}
	if updatedRefreshToken.SessionIdentifier != refreshToken.SessionIdentifier {
		t.Errorf("Expected SessionIdentifier %s, got %s", refreshToken.SessionIdentifier, updatedRefreshToken.SessionIdentifier)
	}
	if updatedRefreshToken.RefreshTokenType != refreshToken.RefreshTokenType {
		t.Errorf("Expected RefreshTokenType %s, got %s", refreshToken.RefreshTokenType, updatedRefreshToken.RefreshTokenType)
	}
	if updatedRefreshToken.Scope != refreshToken.Scope {
		t.Errorf("Expected Scope %s, got %s", refreshToken.Scope, updatedRefreshToken.Scope)
	}
	if !updatedRefreshToken.IssuedAt.Time.Equal(refreshToken.IssuedAt.Time) {
		t.Errorf("Expected IssuedAt %v, got %v", refreshToken.IssuedAt, updatedRefreshToken.IssuedAt)
	}
	if !updatedRefreshToken.ExpiresAt.Time.Equal(refreshToken.ExpiresAt.Time) {
		t.Errorf("Expected ExpiresAt %v, got %v", refreshToken.ExpiresAt, updatedRefreshToken.ExpiresAt)
	}
	if !updatedRefreshToken.MaxLifetime.Time.Equal(refreshToken.MaxLifetime.Time) {
		t.Errorf("Expected MaxLifetime %v, got %v", refreshToken.MaxLifetime, updatedRefreshToken.MaxLifetime)
	}
	if updatedRefreshToken.Revoked != refreshToken.Revoked {
		t.Errorf("Expected Revoked %v, got %v", refreshToken.Revoked, updatedRefreshToken.Revoked)
	}

	if !updatedRefreshToken.UpdatedAt.Time.After(updatedRefreshToken.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetRefreshTokenById(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	retrievedRefreshToken, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	if err != nil {
		t.Fatalf("Failed to get refresh token by ID: %v", err)
	}

	compareRefreshTokens(t, refreshToken, retrievedRefreshToken)

	nonExistentRefreshToken, err := database.GetRefreshTokenById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent refresh token, got: %v", err)
	}
	if nonExistentRefreshToken != nil {
		t.Errorf("Expected nil for non-existent refresh token, got a refresh token with ID: %d", nonExistentRefreshToken.Id)
	}
}

func TestRefreshTokenLoadCode(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	err := database.RefreshTokenLoadCode(nil, refreshToken)
	if err != nil {
		t.Fatalf("Failed to load code for refresh token: %v", err)
	}

	if refreshToken.Code.Id != refreshToken.CodeId.Int64 {
		t.Errorf("Expected loaded Code ID to match CodeId, got %d and %d", refreshToken.Code.Id, refreshToken.CodeId.Int64)
	}
}

func TestRefreshTokenLoadUser(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	err := database.RefreshTokenLoadUser(nil, refreshToken)
	if err != nil {
		t.Fatalf("Failed to load user for refresh token: %v", err)
	}

	if refreshToken.User.Id != refreshToken.UserId.Int64 {
		t.Errorf("Expected loaded User ID to match UserId, got %d and %d", refreshToken.User.Id, refreshToken.UserId.Int64)
	}

	// Test loading user for refresh token with nil UserId
	refreshTokenNoUser := createTestRefreshToken(t)
	refreshTokenNoUser.UserId = sql.NullInt64{Valid: false}
	err = database.UpdateRefreshToken(nil, refreshTokenNoUser)
	if err != nil {
		t.Fatalf("Failed to update refresh token: %v", err)
	}

	err = database.RefreshTokenLoadUser(nil, refreshTokenNoUser)
	if err != nil {
		t.Fatalf("Failed to load user for refresh token with nil UserId: %v", err)
	}
}

func TestRefreshTokenLoadClient(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	err := database.RefreshTokenLoadClient(nil, refreshToken)
	if err != nil {
		t.Fatalf("Failed to load client for refresh token: %v", err)
	}

	if refreshToken.Client.Id != refreshToken.ClientId.Int64 {
		t.Errorf("Expected loaded Client ID to match ClientId, got %d and %d", refreshToken.Client.Id, refreshToken.ClientId.Int64)
	}

	// Test loading client for refresh token with nil ClientId
	refreshTokenNoClient := createTestRefreshToken(t)
	refreshTokenNoClient.ClientId = sql.NullInt64{Valid: false}
	err = database.UpdateRefreshToken(nil, refreshTokenNoClient)
	if err != nil {
		t.Fatalf("Failed to update refresh token: %v", err)
	}

	err = database.RefreshTokenLoadClient(nil, refreshTokenNoClient)
	if err != nil {
		t.Fatalf("Failed to load client for refresh token with nil ClientId: %v", err)
	}
}

func TestGetRefreshTokenByJti(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	retrievedRefreshToken, err := database.GetRefreshTokenByJti(nil, refreshToken.RefreshTokenJti)
	if err != nil {
		t.Fatalf("Failed to get refresh token by JTI: %v", err)
	}

	compareRefreshTokens(t, refreshToken, retrievedRefreshToken)

	nonExistentRefreshToken, err := database.GetRefreshTokenByJti(nil, "non_existent_jti")
	if err != nil {
		t.Errorf("Expected no error for non-existent refresh token, got: %v", err)
	}
	if nonExistentRefreshToken != nil {
		t.Errorf("Expected nil for non-existent refresh token, got a refresh token with ID: %d", nonExistentRefreshToken.Id)
	}
}

func TestDeleteRefreshToken(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	err := database.DeleteRefreshToken(nil, refreshToken.Id)
	if err != nil {
		t.Fatalf("Failed to delete refresh token: %v", err)
	}

	deletedRefreshToken, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted refresh token: %v", err)
	}
	if deletedRefreshToken != nil {
		t.Errorf("Refresh token still exists after deletion")
	}

	err = database.DeleteRefreshToken(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent refresh token, got: %v", err)
	}
}

func createTestRefreshToken(t *testing.T) *models.RefreshToken {
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)
	refreshToken := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: code.Id, Valid: true},
		UserId:            sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:          sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenJti:   gofakeit.UUID(),
		SessionIdentifier: gofakeit.UUID(),
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
		Revoked:           false,
	}
	err := database.CreateRefreshToken(nil, refreshToken)
	if err != nil {
		t.Fatalf("Failed to create test refresh token: %v", err)
	}
	return refreshToken
}

func compareRefreshTokens(t *testing.T, expected, actual *models.RefreshToken) {
	if actual.Id != expected.Id {
		t.Errorf("Expected ID %d, got %d", expected.Id, actual.Id)
	}
	if actual.CodeId != expected.CodeId {
		t.Errorf("Expected CodeId %v, got %v", expected.CodeId, actual.CodeId)
	}
	if actual.UserId != expected.UserId {
		t.Errorf("Expected UserId %v, got %v", expected.UserId, actual.UserId)
	}
	if actual.ClientId != expected.ClientId {
		t.Errorf("Expected ClientId %v, got %v", expected.ClientId, actual.ClientId)
	}
	if actual.RefreshTokenJti != expected.RefreshTokenJti {
		t.Errorf("Expected RefreshTokenJti %s, got %s", expected.RefreshTokenJti, actual.RefreshTokenJti)
	}
	if actual.PreviousRefreshTokenJti != expected.PreviousRefreshTokenJti {
		t.Errorf("Expected PreviousRefreshTokenJti %s, got %s", expected.PreviousRefreshTokenJti, actual.PreviousRefreshTokenJti)
	}
	if actual.FirstRefreshTokenJti != expected.FirstRefreshTokenJti {
		t.Errorf("Expected FirstRefreshTokenJti %s, got %s", expected.FirstRefreshTokenJti, actual.FirstRefreshTokenJti)
	}
	if actual.SessionIdentifier != expected.SessionIdentifier {
		t.Errorf("Expected SessionIdentifier %s, got %s", expected.SessionIdentifier, actual.SessionIdentifier)
	}
	if actual.RefreshTokenType != expected.RefreshTokenType {
		t.Errorf("Expected RefreshTokenType %s, got %s", expected.RefreshTokenType, actual.RefreshTokenType)
	}
	if actual.Scope != expected.Scope {
		t.Errorf("Expected Scope %s, got %s", expected.Scope, actual.Scope)
	}
	if !actual.IssuedAt.Time.Equal(expected.IssuedAt.Time) {
		t.Errorf("Expected IssuedAt %v, got %v", expected.IssuedAt, actual.IssuedAt)
	}
	if !actual.ExpiresAt.Time.Equal(expected.ExpiresAt.Time) {
		t.Errorf("Expected ExpiresAt %v, got %v", expected.ExpiresAt, actual.ExpiresAt)
	}
	if !actual.MaxLifetime.Time.Equal(expected.MaxLifetime.Time) {
		t.Errorf("Expected MaxLifetime %v, got %v", expected.MaxLifetime, actual.MaxLifetime)
	}
	if actual.Revoked != expected.Revoked {
		t.Errorf("Expected Revoked %v, got %v", expected.Revoked, actual.Revoked)
	}
}

func TestGetRefreshTokensByCodeId(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	rt1 := &models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: code.Id, Valid: true},
		RefreshTokenJti:  gofakeit.UUID(),
		RefreshTokenType: "Refresh",
		Scope:            "openid",
		IssuedAt:         sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, rt1); err != nil {
		t.Fatalf("Failed to create rt1: %v", err)
	}

	rt2 := &models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: code.Id, Valid: true},
		RefreshTokenJti:  gofakeit.UUID(),
		RefreshTokenType: "Offline",
		Scope:            "openid offline_access",
		IssuedAt:         sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, rt2); err != nil {
		t.Fatalf("Failed to create rt2: %v", err)
	}

	// Unrelated refresh token under a different code (must not be returned).
	otherCode := createTestCode(t, client.Id, user.Id)
	rtOther := &models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: otherCode.Id, Valid: true},
		RefreshTokenJti:  gofakeit.UUID(),
		RefreshTokenType: "Refresh",
		Scope:            "openid",
		IssuedAt:         sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, rtOther); err != nil {
		t.Fatalf("Failed to create rtOther: %v", err)
	}

	got, err := database.GetRefreshTokensByCodeId(nil, code.Id)
	if err != nil {
		t.Fatalf("GetRefreshTokensByCodeId failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Expected 2 refresh tokens for code %d, got %d", code.Id, len(got))
	}
	seen := map[string]bool{}
	for _, rt := range got {
		seen[rt.RefreshTokenJti] = true
	}
	if !seen[rt1.RefreshTokenJti] || !seen[rt2.RefreshTokenJti] {
		t.Errorf("Expected both rt1 and rt2 to be returned, got: %v", seen)
	}

	// Unknown code id returns empty.
	gotEmpty, err := database.GetRefreshTokensByCodeId(nil, 99999999)
	if err != nil {
		t.Fatalf("GetRefreshTokensByCodeId(unknown) failed: %v", err)
	}
	if len(gotEmpty) != 0 {
		t.Errorf("Expected empty result for unknown code id, got %d", len(gotEmpty))
	}
}

func TestGetRefreshTokensBySessionIdentifier(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	sessionId := "sess_" + gofakeit.LetterN(12)

	// Two codes share the same session identifier (e.g., user federated to two clients
	// during the same SSO session, or one online + one offline exchange).
	codeA := &models.Code{
		ClientId:            client.Id,
		UserId:              user.Id,
		Code:                "code_a_" + gofakeit.LetterN(6),
		CodeHash:            "hash_a_" + gofakeit.LetterN(6),
		CodeChallenge:       sql.NullString{String: "challenge_a_" + gofakeit.LetterN(6), Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		IpAddress:           "127.0.0.1",
		UserAgent:           "test",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   sessionId,
		AcrLevel:            "1",
		AuthMethods:         "pwd",
		Used:                true,
	}
	if err := database.CreateCode(nil, codeA); err != nil {
		t.Fatalf("Failed to create codeA: %v", err)
	}

	codeB := &models.Code{
		ClientId:            client.Id,
		UserId:              user.Id,
		Code:                "code_b_" + gofakeit.LetterN(6),
		CodeHash:            "hash_b_" + gofakeit.LetterN(6),
		CodeChallenge:       sql.NullString{String: "challenge_b_" + gofakeit.LetterN(6), Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid offline_access",
		IpAddress:           "127.0.0.1",
		UserAgent:           "test",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   sessionId,
		AcrLevel:            "1",
		AuthMethods:         "pwd",
		Used:                true,
	}
	if err := database.CreateCode(nil, codeB); err != nil {
		t.Fatalf("Failed to create codeB: %v", err)
	}

	// Online refresh token (carries session_identifier on the row).
	rtOnline := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: codeA.Id, Valid: true},
		RefreshTokenJti:   gofakeit.UUID(),
		SessionIdentifier: sessionId,
		RefreshTokenType:  "Refresh",
		Scope:             "openid",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, rtOnline); err != nil {
		t.Fatalf("Failed to create rtOnline: %v", err)
	}

	// Offline refresh token (empty session_identifier on the row, but its code carries it).
	rtOffline := &models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: codeB.Id, Valid: true},
		RefreshTokenJti:  gofakeit.UUID(),
		RefreshTokenType: "Offline",
		Scope:            "openid offline_access",
		IssuedAt:         sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, rtOffline); err != nil {
		t.Fatalf("Failed to create rtOffline: %v", err)
	}

	// Unrelated refresh token under a different session must not appear.
	unrelatedCode := &models.Code{
		ClientId:            client.Id,
		UserId:              user.Id,
		Code:                "code_c_" + gofakeit.LetterN(6),
		CodeHash:            "hash_c_" + gofakeit.LetterN(6),
		CodeChallenge:       sql.NullString{String: "challenge_c_" + gofakeit.LetterN(6), Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		IpAddress:           "127.0.0.1",
		UserAgent:           "test",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   "different_" + gofakeit.LetterN(8),
		AcrLevel:            "1",
		AuthMethods:         "pwd",
		Used:                true,
	}
	if err := database.CreateCode(nil, unrelatedCode); err != nil {
		t.Fatalf("Failed to create unrelatedCode: %v", err)
	}
	rtUnrelated := &models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: unrelatedCode.Id, Valid: true},
		RefreshTokenJti:  gofakeit.UUID(),
		RefreshTokenType: "Refresh",
		Scope:            "openid",
		IssuedAt:         sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, rtUnrelated); err != nil {
		t.Fatalf("Failed to create rtUnrelated: %v", err)
	}

	got, err := database.GetRefreshTokensBySessionIdentifier(nil, sessionId)
	if err != nil {
		t.Fatalf("GetRefreshTokensBySessionIdentifier failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Expected 2 refresh tokens for session %s, got %d", sessionId, len(got))
	}
	seen := map[string]bool{}
	for _, rt := range got {
		seen[rt.RefreshTokenJti] = true
	}
	if !seen[rtOnline.RefreshTokenJti] || !seen[rtOffline.RefreshTokenJti] {
		t.Errorf("Expected both online and offline refresh tokens, got: %v", seen)
	}
	if seen[rtUnrelated.RefreshTokenJti] {
		t.Errorf("Did not expect unrelated refresh token to be returned")
	}

	// Unknown session identifier returns empty.
	gotEmpty, err := database.GetRefreshTokensBySessionIdentifier(nil, "no-such-session-"+gofakeit.LetterN(8))
	if err != nil {
		t.Fatalf("GetRefreshTokensBySessionIdentifier(unknown) failed: %v", err)
	}
	if len(gotEmpty) != 0 {
		t.Errorf("Expected empty result for unknown session, got %d", len(gotEmpty))
	}
}

func TestGetRefreshTokensBySessionIdentifier_RejectsEmpty(t *testing.T) {
	// Defends against over-revocation: if the caller passes an empty string,
	// the JOIN would otherwise match every code with an empty session_identifier.
	got, err := database.GetRefreshTokensBySessionIdentifier(nil, "")
	if err != nil {
		t.Fatalf("Expected no error for empty session identifier, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Expected empty result for empty session identifier, got %d refresh tokens", len(got))
	}
}

// TestDeleteExpiredRefreshTokens is the exhaustive table for the cleanup predicate,
// which after #128 is exactly `expires_at < now OR max_lifetime < now`. There is no
// third disjunct.
//
// TWO ROWS DELIBERATELY REVERSE THE BEHAVIOUR THIS TEST ASSERTED BEFORE, and both are
// marked below. Do not "correct" them back. Being revoked used to be a reason to delete
// a row, and that erased the replay-detection signal on the cleanup worker's schedule:
// once the row is gone a replay is refused but never detected, and its live family is
// never contained. Retention now coincides with the interval in which detection is
// possible, since an expired token is rejected by the JWT check before its row is read.
func TestDeleteExpiredRefreshTokens(t *testing.T) {
	past := sql.NullTime{Time: time.Now().UTC().Add(-1 * time.Hour), Valid: true}
	future := sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true}
	farFuture := sql.NullTime{Time: time.Now().UTC().Add(48 * time.Hour), Valid: true}
	absent := sql.NullTime{}

	testCases := []struct {
		name        string
		revoked     bool
		expiresAt   sql.NullTime
		maxLifetime sql.NullTime
		wantKept    bool
		why         string
	}{
		{
			name: "revoked but unexpired", revoked: true, expiresAt: future, maxLifetime: farFuture,
			wantKept: true,
			why:      "KEEP THIS ROW: it reverses the old behaviour and is the whole of the retention change",
		},
		{
			name: "revoked and past expires_at", revoked: true, expiresAt: past, maxLifetime: farFuture,
			wantKept: false,
			why:      "expired, so no longer presentable and no longer worth retaining",
		},
		{
			name: "revoked, unexpired, past max_lifetime", revoked: true, expiresAt: future, maxLifetime: past,
			wantKept: false,
			why:      "the offline branch of the predicate",
		},
		{
			name: "live and past expires_at", revoked: false, expiresAt: past, maxLifetime: farFuture,
			wantKept: false,
			why:      "unchanged by #128",
		},
		{
			name: "live and unexpired", revoked: false, expiresAt: future, maxLifetime: farFuture,
			wantKept: true,
			why:      "unchanged by #128",
		},
		{
			name: "live, unexpired, NULL max_lifetime", revoked: false, expiresAt: future, maxLifetime: absent,
			wantKept: true,
			why:      "NULL < now must not delete a session-bound row, which never sets max_lifetime",
		},
		{
			name: "live, past expires_at, NULL max_lifetime", revoked: false, expiresAt: past, maxLifetime: absent,
			wantKept: false,
			why:      "the same NULL asymmetry in the other direction: one disjunct still matches",
		},
		{
			name: "revoked with both timestamps NULL", revoked: true, expiresAt: absent, maxLifetime: absent,
			wantKept: true,
			why: "KEEP THIS ROW: it also reverses the old behaviour. Both comparisons yield NULL, " +
				"so the sweep can never reap it. No issuer creates such a row, so it means legacy or " +
				"imported data, and the row is the detection signal: an imported row with no expiry " +
				"columns can still back a signed token with an unexpired exp. Deleting it would " +
				"recreate the exact defect retention exists to fix, and there is no principled " +
				"deletion time to compute from the row. Operator cleanup, not this sweep, removes it",
		},
	}

	ids := make([]int64, len(testCases))
	for i, tc := range testCases {
		rt := createTestRefreshToken(t)
		rt.Revoked = tc.revoked
		rt.ExpiresAt = tc.expiresAt
		rt.MaxLifetime = tc.maxLifetime
		if err := database.UpdateRefreshToken(nil, rt); err != nil {
			t.Fatalf("failed to seed %q: %v", tc.name, err)
		}
		ids[i] = rt.Id
	}

	// One sweep for the whole table: the cases must not be able to influence each other
	// through repeated deletes.
	if err := database.DeleteExpiredRefreshTokens(nil); err != nil {
		t.Fatalf("DeleteExpiredRefreshTokens failed: %v", err)
	}

	for i, tc := range testCases {
		row, err := database.GetRefreshTokenById(nil, ids[i])
		if err != nil {
			t.Fatalf("error checking %q: %v", tc.name, err)
		}
		if tc.wantKept && row == nil {
			t.Errorf("%q was deleted but must be retained (%s)", tc.name, tc.why)
		}
		if !tc.wantKept && row != nil {
			t.Errorf("%q was retained but must be deleted (%s)", tc.name, tc.why)
		}
	}
}

// TestUpdateRefreshToken_DoesNotClobberAuthStateGeneration pins decision 11(b) of
// #106 for refresh tokens. See TestUpdateUser_DoesNotClobberAuthStateGeneration for
// why the tag matters and why the value is deliberately nonzero.
//
// This is the case with the tightest race: the refresh endpoint marks the presented
// token revoked with a full-row update while a credential change may be promoting
// that same token's siblings. Without the tag, the update would write back the
// generation the model was read with.
func TestUpdateRefreshToken_DoesNotClobberAuthStateGeneration(t *testing.T) {
	refreshToken := createTestRefreshToken(t)

	refreshToken.AuthStateGeneration = 7
	refreshToken.Id = 0
	refreshToken.RefreshTokenJti = gofakeit.UUID()
	if err := database.CreateRefreshToken(nil, refreshToken); err != nil {
		t.Fatalf("Failed to create refresh token with a generation: %v", err)
	}

	created, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	if err != nil {
		t.Fatalf("Failed to reload created refresh token: %v", err)
	}
	if created.AuthStateGeneration != 7 {
		t.Fatalf("CreateRefreshToken must persist auth_state_generation, got %d want 7",
			created.AuthStateGeneration)
	}

	created.AuthStateGeneration = 0
	created.Revoked = true
	if err := database.UpdateRefreshToken(nil, created); err != nil {
		t.Fatalf("Failed to update refresh token: %v", err)
	}

	after, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	if err != nil {
		t.Fatalf("Failed to reload updated refresh token: %v", err)
	}
	if after.AuthStateGeneration != 7 {
		t.Errorf("UpdateRefreshToken regressed auth_state_generation to %d, want 7 (is the dont-update tag missing?)",
			after.AuthStateGeneration)
	}
	if !after.Revoked {
		t.Error("the rest of the update must still apply, Revoked = false")
	}
}

// TestGetRefreshTokensByUserId is the exhaustive owner of this query's linkage-shape
// coverage (#106 decision 1). Later stages test their consumers thinly and say so.
//
// The shapes exist because a refresh token reaches its user two different ways: through
// codes.user_id for the authorization code flow, and directly through
// refresh_tokens.user_id for ROPC, where there is no code at all. The query is two
// UNION ALL branches over those two columns, so every shape below has to be enumerated
// or a whole class of token escapes revocation.
//
// The row that matters most is the offline token whose session row has been DELETED.
// That is the stolen-laptop case: at seeded defaults a session is reaped after two hours
// while an offline refresh token lives a year, so it is the normal resting state of an
// offline grant rather than an edge case, and it is exactly what the issue's own
// session-walk proposal could not reach.
func TestGetRefreshTokensByUserId(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	otherUser := createTestUser(t)

	newCode := func(sessionId string) *models.Code {
		code := &models.Code{
			ClientId:            client.Id,
			UserId:              user.Id,
			Code:                "code_" + gofakeit.LetterN(8),
			CodeHash:            "hash_" + gofakeit.LetterN(8),
			CodeChallenge:       sql.NullString{String: "chal_" + gofakeit.LetterN(8), Valid: true},
			CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
			RedirectURI:         "https://example.com/callback",
			Scope:               "openid",
			IpAddress:           "127.0.0.1",
			UserAgent:           "test",
			ResponseMode:        "query",
			AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
			SessionIdentifier:   sessionId,
			AcrLevel:            "1",
			AuthMethods:         "pwd",
			Used:                true,
		}
		if err := database.CreateCode(nil, code); err != nil {
			t.Fatalf("Failed to create code: %v", err)
		}
		return code
	}

	newToken := func(rt *models.RefreshToken) *models.RefreshToken {
		rt.RefreshTokenJti = gofakeit.UUID()
		rt.Scope = "openid"
		rt.IssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
		rt.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true}
		if err := database.CreateRefreshToken(nil, rt); err != nil {
			t.Fatalf("Failed to create refresh token: %v", err)
		}
		return rt
	}

	// Shape 1: session-bound, session still alive.
	liveSession := createTestUserSession(t, user.Id)
	boundCode := newCode(liveSession.SessionIdentifier)
	sessionBound := newToken(&models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: boundCode.Id, Valid: true},
		SessionIdentifier: liveSession.SessionIdentifier,
		RefreshTokenType:  "Refresh",
	})

	// Shape 2: offline, session still alive. Offline rows carry no session identifier of
	// their own; theirs lives on the code.
	offlineLiveCode := newCode(liveSession.SessionIdentifier)
	offlineLive := newToken(&models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: offlineLiveCode.Id, Valid: true},
		RefreshTokenType: "Offline",
		MaxLifetime:      sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	})

	// Shape 3: offline whose session row is GONE. The decisive row.
	reapedSession := createTestUserSession(t, user.Id)
	reapedCode := newCode(reapedSession.SessionIdentifier)
	offlineReaped := newToken(&models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: reapedCode.Id, Valid: true},
		RefreshTokenType: "Offline",
		MaxLifetime:      sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	})
	if err := database.DeleteUserSession(nil, reapedSession.Id); err != nil {
		t.Fatalf("Failed to delete the session being reaped: %v", err)
	}

	// Shape 4: ROPC, linked straight to the user with no code.
	ropc := newToken(&models.RefreshToken{
		UserId:           sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:         sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenType: "Offline",
		MaxLifetime:      sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	})

	// Negative: a token belonging to somebody else, in both linkage shapes. These vary
	// only the user, so neither can pass with the predicate removed.
	otherCode := &models.Code{
		ClientId: client.Id, UserId: otherUser.Id,
		Code: "code_o_" + gofakeit.LetterN(8), CodeHash: "hash_o_" + gofakeit.LetterN(8),
		CodeChallenge: sql.NullString{String: "chal_o", Valid: true}, CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI: "https://example.com/callback", Scope: "openid", IpAddress: "127.0.0.1",
		UserAgent: "test", ResponseMode: "query",
		AuthenticatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier: "sess_o_" + gofakeit.LetterN(8), AcrLevel: "1", AuthMethods: "pwd", Used: true,
	}
	if err := database.CreateCode(nil, otherCode); err != nil {
		t.Fatalf("Failed to create the other user's code: %v", err)
	}
	otherViaCode := newToken(&models.RefreshToken{
		CodeId:           sql.NullInt64{Int64: otherCode.Id, Valid: true},
		RefreshTokenType: "Refresh",
	})
	otherDirect := newToken(&models.RefreshToken{
		UserId:           sql.NullInt64{Int64: otherUser.Id, Valid: true},
		ClientId:         sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenType: "Offline",
	})

	got, err := database.GetRefreshTokensByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("GetRefreshTokensByUserId failed: %v", err)
	}

	found := make(map[int64]bool, len(got))
	for _, rt := range got {
		found[rt.Id] = true
	}

	for _, want := range []struct {
		label string
		id    int64
	}{
		{"session-bound with a live session", sessionBound.Id},
		{"offline with a live session", offlineLive.Id},
		{"offline whose session row was reaped", offlineReaped.Id},
		{"ROPC linked directly to the user", ropc.Id},
	} {
		if !found[want.id] {
			t.Errorf("missing shape: %s (id %d)", want.label, want.id)
		}
	}

	for _, unwanted := range []struct {
		label string
		id    int64
	}{
		{"another user's token via a code", otherViaCode.Id},
		{"another user's ROPC token", otherDirect.Id},
	} {
		if found[unwanted.id] {
			t.Errorf("returned a token that is not this user's: %s (id %d)", unwanted.label, unwanted.id)
		}
	}

	// The union must not double-count: an auth-code token matches only the first branch.
	if len(got) != 4 {
		t.Errorf("expected exactly 4 tokens for this user, got %d (duplicates from the UNION ALL?)", len(got))
	}
}

// TestGetRefreshTokensByUserId_NoTokens covers the empty result, and the zero-id guard.
func TestGetRefreshTokensByUserId_NoTokens(t *testing.T) {
	user := createTestUser(t)

	got, err := database.GetRefreshTokensByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("GetRefreshTokensByUserId failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no tokens for a fresh user, got %d", len(got))
	}

	got, err = database.GetRefreshTokensByUserId(nil, 0)
	if err != nil {
		t.Fatalf("GetRefreshTokensByUserId(0) should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no tokens for user id 0, got %d", len(got))
	}
}

// TestGetRefreshTokensByClientId is the exhaustive owner of this query's linkage-shape
// coverage (seam 6, #245). The confidential-to-public flip sweeps through it, so a shape
// the query cannot reach is a grant that survives the flip.
//
// The shapes exist because a refresh token reaches its client two different ways: through
// codes.client_id for the authorization code flow, where refresh_tokens.client_id is left
// null, and directly through refresh_tokens.client_id for ROPC, where there is no code at
// all. The query is two UNION ALL branches over those two columns, so both have to be
// enumerated or a whole class of token escapes the sweep.
//
// The ROPC branch is not a formality here. The password arm's entire client
// authentication block sits under `if !client.IsPublic`, so a public client can use ROPC
// presenting nothing at all, and its tokens carry no code for the marker to reach.
func TestGetRefreshTokensByClientId(t *testing.T) {
	client := createTestClient(t)
	otherClient := createTestClient(t)
	user := createTestUser(t)

	newToken := func(rt *models.RefreshToken) *models.RefreshToken {
		rt.RefreshTokenJti = gofakeit.UUID()
		rt.Scope = "openid"
		rt.IssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
		rt.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true}
		if err := database.CreateRefreshToken(nil, rt); err != nil {
			t.Fatalf("Failed to create refresh token: %v", err)
		}
		return rt
	}

	// Shape 1: authorization code flow. The client is on the code; generateRefreshToken
	// writes code_id and leaves the token's own client_id null.
	code := createTestCode(t, client.Id, user.Id)
	viaCode := newToken(&models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: code.Id, Valid: true},
		SessionIdentifier: code.SessionIdentifier,
		RefreshTokenType:  "Refresh",
	})

	// Shape 2: ROPC. generateRefreshTokenForROPC does the reverse, writing user_id and
	// client_id straight onto the token with no code at all.
	ropc := newToken(&models.RefreshToken{
		UserId:           sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:         sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenType: "Offline",
		MaxLifetime:      sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	})

	// Negatives: the same two shapes for a different client. Each varies only the
	// client, so neither can pass with its branch's predicate removed.
	otherCode := createTestCode(t, otherClient.Id, user.Id)
	otherViaCode := newToken(&models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: otherCode.Id, Valid: true},
		SessionIdentifier: otherCode.SessionIdentifier,
		RefreshTokenType:  "Refresh",
	})
	otherRopc := newToken(&models.RefreshToken{
		UserId:           sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:         sql.NullInt64{Int64: otherClient.Id, Valid: true},
		RefreshTokenType: "Offline",
		MaxLifetime:      sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	})

	got, err := database.GetRefreshTokensByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("GetRefreshTokensByClientId failed: %v", err)
	}

	found := make(map[int64]bool, len(got))
	for _, rt := range got {
		found[rt.Id] = true
	}

	for _, want := range []struct {
		label string
		id    int64
	}{
		{"authorization code token reached through codes.client_id", viaCode.Id},
		{"ROPC token reached through refresh_tokens.client_id", ropc.Id},
	} {
		if !found[want.id] {
			t.Errorf("missing shape: %s (id %d)", want.label, want.id)
		}
	}

	for _, unwanted := range []struct {
		label string
		id    int64
	}{
		{"another client's token via a code", otherViaCode.Id},
		{"another client's ROPC token", otherRopc.Id},
	} {
		if found[unwanted.id] {
			t.Errorf("returned a token that is not this client's: %s (id %d)", unwanted.label, unwanted.id)
		}
	}

	// The union must not double-count. The two branches are mutually exclusive in
	// production because the issuer writes one linkage column or the other, never both,
	// so an auth-code token matches only the first branch.
	if len(got) != 2 {
		t.Errorf("expected exactly 2 tokens for this client, got %d (duplicates from the UNION ALL?)", len(got))
	}
}

// TestGetRefreshTokensByClientId_NoTokens covers the empty result, and the zero-id guard.
func TestGetRefreshTokensByClientId_NoTokens(t *testing.T) {
	client := createTestClient(t)

	got, err := database.GetRefreshTokensByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("GetRefreshTokensByClientId failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no tokens for a fresh client, got %d", len(got))
	}

	got, err = database.GetRefreshTokensByClientId(nil, 0)
	if err != nil {
		t.Fatalf("GetRefreshTokensByClientId(0) should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no tokens for client id 0, got %d", len(got))
	}
}

// TestGetRefreshTokensByClientId_TransactionAndFailurePath answers the two questions a
// mock can never answer about a new data method: does it enlist in the caller's
// transaction rather than reading through the pool, and does its failure path return an
// error rather than a benign empty slice.
//
// Both matter for the flip, which reads this inside the same transaction as the client
// write. A read through the pool would miss rows written earlier in that transaction, and
// a database fault collapsed into (nil, nil) would have the flip commit a sweep that
// revoked nothing and audit it as a success.
func TestGetRefreshTokensByClientId_TransactionAndFailurePath(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	tx := beginTx(t)

	random := gofakeit.LetterN(6)
	code := &models.Code{
		ClientId:            client.Id,
		UserId:              user.Id,
		Code:                "txcode_" + random,
		CodeHash:            "txhash_" + random,
		CodeChallenge:       sql.NullString{String: "txchal_" + random, Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		IpAddress:           "127.0.0.1",
		UserAgent:           "test",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   "txsess_" + random,
		AcrLevel:            "1",
		AuthMethods:         "pwd",
	}
	if err := database.CreateCode(tx, code); err != nil {
		t.Fatalf("CreateCode in a transaction: %v", err)
	}
	refreshToken := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: code.Id, Valid: true},
		SessionIdentifier: code.SessionIdentifier,
		RefreshTokenJti:   gofakeit.UUID(),
		RefreshTokenType:  "Refresh",
		Scope:             "openid",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	if err := database.CreateRefreshToken(tx, refreshToken); err != nil {
		t.Fatalf("CreateRefreshToken in a transaction: %v", err)
	}

	// Neither row is committed, so only a query enlisted in this transaction can see
	// them. A query through the pool returns nothing here.
	got, err := database.GetRefreshTokensByClientId(tx, client.Id)
	if err != nil {
		t.Fatalf("GetRefreshTokensByClientId in a transaction returned error: %v", err)
	}
	if len(got) != 1 || got[0].Id != refreshToken.Id {
		t.Fatalf("expected the transaction's own uncommitted token, got %d rows", len(got))
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("RollbackTransaction: %v", err)
	}

	// The failure path, forced by the same finished transaction.
	got, err = database.GetRefreshTokensByClientId(tx, client.Id)
	if err == nil {
		t.Error("a query that cannot run must return an error, not a benign empty slice")
	}
	if len(got) != 0 {
		t.Errorf("a failed call must return no rows, got %d", len(got))
	}
}

// TestPromoteRefreshTokenGenerations checks that promotion touches only the named rows,
// skips already-revoked ones, and treats an empty id list as a no-op.
//
// The empty-list row is not a formality: an empty IN () is a syntax error on some engines
// and matches every row on others, so without the guard this would either fail loudly or
// silently promote the entire table.
func TestPromoteRefreshTokenGenerations(t *testing.T) {
	named := createTestRefreshToken(t)
	unnamed := createTestRefreshToken(t)
	revoked := createTestRefreshToken(t)

	revoked.Revoked = true
	if err := database.UpdateRefreshToken(nil, revoked); err != nil {
		t.Fatalf("Failed to revoke a token: %v", err)
	}

	if err := database.PromoteRefreshTokenGenerations(nil, []int64{named.Id, revoked.Id}, 7); err != nil {
		t.Fatalf("PromoteRefreshTokenGenerations failed: %v", err)
	}

	reload := func(id int64) *models.RefreshToken {
		rt, err := database.GetRefreshTokenById(nil, id)
		if err != nil {
			t.Fatalf("Failed to reload refresh token %d: %v", id, err)
		}
		return rt
	}

	if got := reload(named.Id).AuthStateGeneration; got != 7 {
		t.Errorf("named token generation = %d, want 7", got)
	}
	if got := reload(unnamed.Id).AuthStateGeneration; got != 0 {
		t.Errorf("unnamed token generation = %d, want 0 (promotion must not touch it)", got)
	}
	if got := reload(revoked.Id).AuthStateGeneration; got != 0 {
		t.Errorf("revoked token generation = %d, want 0 (already-revoked tokens are skipped)", got)
	}

	// Empty list: no error, and nothing changes.
	if err := database.PromoteRefreshTokenGenerations(nil, nil, 9); err != nil {
		t.Fatalf("PromoteRefreshTokenGenerations with an empty list must be a no-op, got: %v", err)
	}
	if got := reload(unnamed.Id).AuthStateGeneration; got != 0 {
		t.Errorf("after an empty promotion, unnamed generation = %d, want 0", got)
	}
}

// TestMarkRefreshTokenAsRevoked pins the compare-and-set that makes refresh token
// single use atomic (#128). Modelled on TestMarkCodeAsUsed, which guards the same
// shape of race on authorization codes (#77).
func TestMarkRefreshTokenAsRevoked(t *testing.T) {
	rt := createTestRefreshToken(t)

	// Sanity: a freshly created refresh token is live.
	if rt.Revoked {
		t.Fatalf("expected a freshly created refresh token to be live")
	}

	// First claim wins: the compare-and-set flips revoked=false -> true.
	claimed, err := database.MarkRefreshTokenAsRevoked(nil, rt.Id)
	if err != nil {
		t.Fatalf("first MarkRefreshTokenAsRevoked returned error: %v", err)
	}
	if !claimed {
		t.Fatalf("first MarkRefreshTokenAsRevoked should claim the token, got claimed=false")
	}

	reloaded, err := database.GetRefreshTokenById(nil, rt.Id)
	if err != nil {
		t.Fatalf("failed to reload refresh token: %v", err)
	}
	if !reloaded.Revoked {
		t.Errorf("expected the refresh token to be revoked after a successful claim")
	}

	// Second claim loses: the WHERE revoked=false predicate no longer matches. This
	// is what stops two concurrent presentations of one refresh token from each
	// minting a token set.
	claimed, err = database.MarkRefreshTokenAsRevoked(nil, rt.Id)
	if err != nil {
		t.Fatalf("second MarkRefreshTokenAsRevoked returned error: %v", err)
	}
	if claimed {
		t.Errorf("second MarkRefreshTokenAsRevoked must not claim an already-revoked token, got claimed=true")
	}

	// A token revoked by some OTHER path also loses. Same predicate miss, but
	// reached without this method having run at all, which is the case a security
	// revocation or a family cascade produces.
	other := createTestRefreshToken(t)
	other.Revoked = true
	if err := database.UpdateRefreshToken(nil, other); err != nil {
		t.Fatalf("failed to revoke a token by another path: %v", err)
	}
	claimed, err = database.MarkRefreshTokenAsRevoked(nil, other.Id)
	if err != nil {
		t.Fatalf("MarkRefreshTokenAsRevoked on an externally revoked token returned error: %v", err)
	}
	if claimed {
		t.Errorf("MarkRefreshTokenAsRevoked must not claim a token revoked elsewhere, got claimed=true")
	}

	// A non-existent id affects zero rows: claimed=false, and no error. Reporting it
	// as an error would make a deleted row indistinguishable from a broken query.
	claimed, err = database.MarkRefreshTokenAsRevoked(nil, 999999999)
	if err != nil {
		t.Fatalf("MarkRefreshTokenAsRevoked for a missing token returned error: %v", err)
	}
	if claimed {
		t.Errorf("MarkRefreshTokenAsRevoked for a non-existent id must return claimed=false")
	}

	// Guard: id 0 is rejected outright, and must be an ERROR rather than
	// claimed=false. The bare SQL affects zero rows for id 0, so asserting false here
	// would pass with the guard deleted and would be indistinguishable from the
	// missing-id case above. The guard is the only thing under test.
	_, err = database.MarkRefreshTokenAsRevoked(nil, 0)
	if err == nil {
		t.Errorf("MarkRefreshTokenAsRevoked(0) must return an error")
	}
}

// TestMarkRefreshTokenAsRevoked_DoesNotClobberAuthStateGeneration pins that the
// compare-and-set writes only revoked and updated_at.
//
// It does NOT show that rewriting this as UpdateRefreshToken would regress the column:
// that path already excludes auth_state_generation through the field's dont-update tag,
// and TestUpdateRefreshToken_DoesNotClobberAuthStateGeneration covers it. This is an
// independent contract for the narrow writer, so the boundary holds without depending
// on struct tags a future full-row writer might not honour (#106).
func TestMarkRefreshTokenAsRevoked_DoesNotClobberAuthStateGeneration(t *testing.T) {
	rt := createTestRefreshToken(t)

	if err := database.PromoteRefreshTokenGenerations(nil, []int64{rt.Id}, 5); err != nil {
		t.Fatalf("failed to set the token's generation: %v", err)
	}

	claimed, err := database.MarkRefreshTokenAsRevoked(nil, rt.Id)
	if err != nil {
		t.Fatalf("MarkRefreshTokenAsRevoked returned error: %v", err)
	}
	if !claimed {
		t.Fatalf("expected to claim a live token")
	}

	reloaded, err := database.GetRefreshTokenById(nil, rt.Id)
	if err != nil {
		t.Fatalf("failed to reload refresh token: %v", err)
	}
	if reloaded.AuthStateGeneration != 5 {
		t.Errorf("auth_state_generation = %d after the claim, want 5 (the claim must not touch it)",
			reloaded.AuthStateGeneration)
	}
	if !reloaded.Revoked {
		t.Errorf("expected the token to be revoked")
	}
}

// familyTokenSpec describes one seeded member of a rotation family. A zero CodeId is
// the ROPC shape: no code at all, with the user and client on the refresh token row
// itself. That is the shape a code-scoped query would miss entirely.
type familyTokenSpec struct {
	FamilyJti         string
	CodeId            int64
	UserId            int64
	ClientId          int64
	SessionIdentifier string
	Revoked           bool
}

func seedFamilyToken(t *testing.T, spec familyTokenSpec) *models.RefreshToken {
	t.Helper()

	rt := &models.RefreshToken{
		RefreshTokenJti:      gofakeit.UUID(),
		FirstRefreshTokenJti: spec.FamilyJti,
		SessionIdentifier:    spec.SessionIdentifier,
		RefreshTokenType:     "Refresh",
		Scope:                "openid",
		IssuedAt:             sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:            sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
		Revoked:              spec.Revoked,
	}
	if spec.CodeId != 0 {
		rt.CodeId = sql.NullInt64{Int64: spec.CodeId, Valid: true}
	}
	if spec.UserId != 0 {
		rt.UserId = sql.NullInt64{Int64: spec.UserId, Valid: true}
	}
	if spec.ClientId != 0 {
		rt.ClientId = sql.NullInt64{Int64: spec.ClientId, Valid: true}
	}

	if err := database.CreateRefreshToken(nil, rt); err != nil {
		t.Fatalf("failed to seed family token: %v", err)
	}
	return rt
}

// seedCodeOnSession creates a used authorization code bound to a chosen session
// identifier, so a test can put two independent families on one browser session.
// createTestCode generates its own session identifier and cannot express that.
func seedCodeOnSession(t *testing.T, clientId, userId int64, sessionIdentifier string) *models.Code {
	t.Helper()

	random := gofakeit.LetterN(6)
	code := &models.Code{
		ClientId:            clientId,
		UserId:              userId,
		Code:                "famcode_" + random,
		CodeHash:            "famhash_" + random,
		CodeChallenge:       sql.NullString{String: "famchallenge_" + random, Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		IpAddress:           "127.0.0.1",
		UserAgent:           "test",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   sessionIdentifier,
		AcrLevel:            "1",
		AuthMethods:         "pwd",
		Used:                true,
	}
	if err := database.CreateCode(nil, code); err != nil {
		t.Fatalf("failed to create code on session %s: %v", sessionIdentifier, err)
	}
	return code
}

// refreshTokenIsRevoked reloads a row and reports its revoked flag.
func refreshTokenIsRevoked(t *testing.T, id int64) bool {
	t.Helper()
	rt, err := database.GetRefreshTokenById(nil, id)
	if err != nil {
		t.Fatalf("failed to reload refresh token %d: %v", id, err)
	}
	if rt == nil {
		t.Fatalf("refresh token %d disappeared", id)
	}
	return rt.Revoked
}

// TestRevokeRefreshTokenFamily is the exhaustive owner of the family predicate's
// semantics (#128). The handler tests in later stages are deliberately thin on it and
// assert only that the handler calls it and branches on the returned count.
func TestRevokeRefreshTokenFamily(t *testing.T) {

	t.Run("retired parent and live child", func(t *testing.T) {
		client := createTestClient(t)
		user := createTestUser(t)
		code := createTestCode(t, client.Id, user.Id)
		family := gofakeit.UUID()

		parent := seedFamilyToken(t, familyTokenSpec{FamilyJti: family, CodeId: code.Id, Revoked: true})
		child := seedFamilyToken(t, familyTokenSpec{FamilyJti: family, CodeId: code.Id})

		count, err := database.RevokeRefreshTokenFamily(nil, family)
		if err != nil {
			t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d, want 1 (only the live child transitions)", count)
		}
		if !refreshTokenIsRevoked(t, child.Id) {
			t.Errorf("the live child must be revoked")
		}
		if !refreshTokenIsRevoked(t, parent.Id) {
			t.Errorf("the already-revoked parent must stay revoked")
		}
	})

	t.Run("forked family with two live children", func(t *testing.T) {
		// The fork defect 1 can currently produce: one parent, two children minted
		// from it. Containment has to cover every branch, not just the newest.
		client := createTestClient(t)
		user := createTestUser(t)
		code := createTestCode(t, client.Id, user.Id)
		family := gofakeit.UUID()

		seedFamilyToken(t, familyTokenSpec{FamilyJti: family, CodeId: code.Id, Revoked: true})
		childA := seedFamilyToken(t, familyTokenSpec{FamilyJti: family, CodeId: code.Id})
		childB := seedFamilyToken(t, familyTokenSpec{FamilyJti: family, CodeId: code.Id})

		count, err := database.RevokeRefreshTokenFamily(nil, family)
		if err != nil {
			t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
		}
		if count != 2 {
			t.Errorf("count = %d, want 2 (both forked children transition)", count)
		}
		if !refreshTokenIsRevoked(t, childA.Id) || !refreshTokenIsRevoked(t, childB.Id) {
			t.Errorf("both forked children must be revoked")
		}
	})

	t.Run("family already fully revoked", func(t *testing.T) {
		// The zero-count case the audit gate reads as "nothing to contain": an
		// idempotent no-op, not an incident.
		client := createTestClient(t)
		user := createTestUser(t)
		code := createTestCode(t, client.Id, user.Id)
		family := gofakeit.UUID()

		seedFamilyToken(t, familyTokenSpec{FamilyJti: family, CodeId: code.Id, Revoked: true})
		seedFamilyToken(t, familyTokenSpec{FamilyJti: family, CodeId: code.Id, Revoked: true})

		count, err := database.RevokeRefreshTokenFamily(nil, family)
		if err != nil {
			t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
		}
		if count != 0 {
			t.Errorf("count = %d, want 0 (nothing left to transition)", count)
		}
	})

	t.Run("unknown family identifier", func(t *testing.T) {
		client := createTestClient(t)
		user := createTestUser(t)
		code := createTestCode(t, client.Id, user.Id)

		bystander := seedFamilyToken(t, familyTokenSpec{FamilyJti: gofakeit.UUID(), CodeId: code.Id})

		count, err := database.RevokeRefreshTokenFamily(nil, "no-such-family-"+gofakeit.UUID())
		if err != nil {
			t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
		}
		if count != 0 {
			t.Errorf("count = %d, want 0 for an unknown family", count)
		}
		if refreshTokenIsRevoked(t, bystander.Id) {
			t.Errorf("an unrelated live token must not be revoked: the predicate is not a match-all")
		}
	})

	t.Run("two families on one browser session", func(t *testing.T) {
		// Decision 3: containment is family-scoped, not session-scoped. Revoking
		// family A must leave family B untouched even though both descend from codes
		// carrying the same session identifier, which is what a user federated to two
		// clients in one SSO session looks like.
		client := createTestClient(t)
		user := createTestUser(t)
		sessionId := "sess_" + gofakeit.LetterN(12)
		codeA := seedCodeOnSession(t, client.Id, user.Id, sessionId)
		codeB := seedCodeOnSession(t, client.Id, user.Id, sessionId)

		familyA := gofakeit.UUID()
		familyB := gofakeit.UUID()

		seedFamilyToken(t, familyTokenSpec{
			FamilyJti: familyA, CodeId: codeA.Id, SessionIdentifier: sessionId, Revoked: true})
		childA := seedFamilyToken(t, familyTokenSpec{
			FamilyJti: familyA, CodeId: codeA.Id, SessionIdentifier: sessionId})

		parentB := seedFamilyToken(t, familyTokenSpec{
			FamilyJti: familyB, CodeId: codeB.Id, SessionIdentifier: sessionId})
		childB := seedFamilyToken(t, familyTokenSpec{
			FamilyJti: familyB, CodeId: codeB.Id, SessionIdentifier: sessionId})

		count, err := database.RevokeRefreshTokenFamily(nil, familyA)
		if err != nil {
			t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d, want 1 (only family A's live member)", count)
		}
		if !refreshTokenIsRevoked(t, childA.Id) {
			t.Errorf("family A's live member must be revoked")
		}
		if refreshTokenIsRevoked(t, parentB.Id) || refreshTokenIsRevoked(t, childB.Id) {
			t.Errorf("family B shares the browser session but not the family: it must stay live")
		}
	})

	t.Run("ROPC family with no code at all", func(t *testing.T) {
		// Decision 3 again, from the other side: this is where
		// first_refresh_token_jti materially differs from code_id. A code-scoped
		// containment query would find nothing here, and the predicate must involve
		// no join for it to work.
		client := createTestClient(t)
		user := createTestUser(t)
		family := gofakeit.UUID()

		parent := seedFamilyToken(t, familyTokenSpec{
			FamilyJti: family, UserId: user.Id, ClientId: client.Id, Revoked: true})
		child := seedFamilyToken(t, familyTokenSpec{
			FamilyJti: family, UserId: user.Id, ClientId: client.Id})

		if parent.CodeId.Valid || child.CodeId.Valid {
			t.Fatalf("the ROPC fixture must leave code_id NULL")
		}

		count, err := database.RevokeRefreshTokenFamily(nil, family)
		if err != nil {
			t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d, want 1 (the live ROPC child)", count)
		}
		if !refreshTokenIsRevoked(t, child.Id) {
			t.Errorf("the live ROPC child must be revoked")
		}
	})

	t.Run("empty family identifier is an error", func(t *testing.T) {
		// The trap this row exists for: no production row carries an empty
		// first_refresh_token_jti, so asserting "revokes nothing" would be the benign
		// instance of the class and would pass with the guard deleted. Confirmed by
		// deleting the guard and re-running: the statement revoked the seeded row and
		// returned a nonzero count. So the assertion has to be the ERROR, and the
		// fixture has to seed a LIVE row carrying an empty identifier for the
		// assertion to have anything to protect.
		client := createTestClient(t)
		user := createTestUser(t)
		code := createTestCode(t, client.Id, user.Id)

		emptyFamily := seedFamilyToken(t, familyTokenSpec{FamilyJti: "", CodeId: code.Id})

		count, err := database.RevokeRefreshTokenFamily(nil, "")
		if err == nil {
			t.Errorf("RevokeRefreshTokenFamily(\"\") must return an error, got count=%d", count)
		}
		if refreshTokenIsRevoked(t, emptyFamily.Id) {
			t.Errorf("a live row with an empty family identifier must not be revoked")
		}
	})
}
