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

	time.Sleep(time.Millisecond * 100)

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

func TestDeleteExpiredOrRevokedRefreshTokens(t *testing.T) {
	// Create a set of test refresh tokens with different states

	// 1. Valid token (should not be deleted)
	validToken := createTestRefreshToken(t)
	validToken.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true}
	validToken.MaxLifetime = sql.NullTime{Time: time.Now().UTC().Add(48 * time.Hour), Valid: true}
	validToken.Revoked = false
	err := database.UpdateRefreshToken(nil, validToken)
	if err != nil {
		t.Fatalf("Failed to update valid token: %v", err)
	}

	// 2. Expired token based on ExpiresAt (should be deleted)
	expiredToken := createTestRefreshToken(t)
	expiredToken.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(-1 * time.Hour), Valid: true}
	expiredToken.MaxLifetime = sql.NullTime{Time: time.Now().UTC().Add(48 * time.Hour), Valid: true}
	expiredToken.Revoked = false
	err = database.UpdateRefreshToken(nil, expiredToken)
	if err != nil {
		t.Fatalf("Failed to update expired token: %v", err)
	}

	// 3. Expired token based on MaxLifetime (should be deleted)
	maxLifetimeExpiredToken := createTestRefreshToken(t)
	maxLifetimeExpiredToken.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true}
	maxLifetimeExpiredToken.MaxLifetime = sql.NullTime{Time: time.Now().UTC().Add(-1 * time.Hour), Valid: true}
	maxLifetimeExpiredToken.Revoked = false
	err = database.UpdateRefreshToken(nil, maxLifetimeExpiredToken)
	if err != nil {
		t.Fatalf("Failed to update max lifetime expired token: %v", err)
	}

	// 4. Revoked token (should be deleted)
	revokedToken := createTestRefreshToken(t)
	revokedToken.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true}
	revokedToken.MaxLifetime = sql.NullTime{Time: time.Now().UTC().Add(48 * time.Hour), Valid: true}
	revokedToken.Revoked = true
	err = database.UpdateRefreshToken(nil, revokedToken)
	if err != nil {
		t.Fatalf("Failed to update revoked token: %v", err)
	}

	// Execute the deletion
	err = database.DeleteExpiredOrRevokedRefreshTokens(nil)
	if err != nil {
		t.Fatalf("Failed to delete expired or revoked refresh tokens: %v", err)
	}

	// Verify the results

	// 1. Valid token should still exist
	validTokenCheck, err := database.GetRefreshTokenById(nil, validToken.Id)
	if err != nil {
		t.Fatalf("Error checking valid token: %v", err)
	}
	if validTokenCheck == nil {
		t.Error("Valid token was incorrectly deleted")
	}

	// 2. Expired token should be deleted
	expiredTokenCheck, err := database.GetRefreshTokenById(nil, expiredToken.Id)
	if err != nil {
		t.Fatalf("Error checking expired token: %v", err)
	}
	if expiredTokenCheck != nil {
		t.Error("Expired token was not deleted")
	}

	// 3. MaxLifetime expired token should be deleted
	maxLifetimeExpiredTokenCheck, err := database.GetRefreshTokenById(nil, maxLifetimeExpiredToken.Id)
	if err != nil {
		t.Fatalf("Error checking max lifetime expired token: %v", err)
	}
	if maxLifetimeExpiredTokenCheck != nil {
		t.Error("MaxLifetime expired token was not deleted")
	}

	// 4. Revoked token should be deleted
	revokedTokenCheck, err := database.GetRefreshTokenById(nil, revokedToken.Id)
	if err != nil {
		t.Fatalf("Error checking revoked token: %v", err)
	}
	if revokedTokenCheck != nil {
		t.Error("Revoked token was not deleted")
	}
}
