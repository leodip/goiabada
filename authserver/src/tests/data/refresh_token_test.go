package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/models"
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

	refreshToken.CodeId = updatedCode.Id
	refreshToken.RefreshTokenJti = "updated_jti"
	refreshToken.PreviousRefreshTokenJti = "previous_jti"
	refreshToken.FirstRefreshTokenJti = "first_jti"
	refreshToken.SessionIdentifier = "updated_session"
	refreshToken.RefreshTokenType = "updated_type"
	refreshToken.Scope = "updated_scope"
	refreshToken.IssuedAt = sql.NullTime{Time: time.Now().Add(-1 * time.Hour).Truncate(time.Microsecond), Valid: true}
	refreshToken.ExpiresAt = sql.NullTime{Time: time.Now().Add(2 * time.Hour).Truncate(time.Microsecond), Valid: true}
	refreshToken.MaxLifetime = sql.NullTime{Time: time.Now().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true}
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
		t.Errorf("Expected CodeId %d, got %d", refreshToken.CodeId, updatedRefreshToken.CodeId)
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

	if refreshToken.Code.Id != refreshToken.CodeId {
		t.Errorf("Expected loaded Code ID to match CodeId, got %d and %d", refreshToken.Code.Id, refreshToken.CodeId)
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
		CodeId:            code.Id,
		RefreshTokenJti:   gofakeit.UUID(),
		SessionIdentifier: gofakeit.UUID(),
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: time.Now().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
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
		t.Errorf("Expected CodeId %d, got %d", expected.CodeId, actual.CodeId)
	}
	if actual.RefreshTokenJti != expected.RefreshTokenJti {
		t.Errorf("Expected RefreshTokenJti %s, got %s", expected.RefreshTokenJti, actual.RefreshTokenJti)
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
