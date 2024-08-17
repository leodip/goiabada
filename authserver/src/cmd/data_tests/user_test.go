package datatests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func createTestUser(t *testing.T) *models.User {
	random := gofakeit.LetterN(6)
	user := &models.User{
		Username: "test_user_" + random,
		Subject:  uuid.New(),
		Email:    gofakeit.Email(),
	}
	err := database.CreateUser(nil, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	return user
}
