package integrationtests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a test group with unique identifier
func createTestGroupUnique(t *testing.T) *models.Group {
	group := &models.Group{
		GroupIdentifier:      "test-group-" + gofakeit.LetterN(8),
		Description:          "Test group description",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(nil, group)
	assert.NoError(t, err)
	return group
}