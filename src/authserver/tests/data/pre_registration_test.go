package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
)

func TestCreatePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	if preReg.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !preReg.CreatedAt.Valid || preReg.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !preReg.UpdatedAt.Valid || preReg.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created pre-registration: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)
}

func TestUpdatePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	preReg.Email = "updated_" + gofakeit.Email()
	preReg.PasswordHash = gofakeit.Password(true, true, true, true, false, 16)
	preReg.VerificationCodeEncrypted = []byte(gofakeit.UUID())
	preReg.VerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}

	time.Sleep(time.Millisecond * 100)

	err := database.UpdatePreRegistration(nil, preReg)
	if err != nil {
		t.Fatalf("Failed to update pre-registration: %v", err)
	}

	updatedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated pre-registration: %v", err)
	}

	validatePreRegistration(t, preReg, updatedPreReg)

	if !updatedPreReg.UpdatedAt.Time.After(updatedPreReg.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetPreRegistrationById(t *testing.T) {
	preReg := createTestPreRegistration(t)

	retrievedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to get pre-registration by ID: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)

	nonExistentPreReg, err := database.GetPreRegistrationById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent pre-registration, got: %v", err)
	}
	if nonExistentPreReg != nil {
		t.Errorf("Expected nil for non-existent pre-registration, got a pre-registration with ID: %d", nonExistentPreReg.Id)
	}
}

func TestGetPreRegistrationByEmail(t *testing.T) {
	preReg := createTestPreRegistration(t)

	retrievedPreReg, err := database.GetPreRegistrationByEmail(nil, preReg.Email)
	if err != nil {
		t.Fatalf("Failed to get pre-registration by email: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)

	nonExistentPreReg, err := database.GetPreRegistrationByEmail(nil, "non_existent_email@example.com")
	if err != nil {
		t.Errorf("Expected no error for non-existent pre-registration, got: %v", err)
	}
	if nonExistentPreReg != nil {
		t.Errorf("Expected nil for non-existent pre-registration, got a pre-registration with ID: %d", nonExistentPreReg.Id)
	}
}

func TestDeletePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	err := database.DeletePreRegistration(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to delete pre-registration: %v", err)
	}

	deletedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted pre-registration: %v", err)
	}
	if deletedPreReg != nil {
		t.Errorf("Pre-registration still exists after deletion")
	}

	err = database.DeletePreRegistration(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent pre-registration, got: %v", err)
	}
}

func createTestPreRegistration(t *testing.T) *models.PreRegistration {
	preReg := &models.PreRegistration{
		Email:                     gofakeit.Email(),
		PasswordHash:              gofakeit.Password(true, true, true, true, false, 16),
		VerificationCodeEncrypted: []byte(gofakeit.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
	}
	err := database.CreatePreRegistration(nil, preReg)
	if err != nil {
		t.Fatalf("Failed to create test pre-registration: %v", err)
	}
	return preReg
}

func validatePreRegistration(t *testing.T, expected, actual *models.PreRegistration) {
	if actual.Id != expected.Id {
		t.Errorf("Expected ID %d, got %d", expected.Id, actual.Id)
	}
	if actual.Email != expected.Email {
		t.Errorf("Expected Email %s, got %s", expected.Email, actual.Email)
	}
	if actual.PasswordHash != expected.PasswordHash {
		t.Errorf("Expected PasswordHash %s, got %s", expected.PasswordHash, actual.PasswordHash)
	}
	if string(actual.VerificationCodeEncrypted) != string(expected.VerificationCodeEncrypted) {
		t.Errorf("Expected VerificationCodeEncrypted %v, got %v", expected.VerificationCodeEncrypted, actual.VerificationCodeEncrypted)
	}
	if !actual.VerificationCodeIssuedAt.Time.Equal(expected.VerificationCodeIssuedAt.Time) {
		t.Errorf("Expected VerificationCodeIssuedAt %v, got %v", expected.VerificationCodeIssuedAt, actual.VerificationCodeIssuedAt)
	}
}
