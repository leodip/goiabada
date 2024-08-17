package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateHttpSession(t *testing.T) {
	httpSession := &models.HttpSession{
		Data:      "test_session_data",
		ExpiresOn: sql.NullTime{Time: time.Now().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	}

	err := database.CreateHttpSession(nil, httpSession)
	if err != nil {
		t.Fatalf("Failed to create HTTP session: %v", err)
	}

	if httpSession.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !httpSession.CreatedAt.Valid || httpSession.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !httpSession.UpdatedAt.Valid || httpSession.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedSession, err := database.GetHttpSessionById(nil, httpSession.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created HTTP session: %v", err)
	}

	if retrievedSession.Data != httpSession.Data {
		t.Errorf("Expected Data %s, got %s", httpSession.Data, retrievedSession.Data)
	}
	if !retrievedSession.ExpiresOn.Time.Equal(httpSession.ExpiresOn.Time) {
		t.Errorf("Expected ExpiresOn %v, got %v", httpSession.ExpiresOn, retrievedSession.ExpiresOn)
	}
}

func TestUpdateHttpSession(t *testing.T) {
	httpSession := createTestHttpSession(t)

	httpSession.Data = "updated_session_data"
	httpSession.ExpiresOn = sql.NullTime{Time: time.Now().Add(48 * time.Hour).Truncate(time.Microsecond), Valid: true}

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateHttpSession(nil, httpSession)
	if err != nil {
		t.Fatalf("Failed to update HTTP session: %v", err)
	}

	updatedSession, err := database.GetHttpSessionById(nil, httpSession.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated HTTP session: %v", err)
	}

	if updatedSession.Data != httpSession.Data {
		t.Errorf("Expected Data %s, got %s", httpSession.Data, updatedSession.Data)
	}
	if !updatedSession.ExpiresOn.Time.Equal(httpSession.ExpiresOn.Time) {
		t.Errorf("Expected ExpiresOn %v, got %v", httpSession.ExpiresOn, updatedSession.ExpiresOn)
	}
	if !updatedSession.UpdatedAt.Time.After(updatedSession.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetHttpSessionById(t *testing.T) {
	httpSession := createTestHttpSession(t)

	retrievedSession, err := database.GetHttpSessionById(nil, httpSession.Id)
	if err != nil {
		t.Fatalf("Failed to get HTTP session by ID: %v", err)
	}

	if retrievedSession.Id != httpSession.Id {
		t.Errorf("Expected ID %d, got %d", httpSession.Id, retrievedSession.Id)
	}
	if retrievedSession.Data != httpSession.Data {
		t.Errorf("Expected Data %s, got %s", httpSession.Data, retrievedSession.Data)
	}

	nonExistentSession, err := database.GetHttpSessionById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent session, got: %v", err)
	}
	if nonExistentSession != nil {
		t.Errorf("Expected nil for non-existent session, got a session with ID: %d", nonExistentSession.Id)
	}
}

func TestDeleteHttpSession(t *testing.T) {
	httpSession := createTestHttpSession(t)

	err := database.DeleteHttpSession(nil, httpSession.Id)
	if err != nil {
		t.Fatalf("Failed to delete HTTP session: %v", err)
	}

	deletedSession, err := database.GetHttpSessionById(nil, httpSession.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted HTTP session: %v", err)
	}
	if deletedSession != nil {
		t.Errorf("HTTP session still exists after deletion")
	}

	err = database.DeleteHttpSession(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent HTTP session, got: %v", err)
	}
}

func TestDeleteHttpSessionExpired(t *testing.T) {
	expiredSession := createTestHttpSession(t)
	expiredSession.ExpiresOn = sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true}
	database.UpdateHttpSession(nil, expiredSession)

	validSession := createTestHttpSession(t)

	err := database.DeleteHttpSessionExpired(nil)
	if err != nil {
		t.Fatalf("Failed to delete expired HTTP sessions: %v", err)
	}

	_, err = database.GetHttpSessionById(nil, expiredSession.Id)
	if err != nil {
		t.Errorf("Error while checking for deleted expired session: %v", err)
	}

	validSessionAfterDelete, err := database.GetHttpSessionById(nil, validSession.Id)
	if err != nil {
		t.Fatalf("Error while checking for valid session after delete: %v", err)
	}
	if validSessionAfterDelete == nil {
		t.Error("Valid session was incorrectly deleted")
	}
}

func createTestHttpSession(t *testing.T) *models.HttpSession {
	httpSession := &models.HttpSession{
		Data:      "test_session_data",
		ExpiresOn: sql.NullTime{Time: time.Now().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	err := database.CreateHttpSession(nil, httpSession)
	if err != nil {
		t.Fatalf("Failed to create test HTTP session: %v", err)
	}
	return httpSession
}
