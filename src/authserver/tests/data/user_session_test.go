package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateUserSession(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)

	if userSession.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !userSession.CreatedAt.Valid || userSession.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !userSession.UpdatedAt.Valid || userSession.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedUserSession, err := database.GetUserSessionById(nil, userSession.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created user session: %v", err)
	}

	assertUserSessionEqual(t, userSession, retrievedUserSession)
}

func TestUpdateUserSession(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)

	// Update all properties
	userSession.SessionIdentifier = "updated_" + gofakeit.UUID()
	userSession.Started = time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Microsecond)
	userSession.LastAccessed = time.Now().UTC().Truncate(time.Microsecond)
	userSession.AuthMethods = "pwd,otp"
	userSession.AcrLevel = enums.AcrLevel2Optional.String()
	userSession.AuthTime = time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Microsecond)
	userSession.IpAddress = "192.168.1.2"
	userSession.DeviceName = "Updated Device"
	userSession.DeviceType = "tablet"
	userSession.DeviceOS = "iOS"
	userSession.UserId = user.Id // This shouldn't change, but we'll update it to ensure it's not accidentally modified

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateUserSession(nil, userSession)
	if err != nil {
		t.Fatalf("Failed to update user session: %v", err)
	}

	updatedUserSession, err := database.GetUserSessionById(nil, userSession.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated user session: %v", err)
	}

	assertUserSessionEqual(t, userSession, updatedUserSession)

	if !updatedUserSession.UpdatedAt.Time.After(updatedUserSession.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetUserSessionById(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)

	retrievedUserSession, err := database.GetUserSessionById(nil, userSession.Id)
	if err != nil {
		t.Fatalf("Failed to get user session by ID: %v", err)
	}

	assertUserSessionEqual(t, userSession, retrievedUserSession)

	nonExistentUserSession, err := database.GetUserSessionById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent user session, got: %v", err)
	}
	if nonExistentUserSession != nil {
		t.Errorf("Expected nil for non-existent user session, got a user session with ID: %d", nonExistentUserSession.Id)
	}
}

func TestGetUserSessionBySessionIdentifier(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)

	retrievedUserSession, err := database.GetUserSessionBySessionIdentifier(nil, userSession.SessionIdentifier)
	if err != nil {
		t.Fatalf("Failed to get user session by session identifier: %v", err)
	}

	assertUserSessionEqual(t, userSession, retrievedUserSession)

	nonExistentUserSession, err := database.GetUserSessionBySessionIdentifier(nil, "non_existent_identifier")
	if err != nil {
		t.Errorf("Expected no error for non-existent user session, got: %v", err)
	}
	if nonExistentUserSession != nil {
		t.Errorf("Expected nil for non-existent user session, got a user session with ID: %d", nonExistentUserSession.Id)
	}
}

func TestGetUserSessionsByClientIdPaginated(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	createTestUserSessionsWithClient(t, user.Id, client.Id, 25)

	// Test first page
	userSessionsPage1, total1, err := database.GetUserSessionsByClientIdPaginated(nil, client.Id, 1, 10)
	if err != nil {
		t.Fatalf("Failed to get paginated user sessions (page 1): %v", err)
	}

	if len(userSessionsPage1) != 10 {
		t.Errorf("Expected 10 user sessions on the first page, got %d", len(userSessionsPage1))
	}

	if total1 != 25 {
		t.Errorf("Expected total to be 25, got %d", total1)
	}

	// Test second page
	userSessionsPage2, total2, err := database.GetUserSessionsByClientIdPaginated(nil, client.Id, 2, 10)
	if err != nil {
		t.Fatalf("Failed to get second page of paginated user sessions: %v", err)
	}

	if len(userSessionsPage2) != 10 {
		t.Errorf("Expected 10 user sessions on the second page, got %d", len(userSessionsPage2))
	}

	if total2 != 25 {
		t.Errorf("Expected total to be 25, got %d", total2)
	}

	// Test last page
	userSessionsPage3, total3, err := database.GetUserSessionsByClientIdPaginated(nil, client.Id, 3, 10)
	if err != nil {
		t.Fatalf("Failed to get last page of paginated user sessions: %v", err)
	}

	if len(userSessionsPage3) != 5 {
		t.Errorf("Expected 5 user sessions on the last page, got %d", len(userSessionsPage3))
	}

	if total3 != 25 {
		t.Errorf("Expected total to be 25, got %d", total3)
	}

	// Test page beyond total
	userSessionsPage4, total4, err := database.GetUserSessionsByClientIdPaginated(nil, client.Id, 4, 10)
	if err != nil {
		t.Fatalf("Failed to get page beyond total: %v", err)
	}

	if len(userSessionsPage4) != 0 {
		t.Errorf("Expected 0 user sessions on page beyond total, got %d", len(userSessionsPage4))
	}

	if total4 != 25 {
		t.Errorf("Expected total to be 25, got %d", total4)
	}

	// Validate that all returned user sessions belong to the correct client
	allReturnedSessions := append(append(userSessionsPage1, userSessionsPage2...), userSessionsPage3...)
	for _, us := range allReturnedSessions {
		if err := database.UserSessionLoadClients(nil, &us); err != nil {
			t.Fatalf("Failed to load clients for user session: %v", err)
		}
		if len(us.Clients) != 1 || us.Clients[0].ClientId != client.Id {
			t.Errorf("User session %d is not associated with the correct client", us.Id)
		}
	}
}

func TestUserSessionsLoadUsers(t *testing.T) {
	user := createTestUser(t)
	userSessions := createTestUserSessions(t, user.Id, 5)

	err := database.UserSessionsLoadUsers(nil, userSessions)
	if err != nil {
		t.Fatalf("Failed to load users for user sessions: %v", err)
	}

	for _, us := range userSessions {
		if us.User.Id != user.Id {
			t.Errorf("Expected user ID %d, got %d", user.Id, us.User.Id)
		}
	}
}

func TestUserSessionsLoadClients(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	userSessions := createTestUserSessionsWithClient(t, user.Id, client.Id, 5)

	err := database.UserSessionsLoadClients(nil, userSessions)
	if err != nil {
		t.Fatalf("Failed to load clients for user sessions: %v", err)
	}

	for _, us := range userSessions {
		if len(us.Clients) != 1 {
			t.Errorf("Expected 1 client, got %d", len(us.Clients))
		}
		if us.Clients[0].ClientId != client.Id {
			t.Errorf("Expected client ID %d, got %d", client.Id, us.Clients[0].ClientId)
		}
	}
}

func TestUserSessionLoadClients(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	userSession := createTestUserSessionWithClient(t, user.Id, client.Id)

	err := database.UserSessionLoadClients(nil, userSession)
	if err != nil {
		t.Fatalf("Failed to load clients for user session: %v", err)
	}

	if len(userSession.Clients) != 1 {
		t.Errorf("Expected 1 client, got %d", len(userSession.Clients))
	}
	if userSession.Clients[0].ClientId != client.Id {
		t.Errorf("Expected client ID %d, got %d", client.Id, userSession.Clients[0].ClientId)
	}
}

func TestUserSessionLoadUser(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)

	err := database.UserSessionLoadUser(nil, userSession)
	if err != nil {
		t.Fatalf("Failed to load user for user session: %v", err)
	}

	if userSession.User.Id != user.Id {
		t.Errorf("Expected user ID %d, got %d", user.Id, userSession.User.Id)
	}
}

func TestGetUserSessionsByUserId(t *testing.T) {
	user := createTestUser(t)
	createTestUserSessions(t, user.Id, 5)

	retrievedUserSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to get user sessions by user ID: %v", err)
	}

	if len(retrievedUserSessions) != 5 {
		t.Errorf("Expected 5 user sessions, got %d", len(retrievedUserSessions))
	}

	for _, us := range retrievedUserSessions {
		if us.UserId != user.Id {
			t.Errorf("Expected user ID %d, got %d", user.Id, us.UserId)
		}
	}
}

func TestDeleteUserSession(t *testing.T) {
	user := createTestUser(t)
	userSession := createTestUserSession(t, user.Id)

	err := database.DeleteUserSession(nil, userSession.Id)
	if err != nil {
		t.Fatalf("Failed to delete user session: %v", err)
	}

	deletedUserSession, err := database.GetUserSessionById(nil, userSession.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted user session: %v", err)
	}
	if deletedUserSession != nil {
		t.Errorf("User session still exists after deletion")
	}

	err = database.DeleteUserSession(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent user session, got: %v", err)
	}
}

func createTestUserSession(t *testing.T, userId int64) *models.UserSession {
	userSession := &models.UserSession{
		SessionIdentifier: gofakeit.UUID(),
		Started:           time.Now().UTC().Truncate(time.Microsecond),
		LastAccessed:      time.Now().UTC().Truncate(time.Microsecond),
		AuthMethods:       "pwd",
		AcrLevel:          enums.AcrLevel1.String(),
		AuthTime:          time.Now().UTC().Truncate(time.Microsecond),
		IpAddress:         gofakeit.IPv4Address(),
		DeviceName:        gofakeit.Name(),
		DeviceType:        "desktop",
		DeviceOS:          "Windows",
		UserId:            userId,
	}
	err := database.CreateUserSession(nil, userSession)
	if err != nil {
		t.Fatalf("Failed to create test user session: %v", err)
	}
	return userSession
}

func createTestUserSessions(t *testing.T, userId int64, count int) []models.UserSession {
	var userSessions []models.UserSession
	for i := 0; i < count; i++ {
		userSession := createTestUserSession(t, userId)
		userSessions = append(userSessions, *userSession)
	}
	return userSessions
}

func createTestUserSessionWithClient(t *testing.T, userId, clientId int64) *models.UserSession {
	userSession := createTestUserSession(t, userId)
	userSessionClient := &models.UserSessionClient{
		UserSessionId: userSession.Id,
		ClientId:      clientId,
		Started:       time.Now().UTC().Truncate(time.Microsecond),
		LastAccessed:  time.Now().UTC().Truncate(time.Microsecond),
	}
	err := database.CreateUserSessionClient(nil, userSessionClient)
	if err != nil {
		t.Fatalf("Failed to create test user session client: %v", err)
	}
	return userSession
}

func createTestUserSessionsWithClient(t *testing.T, userId, clientId int64, count int) []models.UserSession {
	var userSessions []models.UserSession
	for i := 0; i < count; i++ {
		userSession := createTestUserSessionWithClient(t, userId, clientId)
		userSessions = append(userSessions, *userSession)
	}
	return userSessions
}

func assertUserSessionEqual(t *testing.T, expected, actual *models.UserSession) {
	if actual.Id != expected.Id {
		t.Errorf("Expected ID %d, got %d", expected.Id, actual.Id)
	}
	if actual.SessionIdentifier != expected.SessionIdentifier {
		t.Errorf("Expected SessionIdentifier %s, got %s", expected.SessionIdentifier, actual.SessionIdentifier)
	}
	if !actual.Started.Equal(expected.Started) {
		t.Errorf("Expected Started %v, got %v", expected.Started, actual.Started)
	}
	if !actual.LastAccessed.Equal(expected.LastAccessed) {
		t.Errorf("Expected LastAccessed %v, got %v", expected.LastAccessed, actual.LastAccessed)
	}
	if actual.AuthMethods != expected.AuthMethods {
		t.Errorf("Expected AuthMethods %s, got %s", expected.AuthMethods, actual.AuthMethods)
	}
	if actual.AcrLevel != expected.AcrLevel {
		t.Errorf("Expected AcrLevel %s, got %s", expected.AcrLevel, actual.AcrLevel)
	}
	if !actual.AuthTime.Equal(expected.AuthTime) {
		t.Errorf("Expected AuthTime %v, got %v", expected.AuthTime, actual.AuthTime)
	}
	if actual.IpAddress != expected.IpAddress {
		t.Errorf("Expected IpAddress %s, got %s", expected.IpAddress, actual.IpAddress)
	}
	if actual.DeviceName != expected.DeviceName {
		t.Errorf("Expected DeviceName %s, got %s", expected.DeviceName, actual.DeviceName)
	}
	if actual.DeviceType != expected.DeviceType {
		t.Errorf("Expected DeviceType %s, got %s", expected.DeviceType, actual.DeviceType)
	}
	if actual.DeviceOS != expected.DeviceOS {
		t.Errorf("Expected DeviceOS %s, got %s", expected.DeviceOS, actual.DeviceOS)
	}
	if actual.UserId != expected.UserId {
		t.Errorf("Expected UserId %d, got %d", expected.UserId, actual.UserId)
	}
	if !actual.CreatedAt.Valid || actual.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !actual.UpdatedAt.Valid || actual.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}
}
