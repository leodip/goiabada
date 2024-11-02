package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
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
	userSession.Level2AuthConfigHasChanged = true
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
		SessionIdentifier:          gofakeit.UUID(),
		Started:                    time.Now().UTC().Truncate(time.Microsecond),
		LastAccessed:               time.Now().UTC().Truncate(time.Microsecond),
		AuthMethods:                "pwd",
		AcrLevel:                   enums.AcrLevel1.String(),
		AuthTime:                   time.Now().UTC().Truncate(time.Microsecond),
		IpAddress:                  gofakeit.IPv4Address(),
		DeviceName:                 gofakeit.Name(),
		DeviceType:                 "desktop",
		DeviceOS:                   "Windows",
		Level2AuthConfigHasChanged: false,
		UserId:                     userId,
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
	if actual.Level2AuthConfigHasChanged != expected.Level2AuthConfigHasChanged {
		t.Errorf("Expected Level2AuthConfigHasChanged %v, got %v", expected.Level2AuthConfigHasChanged, actual.Level2AuthConfigHasChanged)
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

func TestDeleteIdleSessions(t *testing.T) {
	// Create a test user
	user := &models.User{
		Username:      gofakeit.Username(),
		Email:         gofakeit.Email(),
		EmailVerified: true,
		PasswordHash:  gofakeit.Password(true, true, true, true, false, 32),
		Subject:       uuid.New(),
		Enabled:       true,
		GivenName:     gofakeit.FirstName(),
		FamilyName:    gofakeit.LastName(),
		OTPEnabled:    false,
	}
	err := database.CreateUser(nil, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a test client
	client := &models.Client{
		ClientIdentifier:                        gofakeit.UUID(),
		Description:                             "Test Client",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400 * 30, // 30 days
		IncludeOpenIDConnectClaimsInAccessToken: "no",
		DefaultAcrLevel:                         enums.AcrLevel1,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create sessions with different last accessed times
	now := time.Now().UTC()

	// Create an active session (accessed 10 minutes ago)
	activeSession := &models.UserSession{
		SessionIdentifier:          gofakeit.UUID(),
		Started:                    now.Add(-10 * time.Minute),
		LastAccessed:               now.Add(-10 * time.Minute),
		AuthMethods:                "pwd",
		AcrLevel:                   enums.AcrLevel1.String(),
		AuthTime:                   now.Add(-10 * time.Minute),
		IpAddress:                  gofakeit.IPv4Address(),
		DeviceName:                 gofakeit.Name(),
		DeviceType:                 "desktop",
		DeviceOS:                   "Windows",
		Level2AuthConfigHasChanged: false,
		UserId:                     user.Id,
	}
	err = database.CreateUserSession(nil, activeSession)
	if err != nil {
		t.Fatalf("Failed to create active session: %v", err)
	}

	// Create UserSessionClient for active session
	activeSessionClient := &models.UserSessionClient{
		UserSessionId: activeSession.Id,
		ClientId:      client.Id,
		Started:       activeSession.Started,
		LastAccessed:  activeSession.LastAccessed,
	}
	err = database.CreateUserSessionClient(nil, activeSessionClient)
	if err != nil {
		t.Fatalf("Failed to create active session client: %v", err)
	}

	// Create an idle session (accessed 2 hours ago)
	idleSession := &models.UserSession{
		SessionIdentifier:          gofakeit.UUID(),
		Started:                    now.Add(-3 * time.Hour),
		LastAccessed:               now.Add(-2 * time.Hour),
		AuthMethods:                "pwd",
		AcrLevel:                   enums.AcrLevel1.String(),
		AuthTime:                   now.Add(-3 * time.Hour),
		IpAddress:                  gofakeit.IPv4Address(),
		DeviceName:                 gofakeit.Name(),
		DeviceType:                 "desktop",
		DeviceOS:                   "Windows",
		Level2AuthConfigHasChanged: false,
		UserId:                     user.Id,
	}
	err = database.CreateUserSession(nil, idleSession)
	if err != nil {
		t.Fatalf("Failed to create idle session: %v", err)
	}

	// Create UserSessionClient for idle session
	idleSessionClient := &models.UserSessionClient{
		UserSessionId: idleSession.Id,
		ClientId:      client.Id,
		Started:       idleSession.Started,
		LastAccessed:  idleSession.LastAccessed,
	}
	err = database.CreateUserSessionClient(nil, idleSessionClient)
	if err != nil {
		t.Fatalf("Failed to create idle session client: %v", err)
	}

	// Create a very idle session (accessed 4 hours ago)
	veryIdleSession := &models.UserSession{
		SessionIdentifier:          gofakeit.UUID(),
		Started:                    now.Add(-5 * time.Hour),
		LastAccessed:               now.Add(-4 * time.Hour),
		AuthMethods:                "pwd",
		AcrLevel:                   enums.AcrLevel1.String(),
		AuthTime:                   now.Add(-5 * time.Hour),
		IpAddress:                  gofakeit.IPv4Address(),
		DeviceName:                 gofakeit.Name(),
		DeviceType:                 "desktop",
		DeviceOS:                   "Windows",
		Level2AuthConfigHasChanged: false,
		UserId:                     user.Id,
	}
	err = database.CreateUserSession(nil, veryIdleSession)
	if err != nil {
		t.Fatalf("Failed to create very idle session: %v", err)
	}

	// Create UserSessionClient for very idle session
	veryIdleSessionClient := &models.UserSessionClient{
		UserSessionId: veryIdleSession.Id,
		ClientId:      client.Id,
		Started:       veryIdleSession.Started,
		LastAccessed:  veryIdleSession.LastAccessed,
	}
	err = database.CreateUserSessionClient(nil, veryIdleSessionClient)
	if err != nil {
		t.Fatalf("Failed to create very idle session client: %v", err)
	}

	// Set idle timeout to 1 hour
	idleTimeout := 1 * time.Hour

	// Delete idle sessions
	err = database.DeleteIdleSessions(nil, idleTimeout)
	if err != nil {
		t.Fatalf("Failed to delete idle sessions: %v", err)
	}

	// Check if active session still exists
	activeExists, err := database.GetUserSessionById(nil, activeSession.Id)
	if err != nil {
		t.Fatalf("Error checking active session: %v", err)
	}
	if activeExists == nil {
		t.Error("Active session was incorrectly deleted")
	}

	// Verify active session's client association still exists
	activeSessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, activeSession.Id)
	if err != nil {
		t.Fatalf("Error checking active session clients: %v", err)
	}
	if len(activeSessionClients) != 1 {
		t.Error("Active session client was incorrectly deleted")
	}

	// Check if idle session was deleted
	idleExists, err := database.GetUserSessionById(nil, idleSession.Id)
	if err != nil {
		t.Fatalf("Error checking idle session: %v", err)
	}
	if idleExists != nil {
		t.Error("Idle session was not deleted")
	}

	// Verify idle session's client association was also deleted
	idleSessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, idleSession.Id)
	if err != nil {
		t.Fatalf("Error checking idle session clients: %v", err)
	}
	if len(idleSessionClients) != 0 {
		t.Error("Idle session client was not deleted")
	}

	// Check if very idle session was deleted
	veryIdleExists, err := database.GetUserSessionById(nil, veryIdleSession.Id)
	if err != nil {
		t.Fatalf("Error checking very idle session: %v", err)
	}
	if veryIdleExists != nil {
		t.Error("Very idle session was not deleted")
	}

	// Verify very idle session's client association was also deleted
	veryIdleSessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, veryIdleSession.Id)
	if err != nil {
		t.Fatalf("Error checking very idle session clients: %v", err)
	}
	if len(veryIdleSessionClients) != 0 {
		t.Error("Very idle session client was not deleted")
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	// Create a test user
	user := &models.User{
		Username:      gofakeit.Username(),
		Email:         gofakeit.Email(),
		EmailVerified: true,
		PasswordHash:  gofakeit.Password(true, true, true, true, false, 32),
		Subject:       uuid.New(),
		Enabled:       true,
		GivenName:     gofakeit.FirstName(),
		FamilyName:    gofakeit.LastName(),
		OTPEnabled:    false,
	}
	err := database.CreateUser(nil, user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a test client
	client := &models.Client{
		ClientIdentifier:                        gofakeit.UUID(),
		Description:                             "Test Client",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400 * 30, // 30 days
		IncludeOpenIDConnectClaimsInAccessToken: "no",
		DefaultAcrLevel:                         enums.AcrLevel1,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create sessions with different start times
	now := time.Now().UTC()

	// Create a recent session (started 1 hour ago)
	recentSession := &models.UserSession{
		SessionIdentifier:          gofakeit.UUID(),
		Started:                    now.Add(-1 * time.Hour),
		LastAccessed:               now,
		AuthMethods:                "pwd",
		AcrLevel:                   enums.AcrLevel1.String(),
		AuthTime:                   now.Add(-1 * time.Hour),
		IpAddress:                  gofakeit.IPv4Address(),
		DeviceName:                 gofakeit.Name(),
		DeviceType:                 "desktop",
		DeviceOS:                   "Windows",
		Level2AuthConfigHasChanged: false,
		UserId:                     user.Id,
	}
	err = database.CreateUserSession(nil, recentSession)
	if err != nil {
		t.Fatalf("Failed to create recent session: %v", err)
	}

	// Create UserSessionClient for recent session
	recentSessionClient := &models.UserSessionClient{
		UserSessionId: recentSession.Id,
		ClientId:      client.Id,
		Started:       recentSession.Started,
		LastAccessed:  recentSession.LastAccessed,
	}
	err = database.CreateUserSessionClient(nil, recentSessionClient)
	if err != nil {
		t.Fatalf("Failed to create recent session client: %v", err)
	}

	// Create an old session (started 2 days ago)
	oldSession := &models.UserSession{
		SessionIdentifier:          gofakeit.UUID(),
		Started:                    now.Add(-48 * time.Hour),
		LastAccessed:               now,
		AuthMethods:                "pwd",
		AcrLevel:                   enums.AcrLevel1.String(),
		AuthTime:                   now.Add(-48 * time.Hour),
		IpAddress:                  gofakeit.IPv4Address(),
		DeviceName:                 gofakeit.Name(),
		DeviceType:                 "desktop",
		DeviceOS:                   "Windows",
		Level2AuthConfigHasChanged: false,
		UserId:                     user.Id,
	}
	err = database.CreateUserSession(nil, oldSession)
	if err != nil {
		t.Fatalf("Failed to create old session: %v", err)
	}

	// Create UserSessionClient for old session
	oldSessionClient := &models.UserSessionClient{
		UserSessionId: oldSession.Id,
		ClientId:      client.Id,
		Started:       oldSession.Started,
		LastAccessed:  oldSession.LastAccessed,
	}
	err = database.CreateUserSessionClient(nil, oldSessionClient)
	if err != nil {
		t.Fatalf("Failed to create old session client: %v", err)
	}

	// Create a very old session (started 5 days ago)
	veryOldSession := &models.UserSession{
		SessionIdentifier:          gofakeit.UUID(),
		Started:                    now.Add(-120 * time.Hour),
		LastAccessed:               now,
		AuthMethods:                "pwd",
		AcrLevel:                   enums.AcrLevel1.String(),
		AuthTime:                   now.Add(-120 * time.Hour),
		IpAddress:                  gofakeit.IPv4Address(),
		DeviceName:                 gofakeit.Name(),
		DeviceType:                 "desktop",
		DeviceOS:                   "Windows",
		Level2AuthConfigHasChanged: false,
		UserId:                     user.Id,
	}
	err = database.CreateUserSession(nil, veryOldSession)
	if err != nil {
		t.Fatalf("Failed to create very old session: %v", err)
	}

	// Create UserSessionClient for very old session
	veryOldSessionClient := &models.UserSessionClient{
		UserSessionId: veryOldSession.Id,
		ClientId:      client.Id,
		Started:       veryOldSession.Started,
		LastAccessed:  veryOldSession.LastAccessed,
	}
	err = database.CreateUserSessionClient(nil, veryOldSessionClient)
	if err != nil {
		t.Fatalf("Failed to create very old session client: %v", err)
	}

	// Set maximum lifetime to 24 hours
	maxLifetime := 24 * time.Hour

	// Delete expired sessions
	err = database.DeleteExpiredSessions(nil, maxLifetime)
	if err != nil {
		t.Fatalf("Failed to delete expired sessions: %v", err)
	}

	// Check if recent session still exists
	recentExists, err := database.GetUserSessionById(nil, recentSession.Id)
	if err != nil {
		t.Fatalf("Error checking recent session: %v", err)
	}
	if recentExists == nil {
		t.Error("Recent session was incorrectly deleted")
	}

	// Verify recent session's client association still exists
	recentSessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, recentSession.Id)
	if err != nil {
		t.Fatalf("Error checking recent session clients: %v", err)
	}
	if len(recentSessionClients) != 1 {
		t.Error("Recent session client was incorrectly deleted")
	}

	// Check if old session was deleted
	oldExists, err := database.GetUserSessionById(nil, oldSession.Id)
	if err != nil {
		t.Fatalf("Error checking old session: %v", err)
	}
	if oldExists != nil {
		t.Error("Old session was not deleted")
	}

	// Verify old session's client association was also deleted
	oldSessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, oldSession.Id)
	if err != nil {
		t.Fatalf("Error checking old session clients: %v", err)
	}
	if len(oldSessionClients) != 0 {
		t.Error("Old session client was not deleted")
	}

	// Check if very old session was deleted
	veryOldExists, err := database.GetUserSessionById(nil, veryOldSession.Id)
	if err != nil {
		t.Fatalf("Error checking very old session: %v", err)
	}
	if veryOldExists != nil {
		t.Error("Very old session was not deleted")
	}

	// Verify very old session's client association was also deleted
	veryOldSessionClients, err := database.GetUserSessionClientsByUserSessionId(nil, veryOldSession.Id)
	if err != nil {
		t.Fatalf("Error checking very old session clients: %v", err)
	}
	if len(veryOldSessionClients) != 0 {
		t.Error("Very old session client was not deleted")
	}
}
