package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/authserver/internal/models"
)

func TestCreateCode(t *testing.T) {
	// Create a test client and user
	client := createTestClient(t)
	user := createTestUser(t)

	random := gofakeit.LetterN(6)
	code := &models.Code{
		ClientId:            client.Id,
		UserId:              user.Id,
		Code:                "testcode_" + random,
		CodeHash:            "testhash_" + random,
		CodeChallenge:       "testchallenge_" + random,
		CodeChallengeMethod: "S256",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "teststate_" + random,
		Nonce:               "testnonce_" + random,
		IpAddress:           "192.168.1.1",
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   "testsession_" + random,
		AcrLevel:            "1",
		AuthMethods:         "password",
		Used:                false,
	}

	err := database.CreateCode(nil, code)
	if err != nil {
		t.Fatalf("Failed to create code: %v", err)
	}

	// Verify the code was created
	createdCode, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created code: %v", err)
	}

	// Check all properties
	if createdCode.ClientId != code.ClientId {
		t.Errorf("Expected ClientId %d, got %d", code.ClientId, createdCode.ClientId)
	}
	if createdCode.UserId != code.UserId {
		t.Errorf("Expected UserId %d, got %d", code.UserId, createdCode.UserId)
	}
	if createdCode.CodeHash != code.CodeHash {
		t.Errorf("Expected CodeHash '%s', got '%s'", code.CodeHash, createdCode.CodeHash)
	}
	if createdCode.CodeChallenge != code.CodeChallenge {
		t.Errorf("Expected CodeChallenge '%s', got '%s'", code.CodeChallenge, createdCode.CodeChallenge)
	}
	if createdCode.CodeChallengeMethod != code.CodeChallengeMethod {
		t.Errorf("Expected CodeChallengeMethod '%s', got '%s'", code.CodeChallengeMethod, createdCode.CodeChallengeMethod)
	}
	if createdCode.RedirectURI != code.RedirectURI {
		t.Errorf("Expected RedirectURI '%s', got '%s'", code.RedirectURI, createdCode.RedirectURI)
	}
	if createdCode.Scope != code.Scope {
		t.Errorf("Expected Scope '%s', got '%s'", code.Scope, createdCode.Scope)
	}
	if createdCode.State != code.State {
		t.Errorf("Expected State '%s', got '%s'", code.State, createdCode.State)
	}
	if createdCode.Nonce != code.Nonce {
		t.Errorf("Expected Nonce '%s', got '%s'", code.Nonce, createdCode.Nonce)
	}
	if createdCode.IpAddress != code.IpAddress {
		t.Errorf("Expected IpAddress '%s', got '%s'", code.IpAddress, createdCode.IpAddress)
	}
	if createdCode.UserAgent != code.UserAgent {
		t.Errorf("Expected UserAgent '%s', got '%s'", code.UserAgent, createdCode.UserAgent)
	}
	if createdCode.ResponseMode != code.ResponseMode {
		t.Errorf("Expected ResponseMode '%s', got '%s'", code.ResponseMode, createdCode.ResponseMode)
	}
	if !createdCode.AuthenticatedAt.Equal(code.AuthenticatedAt) {
		t.Errorf("Expected AuthenticatedAt %v, got %v", code.AuthenticatedAt, createdCode.AuthenticatedAt)
	}
	if createdCode.SessionIdentifier != code.SessionIdentifier {
		t.Errorf("Expected SessionIdentifier '%s', got '%s'", code.SessionIdentifier, createdCode.SessionIdentifier)
	}
	if createdCode.AcrLevel != code.AcrLevel {
		t.Errorf("Expected AcrLevel '%s', got '%s'", code.AcrLevel, createdCode.AcrLevel)
	}
	if createdCode.AuthMethods != code.AuthMethods {
		t.Errorf("Expected AuthMethods '%s', got '%s'", code.AuthMethods, createdCode.AuthMethods)
	}
	if createdCode.Used != code.Used {
		t.Errorf("Expected Used %v, got %v", code.Used, createdCode.Used)
	}
	if !createdCode.CreatedAt.Valid || createdCode.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !createdCode.UpdatedAt.Valid || createdCode.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}

	// Test creating a code with invalid client ID
	invalidCode := &models.Code{
		ClientId: 0,
		UserId:   user.Id,
	}
	err = database.CreateCode(nil, invalidCode)
	if err == nil {
		t.Errorf("Expected error when creating code with invalid client ID, got nil")
	}

	// Test creating a code with invalid user ID
	invalidCode = &models.Code{
		ClientId: client.Id,
		UserId:   0,
	}
	err = database.CreateCode(nil, invalidCode)
	if err == nil {
		t.Errorf("Expected error when creating code with invalid user ID, got nil")
	}

	// Clean up
	database.DeleteCode(nil, code.Id)
	database.DeleteClient(nil, client.Id)
	database.DeleteUser(nil, user.Id)
}

func TestUpdateCode(t *testing.T) {
	// Create a test client, user, and code
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	// Update the code
	code.Used = true
	code.Scope = "openid profile email"
	code.State = "updated_state"
	code.IpAddress = "192.168.1.2"
	code.UserAgent = "Updated User Agent"
	code.ResponseMode = "fragment"
	code.AcrLevel = "2"
	code.AuthMethods = "password mfa"

	time.Sleep(time.Millisecond * 100) // Ensure some time passes before update

	err := database.UpdateCode(nil, code)
	if err != nil {
		t.Fatalf("Failed to update code: %v", err)
	}

	// Fetch the updated code
	updatedCode, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated code: %v", err)
	}

	// Check updated properties
	if updatedCode.Used != true {
		t.Errorf("Expected Used to be true, got %v", updatedCode.Used)
	}
	if updatedCode.Scope != "openid profile email" {
		t.Errorf("Expected Scope 'openid profile email', got '%s'", updatedCode.Scope)
	}
	if updatedCode.State != "updated_state" {
		t.Errorf("Expected State 'updated_state', got '%s'", updatedCode.State)
	}
	if updatedCode.IpAddress != "192.168.1.2" {
		t.Errorf("Expected IpAddress '192.168.1.2', got '%s'", updatedCode.IpAddress)
	}
	if updatedCode.UserAgent != "Updated User Agent" {
		t.Errorf("Expected UserAgent 'Updated User Agent', got '%s'", updatedCode.UserAgent)
	}
	if updatedCode.ResponseMode != "fragment" {
		t.Errorf("Expected ResponseMode 'fragment', got '%s'", updatedCode.ResponseMode)
	}
	if updatedCode.AcrLevel != "2" {
		t.Errorf("Expected AcrLevel '2', got '%s'", updatedCode.AcrLevel)
	}
	if updatedCode.AuthMethods != "password mfa" {
		t.Errorf("Expected AuthMethods 'password mfa', got '%s'", updatedCode.AuthMethods)
	}
	if !updatedCode.UpdatedAt.Time.After(updatedCode.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}

	// Clean up
	database.DeleteCode(nil, code.Id)
	database.DeleteClient(nil, client.Id)
	database.DeleteUser(nil, user.Id)
}

func TestGetCodeById(t *testing.T) {
	// Create a test client, user, and code
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	// Retrieve the code
	retrievedCode, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve code by ID: %v", err)
	}

	// Check all properties
	if retrievedCode.Id != code.Id {
		t.Errorf("Expected Id %d, got %d", code.Id, retrievedCode.Id)
	}
	if retrievedCode.ClientId != code.ClientId {
		t.Errorf("Expected ClientId %d, got %d", code.ClientId, retrievedCode.ClientId)
	}
	if retrievedCode.UserId != code.UserId {
		t.Errorf("Expected UserId %d, got %d", code.UserId, retrievedCode.UserId)
	}
	if retrievedCode.CodeHash != code.CodeHash {
		t.Errorf("Expected CodeHash '%s', got '%s'", code.CodeHash, retrievedCode.CodeHash)
	}
	if retrievedCode.CodeChallenge != code.CodeChallenge {
		t.Errorf("Expected CodeChallenge '%s', got '%s'", code.CodeChallenge, retrievedCode.CodeChallenge)
	}
	if retrievedCode.CodeChallengeMethod != code.CodeChallengeMethod {
		t.Errorf("Expected CodeChallengeMethod '%s', got '%s'", code.CodeChallengeMethod, retrievedCode.CodeChallengeMethod)
	}
	if retrievedCode.RedirectURI != code.RedirectURI {
		t.Errorf("Expected RedirectURI '%s', got '%s'", code.RedirectURI, retrievedCode.RedirectURI)
	}
	if retrievedCode.Scope != code.Scope {
		t.Errorf("Expected Scope '%s', got '%s'", code.Scope, retrievedCode.Scope)
	}
	if retrievedCode.State != code.State {
		t.Errorf("Expected State '%s', got '%s'", code.State, retrievedCode.State)
	}
	if retrievedCode.Nonce != code.Nonce {
		t.Errorf("Expected Nonce '%s', got '%s'", code.Nonce, retrievedCode.Nonce)
	}
	if retrievedCode.IpAddress != code.IpAddress {
		t.Errorf("Expected IpAddress '%s', got '%s'", code.IpAddress, retrievedCode.IpAddress)
	}
	if retrievedCode.UserAgent != code.UserAgent {
		t.Errorf("Expected UserAgent '%s', got '%s'", code.UserAgent, retrievedCode.UserAgent)
	}
	if retrievedCode.ResponseMode != code.ResponseMode {
		t.Errorf("Expected ResponseMode '%s', got '%s'", code.ResponseMode, retrievedCode.ResponseMode)
	}
	if !retrievedCode.AuthenticatedAt.Equal(code.AuthenticatedAt) {
		t.Errorf("Expected AuthenticatedAt %v, got %v", code.AuthenticatedAt, retrievedCode.AuthenticatedAt)
	}
	if retrievedCode.SessionIdentifier != code.SessionIdentifier {
		t.Errorf("Expected SessionIdentifier '%s', got '%s'", code.SessionIdentifier, retrievedCode.SessionIdentifier)
	}
	if retrievedCode.AcrLevel != code.AcrLevel {
		t.Errorf("Expected AcrLevel '%s', got '%s'", code.AcrLevel, retrievedCode.AcrLevel)
	}
	if retrievedCode.AuthMethods != code.AuthMethods {
		t.Errorf("Expected AuthMethods '%s', got '%s'", code.AuthMethods, retrievedCode.AuthMethods)
	}
	if retrievedCode.Used != code.Used {
		t.Errorf("Expected Used %v, got %v", code.Used, retrievedCode.Used)
	}
	if !retrievedCode.CreatedAt.Valid || retrievedCode.CreatedAt.Time.IsZero() {
		t.Errorf("CreatedAt is not set properly")
	}
	if !retrievedCode.UpdatedAt.Valid || retrievedCode.UpdatedAt.Time.IsZero() {
		t.Errorf("UpdatedAt is not set properly")
	}

	// Test retrieving a non-existent code
	nonExistentCode, err := database.GetCodeById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent code, got: %v", err)
	}
	if nonExistentCode != nil {
		t.Errorf("Expected nil for non-existent code, got a code with ID: %d", nonExistentCode.Id)
	}

	// Clean up
	database.DeleteCode(nil, code.Id)
	database.DeleteClient(nil, client.Id)
	database.DeleteUser(nil, user.Id)
}

func TestCodeLoadClient(t *testing.T) {
	// Create a test client, user, and code
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	// Load client for the code
	err := database.CodeLoadClient(nil, code)
	if err != nil {
		t.Fatalf("Failed to load client for code: %v", err)
	}

	// Check if the client was loaded correctly
	if code.Client.Id != client.Id {
		t.Errorf("Expected Client Id %d, got %d", client.Id, code.Client.Id)
	}
	if code.Client.ClientIdentifier != client.ClientIdentifier {
		t.Errorf("Expected Client Identifier '%s', got '%s'", client.ClientIdentifier, code.Client.ClientIdentifier)
	}

	// Test loading client for nil code
	err = database.CodeLoadClient(nil, nil)
	if err != nil {
		t.Errorf("Expected no error when loading client for nil code, got: %v", err)
	}

	// Test loading client for code with non-existent client
	codeWithNonExistentClient := &models.Code{ClientId: 99999}
	err = database.CodeLoadClient(nil, codeWithNonExistentClient)
	if err != nil {
		t.Errorf("Expected no error when loading non-existent client, got: %v", err)
	}
	if codeWithNonExistentClient.Client.Id != 0 {
		t.Errorf("Expected empty client for non-existent client ID, got client with ID: %d", codeWithNonExistentClient.Client.Id)
	}

	// Clean up
	database.DeleteCode(nil, code.Id)
	database.DeleteClient(nil, client.Id)
	database.DeleteUser(nil, user.Id)
}

func TestCodeLoadUser(t *testing.T) {
	// Create a test client, user, and code
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	// Load user for the code
	err := database.CodeLoadUser(nil, code)
	if err != nil {
		t.Fatalf("Failed to load user for code: %v", err)
	}

	// Check if the user was loaded correctly
	if code.User.Id != user.Id {
		t.Errorf("Expected User Id %d, got %d", user.Id, code.User.Id)
	}
	if code.User.Username != user.Username {
		t.Errorf("Expected Username '%s', got '%s'", user.Username, code.User.Username)
	}

	// Test loading user for nil code
	err = database.CodeLoadUser(nil, nil)
	if err != nil {
		t.Errorf("Expected no error when loading user for nil code, got: %v", err)
	}

	// Test loading user for code with non-existent user
	codeWithNonExistentUser := &models.Code{UserId: 99999}
	err = database.CodeLoadUser(nil, codeWithNonExistentUser)
	if err != nil {
		t.Errorf("Expected no error when loading non-existent user, got: %v", err)
	}
	if codeWithNonExistentUser.User.Id != 0 {
		t.Errorf("Expected empty user for non-existent user ID, got user with ID: %d", codeWithNonExistentUser.User.Id)
	}

	// Clean up
	database.DeleteCode(nil, code.Id)
	database.DeleteClient(nil, client.Id)
	database.DeleteUser(nil, user.Id)
}

func TestGetCodeByCodeHash(t *testing.T) {
	// Create a test client, user, and code
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	// Retrieve the code by code hash
	retrievedCode, err := database.GetCodeByCodeHash(nil, code.CodeHash, false)
	if err != nil {
		t.Fatalf("Failed to retrieve code by code hash: %v", err)
	}

	// Check if the retrieved code matches the original code
	if retrievedCode.Id != code.Id {
		t.Errorf("Expected Code Id %d, got %d", code.Id, retrievedCode.Id)
	}
	if retrievedCode.CodeHash != code.CodeHash {
		t.Errorf("Expected CodeHash '%s', got '%s'", code.CodeHash, retrievedCode.CodeHash)
	}
	if retrievedCode.Used != code.Used {
		t.Errorf("Expected Used %v, got %v", code.Used, retrievedCode.Used)
	}

	// Test retrieving a non-existent code
	nonExistentCode, err := database.GetCodeByCodeHash(nil, "non_existent_hash", false)
	if err != nil {
		t.Errorf("Expected no error for non-existent code, got: %v", err)
	}
	if nonExistentCode != nil {
		t.Errorf("Expected nil for non-existent code, got a code with ID: %d", nonExistentCode.Id)
	}

	// Test retrieving a used code
	code.Used = true
	err = database.UpdateCode(nil, code)
	if err != nil {
		t.Fatalf("Failed to update code: %v", err)
	}

	usedCode, err := database.GetCodeByCodeHash(nil, code.CodeHash, true)
	if err != nil {
		t.Fatalf("Failed to retrieve used code: %v", err)
	}
	if usedCode == nil {
		t.Errorf("Expected to retrieve a used code, got nil")
	}
	if usedCode != nil && usedCode.Used == false {
		t.Errorf("Expected Used to be true, got %v", usedCode.Used)
	}

	// Clean up
	database.DeleteCode(nil, code.Id)
	database.DeleteClient(nil, client.Id)
	database.DeleteUser(nil, user.Id)
}

func TestDeleteCode(t *testing.T) {
	// Create a test client, user, and code
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	// Delete the code
	err := database.DeleteCode(nil, code.Id)
	if err != nil {
		t.Fatalf("Failed to delete code: %v", err)
	}

	// Try to retrieve the deleted code
	deletedCode, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted code: %v", err)
	}
	if deletedCode != nil {
		t.Errorf("Code still exists after deletion")
	}

	// Test deleting a non-existent code
	err = database.DeleteCode(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent code, got: %v", err)
	}

	// Clean up
	database.DeleteClient(nil, client.Id)
	database.DeleteUser(nil, user.Id)
}

// Helper functions

func createTestClient(t *testing.T) *models.Client {
	random := gofakeit.LetterN(6)
	client := &models.Client{
		ClientIdentifier: "test_client_" + random,
		Description:      "Test Client",
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	return client
}

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

func createTestCode(t *testing.T, clientId, userId int64) *models.Code {
	random := gofakeit.LetterN(6)
	code := &models.Code{
		ClientId:            clientId,
		UserId:              userId,
		Code:                "testcode_" + random,
		CodeHash:            "testhash_" + random,
		CodeChallenge:       "testchallenge_" + random,
		CodeChallengeMethod: "S256",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "teststate_" + random,
		Nonce:               "testnonce_" + random,
		IpAddress:           "192.168.1.1",
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   "testsession_" + random,
		AcrLevel:            "1",
		AuthMethods:         "password",
		Used:                false,
	}
	err := database.CreateCode(nil, code)
	if err != nil {
		t.Fatalf("Failed to create test code: %v", err)
	}
	return code
}
