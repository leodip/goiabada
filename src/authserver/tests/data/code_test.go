package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
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
		CodeChallenge:       sql.NullString{String: "testchallenge_" + random, Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
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
	if createdCode.CodeChallenge.String != code.CodeChallenge.String {
		t.Errorf("Expected CodeChallenge '%s', got '%s'", code.CodeChallenge.String, createdCode.CodeChallenge.String)
	}
	if createdCode.CodeChallengeMethod.String != code.CodeChallengeMethod.String {
		t.Errorf("Expected CodeChallengeMethod '%s', got '%s'", code.CodeChallengeMethod.String, createdCode.CodeChallengeMethod.String)
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

	time.Sleep(timestampTick) // Ensure some time passes before update

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
}

// TestMarkCodeAsUsed exercises the atomic compare-and-set that makes
// authorization-code redemption single-use under concurrency (#77). The
// invariant the fix relies on: only the first claim of an unused code succeeds;
// every subsequent claim of that same code fails without error.
func TestMarkCodeAsUsed(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	// Sanity: freshly created codes are unused.
	if code.Used {
		t.Fatalf("expected a freshly created code to be unused")
	}

	// First claim wins: the compare-and-set flips used=false -> true.
	claimed, err := database.MarkCodeAsUsed(nil, code.Id)
	if err != nil {
		t.Fatalf("first MarkCodeAsUsed returned error: %v", err)
	}
	if !claimed {
		t.Fatalf("first MarkCodeAsUsed should claim the code, got claimed=false")
	}

	// The row is actually marked used in the database.
	reloaded, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("failed to reload code: %v", err)
	}
	if !reloaded.Used {
		t.Errorf("expected code to be marked used after a successful claim")
	}

	// Second claim loses: the WHERE used=false predicate no longer matches, so no
	// row is affected. This is exactly what stops a concurrent request from
	// redeeming the same code a second time.
	claimed, err = database.MarkCodeAsUsed(nil, code.Id)
	if err != nil {
		t.Fatalf("second MarkCodeAsUsed returned error: %v", err)
	}
	if claimed {
		t.Errorf("second MarkCodeAsUsed must not claim an already-used code, got claimed=true")
	}

	// A non-existent code affects zero rows: claimed=false, and no error.
	claimed, err = database.MarkCodeAsUsed(nil, 999999999)
	if err != nil {
		t.Fatalf("MarkCodeAsUsed for a missing code returned error: %v", err)
	}
	if claimed {
		t.Errorf("MarkCodeAsUsed for a non-existent code must return claimed=false")
	}

	// Guard: id 0 is rejected outright.
	if _, err := database.MarkCodeAsUsed(nil, 0); err == nil {
		t.Errorf("MarkCodeAsUsed with id 0 must return an error")
	}

	// A revoked code is not claimable even though it was never used. That is the
	// second term of the predicate, and it is what makes ending a session durable
	// against a redemption that validated a moment before the termination (#129).
	// Keep BOTH this case and the already-used one above: either alone still passes
	// with the other term deleted from the predicate.
	revoked := createTestCode(t, client.Id, user.Id)
	if _, err := database.RevokeCodesBySessionIdentifier(nil, revoked.SessionIdentifier); err != nil {
		t.Fatalf("failed to revoke the code's session: %v", err)
	}
	claimed, err = database.MarkCodeAsUsed(nil, revoked.Id)
	if err != nil {
		t.Fatalf("MarkCodeAsUsed for a revoked code returned error: %v", err)
	}
	if claimed {
		t.Errorf("MarkCodeAsUsed must not claim a revoked code, got claimed=true")
	}

	// And it stays unused, so nothing downstream can read it as redeemed.
	unclaimed, err := database.GetCodeById(nil, revoked.Id)
	if err != nil {
		t.Fatalf("failed to reload the revoked code: %v", err)
	}
	if unclaimed.Used {
		t.Errorf("a revoked code must remain unused after a failed claim")
	}
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
	if retrievedCode.CodeChallenge.String != code.CodeChallenge.String {
		t.Errorf("Expected CodeChallenge '%s', got '%s'", code.CodeChallenge.String, retrievedCode.CodeChallenge.String)
	}
	if retrievedCode.CodeChallengeMethod.String != code.CodeChallengeMethod.String {
		t.Errorf("Expected CodeChallengeMethod '%s', got '%s'", code.CodeChallengeMethod.String, retrievedCode.CodeChallengeMethod.String)
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
}

func createTestCode(t *testing.T, clientId, userId int64) *models.Code {
	random := gofakeit.LetterN(6)
	code := &models.Code{
		ClientId:            clientId,
		UserId:              userId,
		Code:                "testcode_" + random,
		CodeHash:            "testhash_" + random,
		CodeChallenge:       sql.NullString{String: "testchallenge_" + random, Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
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

func TestDeleteUsedCodesWithoutRefreshTokens(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	// Test Case 1: Used code without refresh token should be deleted
	code1 := createTestCode(t, client.Id, user.Id)
	code1.Used = true
	err := database.UpdateCode(nil, code1)
	if err != nil {
		t.Fatalf("Failed to update code1 as used: %v", err)
	}

	// Test Case 2: Used code with refresh token should not be deleted
	code2 := createTestCode(t, client.Id, user.Id)
	code2.Used = true
	err = database.UpdateCode(nil, code2)
	if err != nil {
		t.Fatalf("Failed to update code2 as used: %v", err)
	}

	// Create refresh token for code2
	refreshToken := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: code2.Id, Valid: true},
		RefreshTokenJti:   "test_jti_" + gofakeit.LetterN(6),
		SessionIdentifier: "test_session_" + gofakeit.LetterN(6),
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC(), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true},
		Revoked:           false,
	}
	err = database.CreateRefreshToken(nil, refreshToken)
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	// Test Case 3: Unused code should not be deleted regardless of refresh token
	code3 := createTestCode(t, client.Id, user.Id)
	// code3 remains unused (Used = false by default)

	// Cutoff in the future, so every code qualifies on age and these assertions keep
	// testing what they were written to test: the used/refresh-token predicate. The age
	// cutoff itself is covered by TestDeleteUsedCodesWithoutRefreshTokens_AgeCutoff.
	err = database.DeleteUsedCodesWithoutRefreshTokens(nil, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to delete used codes without refresh tokens: %v", err)
	}

	// Verify Test Case 1: Used code without refresh token should be deleted
	deletedCode1, err := database.GetCodeById(nil, code1.Id)
	if err != nil {
		t.Fatalf("Error checking deleted code1: %v", err)
	}
	if deletedCode1 != nil {
		t.Error("Code1 (used, no refresh token) should have been deleted but still exists")
	}

	// Verify Test Case 2: Used code with refresh token should still exist
	remainingCode2, err := database.GetCodeById(nil, code2.Id)
	if err != nil {
		t.Fatalf("Error checking code2: %v", err)
	}
	if remainingCode2 == nil {
		t.Error("Code2 (used, has refresh token) should not have been deleted")
	}

	// Verify Test Case 3: Unused code should still exist
	remainingCode3, err := database.GetCodeById(nil, code3.Id)
	if err != nil {
		t.Fatalf("Error checking code3: %v", err)
	}
	if remainingCode3 == nil {
		t.Error("Code3 (unused) should not have been deleted")
	}

	// Additional Test Case: Delete code whose refresh token has expired.
	// The token below is also revoked, but that is incidental: since #128 the sweep
	// deletes it solely because it is past both expires_at and max_lifetime.
	code4 := createTestCode(t, client.Id, user.Id)
	code4.Used = true
	err = database.UpdateCode(nil, code4)
	if err != nil {
		t.Fatalf("Failed to update code4 as used: %v", err)
	}

	// Create an expired refresh token for code4 (revoked too, which no longer matters)
	revokedRefreshToken := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: code4.Id, Valid: true},
		RefreshTokenJti:   "test_jti_" + gofakeit.LetterN(6),
		SessionIdentifier: "test_session_" + gofakeit.LetterN(6),
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC().Add(-2 * time.Hour), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(-1 * time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(-1 * time.Hour), Valid: true},
		Revoked:           true,
	}
	err = database.CreateRefreshToken(nil, revokedRefreshToken)
	if err != nil {
		t.Fatalf("Failed to create revoked refresh token: %v", err)
	}

	// Delete expired refresh tokens first
	err = database.DeleteExpiredRefreshTokens(nil)
	if err != nil {
		t.Fatalf("Failed to delete expired refresh tokens: %v", err)
	}

	// Then delete used codes without valid refresh tokens. Future cutoff, as above.
	err = database.DeleteUsedCodesWithoutRefreshTokens(nil, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to delete used codes without refresh tokens: %v", err)
	}

	// Verify code4 was deleted after its refresh token was removed
	remainingCode4, err := database.GetCodeById(nil, code4.Id)
	if err != nil {
		t.Fatalf("Error checking code4: %v", err)
	}
	if remainingCode4 != nil {
		t.Error("Code4 (used, expired refresh token) should have been deleted")
	}
}

// TestDeleteUsedCodesWithoutRefreshTokens_AgeCutoff guards the race that broke CI on
// postgres: the token endpoint marks a code used and only afterwards inserts the refresh
// token that references it, so for the duration of token generation a healthy code sits in
// exactly the state this sweep selects, used with no refresh token. Deleting it there makes
// the insert fail on fk_refresh_tokens_code and the client gets a 500 instead of tokens.
//
// The ordering that opens the window arrived with the atomic-redemption fix (#77), which
// moved MarkCodeAsUsed ahead of token generation. Before that the refresh token always
// existed before the flag flipped, so the predicate could never match a live redemption.
//
// A code created now must therefore survive a sweep whose cutoff is in the past, which is
// what the background worker passes. Codes expire after 60 seconds, so anything older than
// the cutoff can no longer be redeemed and is genuinely dead.
func TestDeleteUsedCodesWithoutRefreshTokens_AgeCutoff(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	// A code in exactly the mid-redemption state: used, no refresh token yet.
	code := createTestCode(t, client.Id, user.Id)
	code.Used = true
	if err := database.UpdateCode(nil, code); err != nil {
		t.Fatalf("Failed to mark code as used: %v", err)
	}

	// Sweep with the cutoff the worker uses. The code was created seconds ago, so it is
	// newer than the cutoff and must be left alone.
	cutoff := time.Now().UTC().Add(-5 * time.Minute)
	if err := database.DeleteUsedCodesWithoutRefreshTokens(nil, cutoff); err != nil {
		t.Fatalf("Failed to run the sweep: %v", err)
	}

	survived, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Error re-reading the code: %v", err)
	}
	if survived == nil {
		t.Fatal("a code marked used seconds ago was deleted by the sweep; this is the " +
			"race that fails the token exchange with a foreign key violation on " +
			"fk_refresh_tokens_code")
	}

	// The same code once it is genuinely past the cutoff: no longer redeemable, so it can
	// never gain a refresh token, and the sweep must reap it.
	if err := database.DeleteUsedCodesWithoutRefreshTokens(nil, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("Failed to run the sweep with a future cutoff: %v", err)
	}
	reaped, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Error re-reading the code: %v", err)
	}
	if reaped != nil {
		t.Error("a used code older than the cutoff and with no refresh token should have been deleted")
	}
}

// revokeCodesOf marks one code revoked through the only method that writes the column,
// since Code.Revoked is dont-update tagged and UpdateCode cannot set it. createTestCode
// randomises the session identifier, so sweeping one code's session reaches that code
// alone.
func revokeCodesOf(t *testing.T, code *models.Code) {
	t.Helper()
	if _, err := database.RevokeCodesBySessionIdentifier(nil, code.SessionIdentifier); err != nil {
		t.Fatalf("Failed to revoke the session of code %d: %v", code.Id, err)
	}
	assertCodeRevoked(t, code.Id, true, "the code the fixture just revoked")
}

// markCodeUsed puts a code in the redeemed state. The in-memory copy still reads
// Revoked = false when the caller revoked it first, which is exactly the shape a handler
// that loaded the code earlier holds, and the dont-update tag is what keeps it from
// regressing the marker.
func markCodeUsed(t *testing.T, code *models.Code) {
	t.Helper()
	code.Used = true
	if err := database.UpdateCode(nil, code); err != nil {
		t.Fatalf("Failed to mark code %d as used: %v", code.Id, err)
	}
}

// assertCodeExists reports whether a code row is still there, which is what a reaper's
// contract is about.
func assertCodeExists(t *testing.T, codeId int64, want bool, what string) {
	t.Helper()
	code, err := database.GetCodeById(nil, codeId)
	if err != nil {
		t.Fatalf("Failed to re-read code %d: %v", codeId, err)
	}
	if want && code == nil {
		t.Errorf("%s: was deleted, expected to survive", what)
	}
	if !want && code != nil {
		t.Errorf("%s: survived, expected to be deleted", what)
	}
}

// TestDeleteUsedCodesWithoutRefreshTokens_RevokedUnused covers the second class this sweep
// reaps since #129: a code revoked while it was still unredeemed, which is what ending a
// session leaves behind when the grant it marked had not been exchanged yet (decision 8).
// Without it those rows accumulate forever, and unbounded growth is the defect that moved
// the marker off a session-keyed registry in the first place.
//
// The cutoff is varied rather than the rows, following TestDeleteUsedCodesWithoutRefreshTokens_AgeCutoff
// above, because Code.CreatedAt is dont-update tagged and a row cannot be aged through the
// ORM.
func TestDeleteUsedCodesWithoutRefreshTokens_RevokedUnused(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	// Revoked while still unredeemed: the row the extension exists for.
	revokedUnused := createTestCode(t, client.Id, user.Id)
	revokeCodesOf(t, revokedUnused)

	// Revoked after redemption, with an unrevoked refresh token descended from it. Keep
	// this row. It is the regression guard for the retention argument decision 8 rests on,
	// that the marker outlives every descendant that could present it, and its value is
	// invisible once the design is right. The descendant is deliberately unrevoked, which
	// is gap 2's racing child: a rotation that validated before the termination inserts it
	// afterwards, so the termination's own token sweep never saw it and the code's marker
	// is the only thing that rejects it. The stake is therefore higher than losing a
	// marker: fk_refresh_tokens_code is ON DELETE CASCADE, so a sweep reaching this code
	// would delete the very descendant the marker exists to reject, and the token would
	// stop being rejected because it stopped existing rather than because it was contained.
	revokedUsedWithToken := createTestCode(t, client.Id, user.Id)
	revokeCodesOf(t, revokedUsedWithToken)
	markCodeUsed(t, revokedUsedWithToken)
	racingChild := &models.RefreshToken{
		CodeId:            sql.NullInt64{Int64: revokedUsedWithToken.Id, Valid: true},
		RefreshTokenJti:   "test_jti_" + gofakeit.LetterN(6),
		SessionIdentifier: revokedUsedWithToken.SessionIdentifier,
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile offline_access",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC(), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true},
		Revoked:           false,
	}
	if err := database.CreateRefreshToken(nil, racingChild); err != nil {
		t.Fatalf("Failed to create the descendant refresh token: %v", err)
	}

	// Revoked after redemption with nothing referencing it. The pre-existing branch, and
	// the proof that adding `used = false` to the new branch did not narrow the old one.
	revokedUsedNoToken := createTestCode(t, client.Id, user.Id)
	revokeCodesOf(t, revokedUsedNoToken)
	markCodeUsed(t, revokedUsedNoToken)

	// Unredeemed and never revoked: an abandoned ceremony's code. The negative control for
	// the `revoked = true` term, and the only row that fails if the sweep is written to
	// reap every unredeemed code.
	unrevokedUnused := createTestCode(t, client.Id, user.Id)

	// The cutoff the worker actually passes, first and while every row is still there.
	// All four were created seconds ago, so all four must survive. This is the only
	// assertion here that fails if the extension drops the shared created_at term, or
	// states it per branch and gets one of them wrong.
	if err := database.DeleteUsedCodesWithoutRefreshTokens(nil, time.Now().UTC().Add(-5*time.Minute)); err != nil {
		t.Fatalf("Failed to run the sweep with the worker's cutoff: %v", err)
	}
	assertCodeExists(t, revokedUnused.Id, true, "a revoked, unredeemed code newer than the cutoff")
	assertCodeExists(t, revokedUsedNoToken.Id, true, "a revoked, redeemed code newer than the cutoff")
	assertCodeExists(t, revokedUsedWithToken.Id, true, "a revoked, redeemed code with a descendant refresh token, newer than the cutoff")
	assertCodeExists(t, unrevokedUnused.Id, true, "an unrevoked, unredeemed code newer than the cutoff")

	// Then a cutoff every row is past, so the remaining assertions are about the
	// used/revoked predicate rather than about age.
	if err := database.DeleteUsedCodesWithoutRefreshTokens(nil, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("Failed to run the sweep with a future cutoff: %v", err)
	}
	assertCodeExists(t, revokedUnused.Id, false, "a revoked, unredeemed code past the cutoff")
	assertCodeExists(t, revokedUsedNoToken.Id, false, "a revoked, redeemed code with no refresh token, past the cutoff")
	assertCodeExists(t, revokedUsedWithToken.Id, true,
		"a revoked, redeemed code whose descendant refresh token is still there; the marker "+
			"must outlive it, and deleting the code would cascade the descendant away")
	assertCodeExists(t, unrevokedUnused.Id, true, "an unrevoked, unredeemed code past the cutoff")
}

// TestDeleteUsedCodesWithoutRefreshTokens_RevokedUnusedWithRopcTokenPresent pins where the
// NOT IN subquery sits, which is the one thing in the widened predicate that can ship inert.
// ROPC refresh tokens carry code_id = NULL, and `x NOT IN (…, NULL)` is UNKNOWN rather than
// TRUE, so the redeemed branch already matches nothing on any deployment that has issued one.
// That is #130 and it is out of scope here. Keeping the subquery inside that branch is what
// contains it: UNKNOWN OR TRUE is TRUE, so the revoked branch reaps anyway. Hoisting the
// subquery beside the cutoff, which reads as the tidier factoring, makes the whole predicate
// UNKNOWN and this method silently stops deleting anything at all.
//
// Separate from the test above rather than a row in it, because the NULL row changes what the
// redeemed branch can prove: while it is present, a revoked and redeemed code with no refresh
// token is no longer reaped either, which is #130 behaving as documented rather than a defect
// in this change.
func TestDeleteUsedCodesWithoutRefreshTokens_RevokedUnusedWithRopcTokenPresent(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	// A ROPC-shaped refresh token: no originating code, so code_id is NULL. Removed at the
	// end so it cannot change what a later test in this package proves about the sweep.
	ropcToken := &models.RefreshToken{
		CodeId:            sql.NullInt64{Valid: false},
		UserId:            sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:          sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenJti:   "test_jti_" + gofakeit.LetterN(6),
		SessionIdentifier: "",
		RefreshTokenType:  "Bearer",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC(), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true},
	}
	if err := database.CreateRefreshToken(nil, ropcToken); err != nil {
		t.Fatalf("Failed to create the ROPC refresh token: %v", err)
	}
	t.Cleanup(func() {
		if err := database.DeleteRefreshToken(nil, ropcToken.Id); err != nil {
			t.Errorf("Failed to remove the ROPC refresh token: %v", err)
		}
	})

	revokedUnused := createTestCode(t, client.Id, user.Id)
	revokeCodesOf(t, revokedUnused)

	if err := database.DeleteUsedCodesWithoutRefreshTokens(nil, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("Failed to run the sweep: %v", err)
	}
	assertCodeExists(t, revokedUnused.Id, false,
		"a revoked, unredeemed code swept while a refresh token with a NULL code_id exists; "+
			"if this survived, the NOT IN subquery was hoisted out of the redeemed branch and "+
			"the whole predicate is UNKNOWN")
}

// TestUpdateCode_DoesNotClobberAuthStateGeneration pins decision 11(b) of #106 for
// codes. See TestUpdateUser_DoesNotClobberAuthStateGeneration for why the tag
// matters and why the value is deliberately nonzero.
func TestUpdateCode_DoesNotClobberAuthStateGeneration(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	code.AuthStateGeneration = 7
	code.Id = 0
	code.CodeHash = "genhash_" + gofakeit.LetterN(8)
	if err := database.CreateCode(nil, code); err != nil {
		t.Fatalf("Failed to create code with a generation: %v", err)
	}

	created, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Failed to reload created code: %v", err)
	}
	if created.AuthStateGeneration != 7 {
		t.Fatalf("CreateCode must persist auth_state_generation, got %d want 7",
			created.AuthStateGeneration)
	}

	created.AuthStateGeneration = 0
	created.Used = true
	if err := database.UpdateCode(nil, created); err != nil {
		t.Fatalf("Failed to update code: %v", err)
	}

	after, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Failed to reload updated code: %v", err)
	}
	if after.AuthStateGeneration != 7 {
		t.Errorf("UpdateCode regressed auth_state_generation to %d, want 7 (is the dont-update tag missing?)",
			after.AuthStateGeneration)
	}
	if !after.Used {
		t.Error("the rest of the update must still apply, Used = false")
	}
}

// createTestCodeInSession creates a code bound to a specific session identifier,
// which the session-scoped revocation sweep is keyed on. createTestCode randomises
// the identifier, so a caller needing two codes on ONE session cannot use it.
func createTestCodeInSession(t *testing.T, clientId, userId int64, sessionIdentifier string) *models.Code {
	t.Helper()
	code := createTestCode(t, clientId, userId)
	code.SessionIdentifier = sessionIdentifier
	if err := database.UpdateCode(nil, code); err != nil {
		t.Fatalf("Failed to bind test code to session %q: %v", sessionIdentifier, err)
	}
	return code
}

// assertCodeRevoked reloads a code and checks the marker, since the whole point of
// the column is what a later read of it says.
func assertCodeRevoked(t *testing.T, codeId int64, want bool, what string) {
	t.Helper()
	code, err := database.GetCodeById(nil, codeId)
	if err != nil {
		t.Fatalf("Failed to reload code %d: %v", codeId, err)
	}
	if code == nil {
		t.Fatalf("Code %d disappeared", codeId)
	}
	if code.Revoked != want {
		t.Errorf("%s: Revoked = %v, want %v", what, code.Revoked, want)
	}
}

// TestRevokeCodesBySessionIdentifier covers the marker that makes ending a session
// durable (#129): every code of the terminated session is marked, and nothing else is.
func TestRevokeCodesBySessionIdentifier(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	sessionA := "revoke_a_" + gofakeit.LetterN(8)
	sessionB := "revoke_b_" + gofakeit.LetterN(8)

	first := createTestCodeInSession(t, client.Id, user.Id, sessionA)
	second := createTestCodeInSession(t, client.Id, user.Id, sessionA)
	unrelated := createTestCodeInSession(t, client.Id, user.Id, sessionB)

	// Every code of the target session transitions, and the count says how many. The
	// count is what the audit event reports, so it is part of the contract.
	count, err := database.RevokeCodesBySessionIdentifier(nil, sessionA)
	if err != nil {
		t.Fatalf("RevokeCodesBySessionIdentifier returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 codes revoked, got %d", count)
	}
	assertCodeRevoked(t, first.Id, true, "a code of the terminated session")
	assertCodeRevoked(t, second.Id, true, "the second code of the terminated session")

	// The negative control. Without it this test passes against a method that revokes
	// every code in the table, which is the failure that matters most here: it would
	// sign out every other device belonging to every user.
	assertCodeRevoked(t, unrelated.Id, false, "a code of an unrelated session")

	// Idempotent, and the count reports rows actually transitioned rather than rows
	// matched. MySQL reports changed rows, so without `revoked = false` in the
	// predicate the updated_at assignment alone would make this return 2 there and 0
	// on the other three engines.
	count, err = database.RevokeCodesBySessionIdentifier(nil, sessionA)
	if err != nil {
		t.Fatalf("second RevokeCodesBySessionIdentifier returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("re-revoking an already revoked session must report 0 rows, got %d", count)
	}
	assertCodeRevoked(t, first.Id, true, "a code after its session was revoked twice")

	// An unknown session identifier is not an error, it simply matches nothing.
	count, err = database.RevokeCodesBySessionIdentifier(nil, "revoke_missing_"+gofakeit.LetterN(8))
	if err != nil {
		t.Fatalf("RevokeCodesBySessionIdentifier for an unknown session returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("an unknown session identifier must report 0 rows, got %d", count)
	}

	// An empty identifier is rejected outright rather than used as a filter. Every
	// user_sessions row carries a UUID, so an empty value means a caller bug, and
	// matching on it would sweep codes that belong to no session under termination.
	if _, err := database.RevokeCodesBySessionIdentifier(nil, ""); err == nil {
		t.Error("an empty session identifier must return an error")
	}
	assertCodeRevoked(t, unrelated.Id, false,
		"a code of an unrelated session after the empty-identifier call")
}

// TestRevokeCodesBySessionIdentifier_TransactionAndFailurePath answers the two
// questions a mock can never answer about a new data method: does it enlist in the
// caller's transaction rather than writing through the pool, and does its failure
// path return an error rather than a benign zero. Both matter here because the
// termination helper performs three writes in one transaction, and a method that
// collapsed a database fault into (0, nil) would let the caller audit a revocation
// that never happened.
func TestRevokeCodesBySessionIdentifier_TransactionAndFailurePath(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	session := "revoke_tx_" + gofakeit.LetterN(8)
	code := createTestCodeInSession(t, client.Id, user.Id, session)

	tx := beginTx(t)
	count, err := database.RevokeCodesBySessionIdentifier(tx, session)
	if err != nil {
		t.Fatalf("RevokeCodesBySessionIdentifier in a transaction returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 code revoked inside the transaction, got %d", count)
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("RollbackTransaction: %v", err)
	}

	// Had the statement gone through the pool instead of the transaction it would have
	// survived the rollback, and a termination whose later steps failed would leave the
	// grant marked while the session stayed alive.
	assertCodeRevoked(t, code.Id, false, "a code revoked inside a rolled-back transaction")

	// The failure path, forced by the same finished transaction.
	count, err = database.RevokeCodesBySessionIdentifier(tx, session)
	if err == nil {
		t.Error("a statement that cannot run must return an error, not a benign zero count")
	}
	if count != 0 {
		t.Errorf("a failed call must report 0 rows, got %d", count)
	}
}

// TestRevokeCodeIfSessionGone covers the compensating revoke that runs immediately after a
// code is inserted (#129 decision 12). The liveness read at /auth/issue and that insert are
// two statements, so a termination can commit between them and leave a code bound to a
// session that no longer exists and that the termination's own sweep could not have marked.
func TestRevokeCodeIfSessionGone(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)

	// A session that really exists, plus a code bound to it. This is the ordinary case: the
	// statement runs after every authorization code issued, and normally matches nothing.
	liveSession := createTestUserSession(t, user.Id)
	liveCode := createTestCodeInSession(t, client.Id, user.Id, liveSession.SessionIdentifier)

	// A session identifier with no row, plus two codes bound to it.
	goneSession := "gone_" + gofakeit.LetterN(8)
	goneCode := createTestCodeInSession(t, client.Id, user.Id, goneSession)
	siblingOfGoneCode := createTestCodeInSession(t, client.Id, user.Id, goneSession)

	// Keep this row. It is the only case that fails against a method that always revokes,
	// and such a method would pass every other assertion in this test while breaking every
	// authorization code the server issues.
	revoked, err := database.RevokeCodeIfSessionGone(nil, liveCode.Id, liveSession.SessionIdentifier)
	if err != nil {
		t.Fatalf("RevokeCodeIfSessionGone for a live session returned error: %v", err)
	}
	if revoked {
		t.Error("a code whose session still exists must not be revoked")
	}
	assertCodeRevoked(t, liveCode.Id, false, "a code whose session is still alive")

	// The statement's own job. liveSession above is still in the table while this runs, which
	// is what makes this also the control for the subquery's WHERE clause: a NOT EXISTS over
	// user_sessions with no predicate would find that row and revoke nothing, forever.
	revoked, err = database.RevokeCodeIfSessionGone(nil, goneCode.Id, goneSession)
	if err != nil {
		t.Fatalf("RevokeCodeIfSessionGone for a gone session returned error: %v", err)
	}
	if !revoked {
		t.Error("a code whose session is gone must be revoked")
	}
	assertCodeRevoked(t, goneCode.Id, true, "a code whose session is gone")

	// The id term. Without it this is a session-wide sweep wearing a single-code signature,
	// and the compensating statement would revoke codes of earlier ceremonies on the same
	// session that were legitimately issued while it was alive.
	assertCodeRevoked(t, siblingOfGoneCode.Id, false,
		"another code of the same gone session, not the one named by id")

	// Idempotent, and the bool means "this call transitioned it" rather than "matched a row".
	// The revoked = false term is what makes that true, and measurement says it is needed on
	// all four engines here rather than on MySQL alone: the updated_at assignment changes on
	// every call, so without the term an already-revoked row reports as affected everywhere.
	// This interleaving is reachable rather than theoretical: it is the one where the
	// termination's sweep marked the code first and this statement then ran on the same row.
	revoked, err = database.RevokeCodeIfSessionGone(nil, goneCode.Id, goneSession)
	if err != nil {
		t.Fatalf("second RevokeCodeIfSessionGone returned error: %v", err)
	}
	if revoked {
		t.Error("re-revoking an already revoked code must report false")
	}
	assertCodeRevoked(t, goneCode.Id, true, "a code after being revoked twice")

	// An empty session identifier is rejected outright, and that guard is load bearing here
	// rather than defensive: no user_sessions row carries an empty identifier, so NOT EXISTS
	// over one is trivially true and the statement would revoke whatever code it was handed.
	if _, err := database.RevokeCodeIfSessionGone(nil, liveCode.Id, ""); err == nil {
		t.Error("an empty session identifier must return an error")
	}
	assertCodeRevoked(t, liveCode.Id, false, "a live session's code after the empty-identifier call")

	// A zero code id is a caller bug, refused the way MarkCodeAsUsed refuses it.
	if _, err := database.RevokeCodeIfSessionGone(nil, 0, goneSession); err == nil {
		t.Error("a zero code id must return an error")
	}
	assertCodeRevoked(t, siblingOfGoneCode.Id, false, "an unnamed code after the zero-id call")
}

// TestRevokeCodeIfSessionGone_TransactionAndFailurePath answers the two questions a mock
// cannot answer about a new data method, following the sweep's sibling above. The failure
// path matters more here than usual: this statement is the second of the two sweepers that
// cover each other, so collapsing a database fault into a benign false would leave a code
// bound to a terminated session unmarked with the suite green.
func TestRevokeCodeIfSessionGone_TransactionAndFailurePath(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	goneSession := "gone_tx_" + gofakeit.LetterN(8)
	code := createTestCodeInSession(t, client.Id, user.Id, goneSession)

	tx := beginTx(t)
	revoked, err := database.RevokeCodeIfSessionGone(tx, code.Id, goneSession)
	if err != nil {
		t.Fatalf("RevokeCodeIfSessionGone in a transaction returned error: %v", err)
	}
	if !revoked {
		t.Fatal("expected the code to be revoked inside the transaction")
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("RollbackTransaction: %v", err)
	}

	// Had the statement gone through the pool it would have survived the rollback. The
	// production caller passes nil, but a method that ignores its transaction parameter is
	// a trap for whichever caller composes it into one later.
	assertCodeRevoked(t, code.Id, false, "a code revoked inside a rolled-back transaction")

	revoked, err = database.RevokeCodeIfSessionGone(tx, code.Id, goneSession)
	if err == nil {
		t.Error("a statement that cannot run must return an error, not a benign false")
	}
	if revoked {
		t.Error("a failed call must report false")
	}
}

// TestUpdateCode_DoesNotClobberRevoked pins the dont-update tag on Code.Revoked
// (#129 decision 4). Nothing else in the suite fails if the tag is removed: the
// termination sweep writes the column with its own statement, while UpdateCode writes
// every untagged column from whatever the caller happens to hold, so a Code loaded
// before the termination would write revoked = false back and hand the grant to its
// holder again.
func TestUpdateCode_DoesNotClobberRevoked(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	code := createTestCode(t, client.Id, user.Id)

	if _, err := database.RevokeCodesBySessionIdentifier(nil, code.SessionIdentifier); err != nil {
		t.Fatalf("Failed to revoke the code's session: %v", err)
	}

	// The in-memory copy still reads Revoked = false, exactly as a handler that loaded
	// the code before the termination would.
	code.Used = true
	if err := database.UpdateCode(nil, code); err != nil {
		t.Fatalf("Failed to update code: %v", err)
	}

	after, err := database.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatalf("Failed to reload updated code: %v", err)
	}
	if !after.Revoked {
		t.Error("UpdateCode regressed revoked to false (is the dont-update tag missing?)")
	}
	if !after.Used {
		t.Error("the rest of the update must still apply, Used = false")
	}
}
