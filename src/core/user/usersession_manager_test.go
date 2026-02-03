package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
)

// =============================================================================
// Tests for shouldUpgradeAcrLevel
// =============================================================================

func TestShouldUpgradeAcrLevel(t *testing.T) {
	// Test all valid ACR level upgrade scenarios
	t.Run("level1 to level2_optional should upgrade", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel1.String(),
			enums.AcrLevel2Optional.String(),
		)
		assert.True(t, result, "level1 → level2_optional should return true (upgrade)")
	})

	t.Run("level1 to level2_mandatory should upgrade", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel1.String(),
			enums.AcrLevel2Mandatory.String(),
		)
		assert.True(t, result, "level1 → level2_mandatory should return true (upgrade)")
	})

	t.Run("level2_optional to level2_mandatory should upgrade", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel2Optional.String(),
			enums.AcrLevel2Mandatory.String(),
		)
		assert.True(t, result, "level2_optional → level2_mandatory should return true (upgrade)")
	})

	// Test all valid ACR level NO upgrade scenarios (same or downgrade)
	t.Run("level2_optional to level1 should NOT upgrade (downgrade)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel2Optional.String(),
			enums.AcrLevel1.String(),
		)
		assert.False(t, result, "level2_optional → level1 should return false (no downgrade)")
	})

	t.Run("level2_mandatory to level1 should NOT upgrade (downgrade)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel2Mandatory.String(),
			enums.AcrLevel1.String(),
		)
		assert.False(t, result, "level2_mandatory → level1 should return false (no downgrade)")
	})

	t.Run("level2_mandatory to level2_optional should NOT upgrade (downgrade)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel2Mandatory.String(),
			enums.AcrLevel2Optional.String(),
		)
		assert.False(t, result, "level2_mandatory → level2_optional should return false (no downgrade)")
	})

	// Test same level scenarios
	t.Run("level1 to level1 should NOT upgrade (same)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel1.String(),
			enums.AcrLevel1.String(),
		)
		assert.False(t, result, "level1 → level1 should return false (same level)")
	})

	t.Run("level2_optional to level2_optional should NOT upgrade (same)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel2Optional.String(),
			enums.AcrLevel2Optional.String(),
		)
		assert.False(t, result, "level2_optional → level2_optional should return false (same level)")
	})

	t.Run("level2_mandatory to level2_mandatory should NOT upgrade (same)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel2Mandatory.String(),
			enums.AcrLevel2Mandatory.String(),
		)
		assert.False(t, result, "level2_mandatory → level2_mandatory should return false (same level)")
	})

	// Test unknown/invalid ACR levels (fail-safe behavior)
	t.Run("unknown current ACR should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			"unknown:acr:level",
			enums.AcrLevel2Mandatory.String(),
		)
		assert.False(t, result, "unknown current ACR should return false (fail-safe)")
	})

	t.Run("unknown new ACR should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel1.String(),
			"unknown:acr:level",
		)
		assert.False(t, result, "unknown new ACR should return false (fail-safe)")
	})

	t.Run("both unknown ACRs should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			"unknown:acr:level1",
			"unknown:acr:level2",
		)
		assert.False(t, result, "both unknown ACRs should return false (fail-safe)")
	})

	t.Run("empty current ACR should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			"",
			enums.AcrLevel2Mandatory.String(),
		)
		assert.False(t, result, "empty current ACR should return false (fail-safe)")
	})

	t.Run("empty new ACR should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			enums.AcrLevel1.String(),
			"",
		)
		assert.False(t, result, "empty new ACR should return false (fail-safe)")
	})

	t.Run("both empty ACRs should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel("", "")
		assert.False(t, result, "both empty ACRs should return false (fail-safe)")
	})
}

// =============================================================================
// Tests for BumpUserSession - Step-up Authentication Logic
// =============================================================================

func TestBumpUserSession_StepUpAuthentication(t *testing.T) {
	// Helper to create a basic request with remote address
	createRequest := func() *http.Request {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		return req
	}

	// Helper to create a user session with specific ACR/AMR
	createUserSession := func(acrLevel, authMethods string) *models.UserSession {
		return &models.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          acrLevel,
			AuthMethods:       authMethods,
			IpAddress:         "192.168.1.1",
			LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
			Clients:           []models.UserSessionClient{},
		}
	}

	t.Run("Step-up: level1 to level2_optional upgrades ACR and updates AuthMethods", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		// Session starts at level1 with password only
		userSession := createUserSession(enums.AcrLevel1.String(), "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// Verify the session was updated with new ACR and AuthMethods
			return s.AcrLevel == enums.AcrLevel2Optional.String() &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		// Step-up to level2_optional with pwd+otp
		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", enums.AcrLevel2Optional.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Optional.String(), result.AcrLevel)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("Step-up: level1 to level2_mandatory upgrades ACR and updates AuthMethods", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		userSession := createUserSession(enums.AcrLevel1.String(), "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			return s.AcrLevel == enums.AcrLevel2Mandatory.String() &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", enums.AcrLevel2Mandatory.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Mandatory.String(), result.AcrLevel)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("Step-up: level2_optional to level2_mandatory upgrades ACR", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		// Already at level2_optional with pwd+otp
		userSession := createUserSession(enums.AcrLevel2Optional.String(), "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// ACR should upgrade, AuthMethods should stay the same
			return s.AcrLevel == enums.AcrLevel2Mandatory.String() &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", enums.AcrLevel2Mandatory.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Mandatory.String(), result.AcrLevel)

		database.AssertExpectations(t)
	})

	t.Run("No downgrade: level2_mandatory to level1 preserves higher ACR", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		// Session is at level2_mandatory
		userSession := createUserSession(enums.AcrLevel2Mandatory.String(), "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// ACR should NOT be downgraded, should remain level2_mandatory
			return s.AcrLevel == enums.AcrLevel2Mandatory.String()
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		// Request level1, but session should stay at level2_mandatory
		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", enums.AcrLevel1.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Mandatory.String(), result.AcrLevel,
			"ACR should NOT be downgraded from level2_mandatory to level1")

		database.AssertExpectations(t)
	})

	t.Run("No downgrade: level2_optional to level1 preserves higher ACR", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		userSession := createUserSession(enums.AcrLevel2Optional.String(), "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			return s.AcrLevel == enums.AcrLevel2Optional.String()
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", enums.AcrLevel1.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Optional.String(), result.AcrLevel,
			"ACR should NOT be downgraded from level2_optional to level1")

		database.AssertExpectations(t)
	})

	t.Run("Same level: no ACR change when levels are equal", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		userSession := createUserSession(enums.AcrLevel2Optional.String(), "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			return s.AcrLevel == enums.AcrLevel2Optional.String() &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", enums.AcrLevel2Optional.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Optional.String(), result.AcrLevel)

		database.AssertExpectations(t)
	})

	t.Run("Empty authMethods preserves existing AuthMethods", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		userSession := createUserSession(enums.AcrLevel1.String(), "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// AuthMethods should remain "pwd" when empty string passed
			return s.AuthMethods == "pwd"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		// Pass empty authMethods - should preserve existing
		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"", enums.AcrLevel1.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "pwd", result.AuthMethods,
			"AuthMethods should be preserved when empty string is passed")

		database.AssertExpectations(t)
	})

	t.Run("Empty acrLevel preserves existing AcrLevel", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		userSession := createUserSession(enums.AcrLevel2Optional.String(), "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// AcrLevel should remain level2_optional when empty string passed
			return s.AcrLevel == enums.AcrLevel2Optional.String()
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		// Pass empty acrLevel - should preserve existing
		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", "")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Optional.String(), result.AcrLevel,
			"AcrLevel should be preserved when empty string is passed")

		database.AssertExpectations(t)
	})

	t.Run("Both empty strings preserve existing ACR and AuthMethods (refresh token scenario)", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		userSession := createUserSession(enums.AcrLevel2Mandatory.String(), "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// Both should be preserved
			return s.AcrLevel == enums.AcrLevel2Mandatory.String() &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		// This is the refresh token scenario - both empty
		result, err := manager.BumpUserSession(req, "test-session-id", 456, "", "")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, enums.AcrLevel2Mandatory.String(), result.AcrLevel)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("AuthMethods updated when different (same ACR level)", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		// Edge case: same ACR but different auth methods string
		// (This shouldn't normally happen, but we should handle it)
		userSession := createUserSession(enums.AcrLevel2Optional.String(), "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// AuthMethods should be updated
			return s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(req, "test-session-id", 456,
			"pwd otp", enums.AcrLevel2Optional.String())

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("Session not found returns error", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest()

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "non-existent-session").
			Return(nil, nil)

		result, err := manager.BumpUserSession(req, "non-existent-session", 456,
			"pwd", enums.AcrLevel1.String())

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "can't bump user session because user session is nil")

		database.AssertExpectations(t)
	})
}

// =============================================================================
// Tests for BumpUserSession - Client and IP Tracking (existing functionality)
// =============================================================================

func TestBumpUserSession_ClientTracking(t *testing.T) {
	createRequest := func(remoteAddr string) *http.Request {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = remoteAddr
		return req
	}

	t.Run("New client is added to session", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest("192.168.1.1:12345")

		userSession := &models.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          enums.AcrLevel1.String(),
			AuthMethods:       "pwd",
			IpAddress:         "192.168.1.1",
			LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
			Clients: []models.UserSessionClient{
				{Id: 1, ClientId: 100, UserSessionId: 1},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, userSession).Return(nil)
		database.On("UpdateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.MatchedBy(func(c *models.UserSessionClient) bool {
			return c.ClientId == 200
		})).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		// Add new client 200
		result, err := manager.BumpUserSession(req, "test-session-id", 200, "", "")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Clients, 2, "Should have 2 clients now")

		database.AssertExpectations(t)
	})

	t.Run("Existing client updates LastAccessed", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest("192.168.1.1:12345")

		oldTime := time.Now().UTC().Add(-1 * time.Hour)
		userSession := &models.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          enums.AcrLevel1.String(),
			AuthMethods:       "pwd",
			IpAddress:         "192.168.1.1",
			LastAccessed:      oldTime,
			Clients: []models.UserSessionClient{
				{Id: 1, ClientId: 100, UserSessionId: 1, LastAccessed: oldTime},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, userSession).Return(nil)
		database.On("UpdateUserSessionClient", mock.Anything, mock.MatchedBy(func(c *models.UserSessionClient) bool {
			// LastAccessed should be updated to a newer time
			return c.ClientId == 100 && c.LastAccessed.After(oldTime)
		})).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		// Same client 100 again
		result, err := manager.BumpUserSession(req, "test-session-id", 100, "", "")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Clients, 1, "Should still have 1 client")

		database.AssertExpectations(t)
	})

	t.Run("New IP is concatenated to existing", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest("10.0.0.1:12345") // Different IP

		userSession := &models.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          enums.AcrLevel1.String(),
			AuthMethods:       "pwd",
			IpAddress:         "192.168.1.1", // Original IP
			LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
			Clients:           []models.UserSessionClient{},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// IP should be concatenated
			return s.IpAddress == "192.168.1.1,10.0.0.1"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(req, "test-session-id", 100, "", "")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "192.168.1.1,10.0.0.1", result.IpAddress)

		database.AssertExpectations(t)
	})

	t.Run("Same IP is not duplicated", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		manager := &UserSessionManager{database: database}
		req := createRequest("192.168.1.1:12345") // Same IP

		userSession := &models.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          enums.AcrLevel1.String(),
			AuthMethods:       "pwd",
			IpAddress:         "192.168.1.1",
			LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
			Clients:           []models.UserSessionClient{},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).
			Return(nil)
		database.On("BeginTransaction").Return(nil, nil)
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			// IP should NOT be duplicated
			return s.IpAddress == "192.168.1.1"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil)
		database.On("CommitTransaction", mock.Anything).Return(nil)
		database.On("RollbackTransaction", mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(req, "test-session-id", 100, "", "")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "192.168.1.1", result.IpAddress, "IP should not be duplicated")

		database.AssertExpectations(t)
	})
}

// =============================================================================
// Tests for HasValidUserSession
// =============================================================================

func TestHasValidUserSession(t *testing.T) {
	createSettings := func(idleTimeout, maxLifetime int) *models.Settings {
		return &models.Settings{
			UserSessionIdleTimeoutInSeconds: idleTimeout,
			UserSessionMaxLifetimeInSeconds: maxLifetime,
		}
	}

	createContext := func(settings *models.Settings) context.Context {
		return context.WithValue(context.Background(), constants.ContextKeySettings, settings)
	}

	t.Run("nil session returns false", func(t *testing.T) {
		manager := &UserSessionManager{}
		settings := createSettings(3600, 86400)
		ctx := createContext(settings)

		result := manager.HasValidUserSession(ctx, nil, nil)

		assert.False(t, result)
	})

	t.Run("valid session within idle and max lifetime returns true", func(t *testing.T) {
		manager := &UserSessionManager{}
		settings := createSettings(3600, 86400) // 1 hour idle, 24 hours max
		ctx := createContext(settings)

		userSession := &models.UserSession{
			Started:      time.Now().UTC().Add(-1 * time.Hour),    // Started 1 hour ago
			LastAccessed: time.Now().UTC().Add(-10 * time.Minute), // Last accessed 10 minutes ago
		}

		result := manager.HasValidUserSession(ctx, userSession, nil)

		assert.True(t, result)
	})

	t.Run("session expired by idle timeout returns false", func(t *testing.T) {
		manager := &UserSessionManager{}
		settings := createSettings(3600, 86400) // 1 hour idle timeout
		ctx := createContext(settings)

		userSession := &models.UserSession{
			Started:      time.Now().UTC().Add(-2 * time.Hour), // Started 2 hours ago
			LastAccessed: time.Now().UTC().Add(-2 * time.Hour), // Last accessed 2 hours ago (exceeds 1 hour idle)
		}

		result := manager.HasValidUserSession(ctx, userSession, nil)

		assert.False(t, result)
	})

	t.Run("session expired by max lifetime returns false", func(t *testing.T) {
		manager := &UserSessionManager{}
		settings := createSettings(3600, 3600) // 1 hour max lifetime
		ctx := createContext(settings)

		userSession := &models.UserSession{
			Started:      time.Now().UTC().Add(-2 * time.Hour),   // Started 2 hours ago (exceeds 1 hour max)
			LastAccessed: time.Now().UTC().Add(-1 * time.Minute), // Recently accessed
		}

		result := manager.HasValidUserSession(ctx, userSession, nil)

		assert.False(t, result)
	})

	t.Run("max_age parameter respected", func(t *testing.T) {
		manager := &UserSessionManager{}
		settings := createSettings(86400, 86400) // 24 hours for both
		ctx := createContext(settings)

		userSession := &models.UserSession{
			Started:      time.Now().UTC().Add(-2 * time.Hour), // Started 2 hours ago
			LastAccessed: time.Now().UTC().Add(-1 * time.Minute),
		}

		maxAge := 3600 // 1 hour max_age requested by client
		result := manager.HasValidUserSession(ctx, userSession, &maxAge)

		// Session started 2 hours ago, but max_age is 1 hour - should be invalid
		assert.False(t, result)
	})

	t.Run("max_age parameter allows valid session", func(t *testing.T) {
		manager := &UserSessionManager{}
		settings := createSettings(86400, 86400)
		ctx := createContext(settings)

		userSession := &models.UserSession{
			Started:      time.Now().UTC().Add(-30 * time.Minute), // Started 30 minutes ago
			LastAccessed: time.Now().UTC().Add(-1 * time.Minute),
		}

		maxAge := 3600 // 1 hour max_age - session is within this
		result := manager.HasValidUserSession(ctx, userSession, &maxAge)

		assert.True(t, result)
	})
}
