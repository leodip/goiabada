package usersession

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// =============================================================================
// Tests for shouldUpgradeAcrLevel
// =============================================================================

func TestShouldUpgradeAcrLevel(t *testing.T) {
	// Test all valid ACR level upgrade scenarios
	t.Run("level1 to level2_optional should upgrade", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel1,
			record.AcrLevel2Optional,
		)
		assert.True(t, result, "level1 → level2_optional should return true (upgrade)")
	})

	t.Run("level1 to level2_mandatory should upgrade", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel1,
			record.AcrLevel2Mandatory,
		)
		assert.True(t, result, "level1 → level2_mandatory should return true (upgrade)")
	})

	t.Run("level2_optional to level2_mandatory should upgrade", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel2Optional,
			record.AcrLevel2Mandatory,
		)
		assert.True(t, result, "level2_optional → level2_mandatory should return true (upgrade)")
	})

	// Test all valid ACR level NO upgrade scenarios (same or downgrade)
	t.Run("level2_optional to level1 should NOT upgrade (downgrade)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel2Optional,
			record.AcrLevel1,
		)
		assert.False(t, result, "level2_optional → level1 should return false (no downgrade)")
	})

	t.Run("level2_mandatory to level1 should NOT upgrade (downgrade)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel2Mandatory,
			record.AcrLevel1,
		)
		assert.False(t, result, "level2_mandatory → level1 should return false (no downgrade)")
	})

	t.Run("level2_mandatory to level2_optional should NOT upgrade (downgrade)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel2Mandatory,
			record.AcrLevel2Optional,
		)
		assert.False(t, result, "level2_mandatory → level2_optional should return false (no downgrade)")
	})

	// Test same level scenarios
	t.Run("level1 to level1 should NOT upgrade (same)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel1,
			record.AcrLevel1,
		)
		assert.False(t, result, "level1 → level1 should return false (same level)")
	})

	t.Run("level2_optional to level2_optional should NOT upgrade (same)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel2Optional,
			record.AcrLevel2Optional,
		)
		assert.False(t, result, "level2_optional → level2_optional should return false (same level)")
	})

	t.Run("level2_mandatory to level2_mandatory should NOT upgrade (same)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel2Mandatory,
			record.AcrLevel2Mandatory,
		)
		assert.False(t, result, "level2_mandatory → level2_mandatory should return false (same level)")
	})

	// Test unknown/invalid ACR levels (fail-safe behavior)
	t.Run("unknown current ACR should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			"unknown:acr:level",
			record.AcrLevel2Mandatory,
		)
		assert.False(t, result, "unknown current ACR should return false (fail-safe)")
	})

	t.Run("unknown new ACR should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel1,
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
			record.AcrLevel2Mandatory,
		)
		assert.False(t, result, "empty current ACR should return false (fail-safe)")
	})

	t.Run("empty new ACR should NOT upgrade (fail-safe)", func(t *testing.T) {
		result := shouldUpgradeAcrLevel(
			record.AcrLevel1,
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
	// Helper to create a user session with specific ACR/AMR
	createUserSession := func(acrLevel record.AcrLevel, authMethods string) *record.UserSession {
		return &record.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          acrLevel,
			AuthMethods:       authMethods,
			IpAddress:         "192.168.1.1",
			LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
			Clients:           []record.UserSessionClient{},
		}
	}

	t.Run("Step-up: level1 to level2_optional upgrades ACR and updates AuthMethods", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		// Session starts at level1 with password only
		userSession := createUserSession(record.AcrLevel1, "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			// Verify the session was updated with new ACR and AuthMethods
			return s.AcrLevel == record.AcrLevel2Optional &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Step-up to level2_optional with pwd+otp
		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", record.AcrLevel2Optional, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Optional, result.AcrLevel)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("Step-up: level1 to level2_mandatory upgrades ACR and updates AuthMethods", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		userSession := createUserSession(record.AcrLevel1, "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			return s.AcrLevel == record.AcrLevel2Mandatory &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", record.AcrLevel2Mandatory, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Mandatory, result.AcrLevel)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("Step-up: level2_optional to level2_mandatory upgrades ACR", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		// Already at level2_optional with pwd+otp
		userSession := createUserSession(record.AcrLevel2Optional, "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			// ACR should upgrade, AuthMethods should stay the same
			return s.AcrLevel == record.AcrLevel2Mandatory &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", record.AcrLevel2Mandatory, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Mandatory, result.AcrLevel)

		database.AssertExpectations(t)
	})

	t.Run("No downgrade: level2_mandatory to level1 preserves higher ACR", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		// Session is at level2_mandatory
		userSession := createUserSession(record.AcrLevel2Mandatory, "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			// ACR should NOT be downgraded, should remain level2_mandatory
			return s.AcrLevel == record.AcrLevel2Mandatory
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Request level1, but session should stay at level2_mandatory
		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", record.AcrLevel1, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Mandatory, result.AcrLevel,
			"ACR should NOT be downgraded from level2_mandatory to level1")

		database.AssertExpectations(t)
	})

	t.Run("No downgrade: level2_optional to level1 preserves higher ACR", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		userSession := createUserSession(record.AcrLevel2Optional, "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			return s.AcrLevel == record.AcrLevel2Optional
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", record.AcrLevel1, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Optional, result.AcrLevel,
			"ACR should NOT be downgraded from level2_optional to level1")

		database.AssertExpectations(t)
	})

	t.Run("Same level: no ACR change when levels are equal", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		userSession := createUserSession(record.AcrLevel2Optional, "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			return s.AcrLevel == record.AcrLevel2Optional &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", record.AcrLevel2Optional, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Optional, result.AcrLevel)

		database.AssertExpectations(t)
	})

	t.Run("Empty authMethods preserves existing AuthMethods", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		userSession := createUserSession(record.AcrLevel1, "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			// AuthMethods should remain "pwd" when empty string passed
			return s.AuthMethods == "pwd"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Pass empty authMethods - should preserve existing
		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"", record.AcrLevel1, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "pwd", result.AuthMethods,
			"AuthMethods should be preserved when empty string is passed")

		database.AssertExpectations(t)
	})

	t.Run("Empty acrLevel preserves existing AcrLevel", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		userSession := createUserSession(record.AcrLevel2Optional, "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			// AcrLevel should remain level2_optional when empty string passed
			return s.AcrLevel == record.AcrLevel2Optional
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Pass empty acrLevel - should preserve existing
		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", "", "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Optional, result.AcrLevel,
			"AcrLevel should be preserved when empty string is passed")

		database.AssertExpectations(t)
	})

	t.Run("Both empty strings preserve existing ACR and AuthMethods (refresh token scenario)", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		userSession := createUserSession(record.AcrLevel2Mandatory, "pwd otp")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			// Both should be preserved
			return s.AcrLevel == record.AcrLevel2Mandatory &&
				s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// This is the refresh token scenario - both empty
		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456, "", "", "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, record.AcrLevel2Mandatory, result.AcrLevel)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("AuthMethods updated when different (same ACR level)", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		// Edge case: same ACR but different auth methods string
		// (This shouldn't normally happen, but we should handle it)
		userSession := createUserSession(record.AcrLevel2Optional, "pwd")

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, mock.MatchedBy(func(s *record.UserSession) bool {
			// AuthMethods should be updated
			return s.AuthMethods == "pwd otp"
		})).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 456,
			"pwd otp", record.AcrLevel2Optional, "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "pwd otp", result.AuthMethods)

		database.AssertExpectations(t)
	})

	t.Run("Session not found returns error", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		// The read is on the transaction, since the decision it feeds is taken there (#249).
		stub := datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, "non-existent-session").
			Return(nil, nil).Once()

		result, err := manager.BumpUserSession(context.Background(), "non-existent-session", 456,
			"pwd", record.AcrLevel1, "192.168.1.1")

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "can't bump user session because user session is nil")
		assert.Error(t, stub.BodyErr, "the transaction rolled back, and nothing was written")

		database.AssertExpectations(t)
		database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
	})
}

// =============================================================================
// Tests for BumpUserSession - Client and IP Tracking (existing functionality)
// =============================================================================

func TestBumpUserSession_ClientTracking(t *testing.T) {
	t.Run("New client is added to session", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		userSession := &record.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          record.AcrLevel1,
			AuthMethods:       "pwd",
			IpAddress:         "192.168.1.1",
			LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
			Clients: []record.UserSessionClient{
				{Id: 1, ClientId: 100, UserSessionId: 1},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, userSession).Return(nil)
		database.On("UpdateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		database.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.MatchedBy(func(c *record.UserSessionClient) bool {
			return c.ClientId == 200
		})).Return(nil)

		// Add new client 200
		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 200, "", "", "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Clients, 2, "Should have 2 clients now")

		database.AssertExpectations(t)
	})

	t.Run("Existing client updates LastAccessed", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		manager := &Manager{database: database}

		oldTime := time.Now().UTC().Add(-1 * time.Hour)
		userSession := &record.UserSession{
			Id:                1,
			SessionIdentifier: "test-session-id",
			UserId:            123,
			AcrLevel:          record.AcrLevel1,
			AuthMethods:       "pwd",
			IpAddress:         "192.168.1.1",
			LastAccessed:      oldTime,
			Clients: []record.UserSessionClient{
				{Id: 1, ClientId: 100, UserSessionId: 1, LastAccessed: oldTime},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
			Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
			Return(nil)
		datamocks.ExpectRunInTransaction(database, txSentinel)
		database.On("UpdateUserSession", mock.Anything, mock.Anything, userSession).Return(nil)
		database.On("UpdateUserSessionClient", mock.Anything, mock.Anything, mock.MatchedBy(func(c *record.UserSessionClient) bool {
			// LastAccessed should be updated to a newer time
			return c.ClientId == 100 && c.LastAccessed.After(oldTime)
		})).Return(nil)

		// Same client 100 again
		result, err := manager.BumpUserSession(context.Background(), "test-session-id", 100, "", "", "192.168.1.1")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Clients, 1, "Should still have 1 client")

		database.AssertExpectations(t)
	})
}

// TestBumpUserSession_RecordsTheLatestAddress is decision 17 of #433 at the manager: a session
// holds the latest address its browser was seen from, one address and no history. A bump given an
// address overwrites the recorded one, whatever the two have in common, and a bump given none
// leaves it, which is what the token endpoint's refresh bump relies on (#243).
func TestBumpUserSession_RecordsTheLatestAddress(t *testing.T) {
	testCases := []struct {
		name      string
		stored    string
		given     string
		wantAfter string
	}{
		{"a new address replaces the recorded one", "192.168.1.1", "10.0.0.1", "10.0.0.1"},
		// The substring test this replaced read 10.0.0.1 as already present in 10.0.0.12 and kept
		// the old value.
		{"an address the recorded one contains still replaces it", "10.0.0.12", "10.0.0.1", "10.0.0.1"},
		{"a history left by an earlier binary collapses to the latest address", "192.168.1.1,10.0.0.1", "172.16.0.5", "172.16.0.5"},
		{"the same address stays as it is", "192.168.1.1", "192.168.1.1", "192.168.1.1"},
		{"an empty address leaves the recorded one", "192.168.1.1", "", "192.168.1.1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			manager := &Manager{database: database}

			userSession := &record.UserSession{
				Id:                1,
				SessionIdentifier: "test-session-id",
				UserId:            123,
				AcrLevel:          record.AcrLevel1,
				AuthMethods:       "pwd",
				IpAddress:         tc.stored,
				LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
				Clients:           []record.UserSessionClient{},
			}

			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test-session-id").
				Return(userSession, nil)
			database.On("UserSessionLoadClients", mock.Anything, mock.Anything, userSession).
				Return(nil)
			datamocks.ExpectRunInTransaction(database, txSentinel)
			database.On("UpdateUserSession", mock.Anything, txSentinel, mock.MatchedBy(func(s *record.UserSession) bool {
				return s.IpAddress == tc.wantAfter
			})).Return(nil).Once()
			database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

			result, err := manager.BumpUserSession(context.Background(), "test-session-id", 100, "", "", tc.given)

			require.NoError(t, err)
			assert.Equal(t, tc.wantAfter, result.IpAddress)
		})
	}
}

// =============================================================================
// Tests for HasValidUserSession
// =============================================================================

// TestHasValidUserSession is the manager's row of the services table: it judges a session on its
// own clock with the two lifetimes its caller passes, in that order. Idle and max lifetime are
// distinct in every case, so a manager that swapped the two adjacent ints fails one (#433
// decision 9). The validity rules themselves are UserSession.IsValid's, tested in record.
func TestHasValidUserSession(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	manager := &Manager{now: func() time.Time { return now }}

	const idle = 3600         // one hour
	const maxLifetime = 86400 // one day

	t.Run("nil session returns false", func(t *testing.T) {
		assert.False(t, manager.HasValidUserSession(nil, idle, maxLifetime, nil))
	})

	t.Run("valid session within idle and max lifetime returns true", func(t *testing.T) {
		userSession := &record.UserSession{
			Started:      now.Add(-2 * time.Hour),
			LastAccessed: now.Add(-10 * time.Minute),
			AuthTime:     now.Add(-2 * time.Hour),
		}
		assert.True(t, manager.HasValidUserSession(userSession, idle, maxLifetime, nil))
	})

	t.Run("the first int is the idle timeout, measured from LastAccessed", func(t *testing.T) {
		// Idle for two hours, well inside the day's lifetime: invalid only if the first int is
		// the idle bound. Swapped, two hours of idleness against a day would pass.
		userSession := &record.UserSession{
			Started:      now.Add(-3 * time.Hour),
			LastAccessed: now.Add(-2 * time.Hour),
			AuthTime:     now.Add(-3 * time.Hour),
		}
		assert.False(t, manager.HasValidUserSession(userSession, idle, maxLifetime, nil))
	})

	t.Run("the second int is the max lifetime, measured from Started", func(t *testing.T) {
		// Started two hours ago and used a minute ago: valid only if the second int is the
		// lifetime. Swapped, two hours against the one-hour idle value would refuse it.
		userSession := &record.UserSession{
			Started:      now.Add(-2 * time.Hour),
			LastAccessed: now.Add(-time.Minute),
			AuthTime:     now.Add(-2 * time.Hour),
		}
		assert.True(t, manager.HasValidUserSession(userSession, idle, maxLifetime, nil))

		expired := &record.UserSession{
			Started:      now.Add(-25 * time.Hour),
			LastAccessed: now.Add(-time.Minute),
			AuthTime:     now.Add(-25 * time.Hour),
		}
		assert.False(t, manager.HasValidUserSession(expired, idle, maxLifetime, nil))
	})

	t.Run("max_age is measured from AuthTime on the manager's clock", func(t *testing.T) {
		userSession := &record.UserSession{
			Started:      now.Add(-20 * time.Hour),
			LastAccessed: now.Add(-time.Minute),
			AuthTime:     now.Add(-5 * time.Minute),
		}
		maxAge := int64(3600)
		assert.True(t, manager.HasValidUserSession(userSession, idle, maxLifetime, &maxAge))

		userSession.AuthTime = now.Add(-2 * time.Hour)
		assert.False(t, manager.HasValidUserSession(userSession, idle, maxLifetime, &maxAge))
	})

	t.Run("the clock is the manager's, not the wall clock", func(t *testing.T) {
		// Valid against the fixed now, and long expired against the real one.
		userSession := &record.UserSession{
			Started:      now.Add(-time.Minute),
			LastAccessed: now.Add(-time.Minute),
			AuthTime:     now.Add(-time.Minute),
		}
		assert.True(t, manager.HasValidUserSession(userSession, idle, maxLifetime, nil))
		assert.False(t, (&Manager{now: func() time.Time { return now.Add(48 * time.Hour) }}).
			HasValidUserSession(userSession, idle, maxLifetime, nil))
	})
}

// =============================================================================
// Tests for WillRaisePrivilege
// =============================================================================

// TestWillRaisePrivilege pins the predicate /auth/completed gates the browser session's
// identifier rotation on (#266 decision 6).
//
// It is worth its own cases rather than being left to the step-up tests above, because a
// wrong answer here is silent in both directions: false when it should be true drops the
// rotation and leaves an identifier stolen at level 1 working after a step-up, and neither
// the bump nor the token that follows looks any different for it.
func TestWillRaisePrivilege(t *testing.T) {
	tests := []struct {
		name        string
		userSession *record.UserSession
		authMethods string
		acrLevel    record.AcrLevel
		expected    bool
	}{
		{
			name:        "Nil session raises nothing",
			userSession: nil,
			authMethods: "pwd otp",
			acrLevel:    record.AcrLevel2Mandatory,
			expected:    false,
		},
		{
			name:        "Neither changes",
			userSession: &record.UserSession{AuthMethods: "pwd", AcrLevel: record.AcrLevel1},
			authMethods: "pwd",
			acrLevel:    record.AcrLevel1,
			expected:    false,
		},
		{
			name:        "Auth methods rise",
			userSession: &record.UserSession{AuthMethods: "pwd", AcrLevel: record.AcrLevel1},
			authMethods: "pwd otp",
			acrLevel:    record.AcrLevel1,
			expected:    true,
		},
		{
			name:        "ACR level rises",
			userSession: &record.UserSession{AuthMethods: "pwd", AcrLevel: record.AcrLevel1},
			authMethods: "pwd",
			acrLevel:    record.AcrLevel2Mandatory,
			expected:    true,
		},
		{
			// The session already holds the stronger level, so this ceremony is not a
			// step-up and rotating would spend a write on nothing.
			name:        "ACR level would be downgraded",
			userSession: &record.UserSession{AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory},
			authMethods: "pwd otp",
			acrLevel:    record.AcrLevel1,
			expected:    false,
		},
		{
			// An empty incoming value means the ceremony recorded nothing, which is not a
			// change. Reading it as one would rotate on every SSO reuse.
			name:        "Empty inputs change nothing",
			userSession: &record.UserSession{AuthMethods: "pwd", AcrLevel: record.AcrLevel1},
			authMethods: "",
			acrLevel:    "",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected,
				WillRaisePrivilege(tt.userSession, tt.authMethods, tt.acrLevel))
		})
	}
}
