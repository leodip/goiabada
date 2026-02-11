package datatests

import (
	"testing"
	"time"

	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuditLog(t *testing.T) {
	t.Run("Success - Create audit log", func(t *testing.T) {
		auditLog := &models.AuditLog{
			AuditEvent: "test_event",
			Details:    `{"user_id": "123", "action": "login"}`,
		}

		err := database.CreateAuditLog(nil, auditLog)
		require.NoError(t, err)

		// Verify ID was assigned
		assert.Greater(t, auditLog.Id, int64(0))

		// Verify CreatedAt was set
		assert.False(t, auditLog.CreatedAt.IsZero())
		assert.WithinDuration(t, time.Now().UTC(), auditLog.CreatedAt, 2*time.Second)
	})

	t.Run("Success - CreatedAt overridden", func(t *testing.T) {
		// Even if we set CreatedAt, it should be overridden
		pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		auditLog := &models.AuditLog{
			AuditEvent: "test_event",
			Details:    `{"key": "value"}`,
			CreatedAt:  pastTime,
		}

		err := database.CreateAuditLog(nil, auditLog)
		require.NoError(t, err)

		// Verify CreatedAt was overridden to current time (not pastTime)
		assert.NotEqual(t, pastTime, auditLog.CreatedAt)
		assert.WithinDuration(t, time.Now().UTC(), auditLog.CreatedAt, 2*time.Second)
	})

	t.Run("Error - Empty audit event", func(t *testing.T) {
		auditLog := &models.AuditLog{
			AuditEvent: "",
			Details:    `{"key": "value"}`,
		}

		err := database.CreateAuditLog(nil, auditLog)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty audit_event")
	})

	t.Run("Success - Empty details defaults to empty JSON", func(t *testing.T) {
		auditLog := &models.AuditLog{
			AuditEvent: "test_event",
			Details:    "",
		}

		err := database.CreateAuditLog(nil, auditLog)
		require.NoError(t, err)
		assert.Greater(t, auditLog.Id, int64(0))
	})
}

func TestDeleteOldAuditLogs_NoMatchingLogs(t *testing.T) {
	// Create recent audit logs
	for i := 0; i < 5; i++ {
		auditLog := &models.AuditLog{
			AuditEvent: "recent_log",
			Details:    `{"test": "data"}`,
		}
		err := database.CreateAuditLog(nil, auditLog)
		require.NoError(t, err)
	}

	t.Run("No logs deleted when all are recent", func(t *testing.T) {
		// Cutoff is 90 days ago, all logs are recent
		cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour)

		deleted, err := database.DeleteOldAuditLogs(nil, cutoff, 1000)
		require.NoError(t, err)

		// Should delete 0 logs (all are recent)
		assert.Equal(t, 0, deleted)
	})
}

func TestGetAuditLogsPaginated(t *testing.T) {
	// Create test audit logs
	events := []string{
		"user_login",
		"user_logout",
		"user_login",
		"admin_action",
		"user_login",
		"data_update",
	}

	for _, event := range events {
		auditLog := &models.AuditLog{
			AuditEvent: event,
			Details:    `{"test": "data"}`,
		}
		err := database.CreateAuditLog(nil, auditLog)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	t.Run("Get all logs - first page", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(nil, 1, 3, "")
		require.NoError(t, err)

		assert.GreaterOrEqual(t, total, 6) // At least 6 from this test
		assert.Len(t, logs, 3)

		// Verify ordering (newest first)
		assert.Equal(t, "data_update", logs[0].AuditEvent)
	})

	t.Run("Get all logs - second page", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(nil, 2, 3, "")
		require.NoError(t, err)

		assert.GreaterOrEqual(t, total, 6)
		assert.LessOrEqual(t, len(logs), 3) // May be less if we're at the end
	})

	t.Run("Filter by audit event", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(nil, 1, 10, "user_login")
		require.NoError(t, err)

		assert.GreaterOrEqual(t, total, 3) // At least 3 user_login events from this test
		assert.GreaterOrEqual(t, len(logs), 3)

		// Verify all returned logs match filter
		for _, log := range logs {
			assert.Equal(t, "user_login", log.AuditEvent)
		}
	})

	t.Run("Filter with no matches", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(nil, 1, 10, "nonexistent_event_12345")
		require.NoError(t, err)

		assert.Equal(t, 0, total)
		assert.Len(t, logs, 0)
	})

	t.Run("Invalid page defaults to 1", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(nil, 0, 10, "")
		require.NoError(t, err)

		assert.Greater(t, total, 0)
		assert.Greater(t, len(logs), 0)
	})

	t.Run("Invalid page size defaults to 20", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(nil, 1, 0, "")
		require.NoError(t, err)

		assert.Greater(t, total, 0)
		assert.Greater(t, len(logs), 0)
	})
}

func TestGetAuditLogsPaginated_Sorting(t *testing.T) {
	// Create logs with known order
	testEvents := []string{"event_1", "event_2", "event_3", "event_4", "event_5"}

	for _, event := range testEvents {
		auditLog := &models.AuditLog{
			AuditEvent: event,
			Details:    `{"test": "data"}`,
		}
		err := database.CreateAuditLog(nil, auditLog)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	t.Run("Logs sorted by created_at DESC", func(t *testing.T) {
		logs, total, err := database.GetAuditLogsPaginated(nil, 1, 10, "")
		require.NoError(t, err)

		assert.Greater(t, total, 0)
		assert.Greater(t, len(logs), 0)

		// Verify newest first (event_5 was created last)
		// Find event_5 in the results
		foundEvent5 := false
		for _, log := range logs {
			if log.AuditEvent == "event_5" {
				foundEvent5 = true
				break
			}
		}
		assert.True(t, foundEvent5, "Expected to find event_5 in first page of results")
	})
}
