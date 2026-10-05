package cleanup

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
)

// The claimed cleanup run on the metrics listener (#400 decision 5): each run counted by how it
// ended, how long the last one took, and when one last completed, with that same duration on the
// run's completion record (#400 decision 11).

// cleanupSamples answers the cleanup families' sample lines in reg's exposition, keyed by series.
func cleanupSamples(t *testing.T, reg *metrics.Registry) map[string]string {
	t.Helper()

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	samples := map[string]string{}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "goiabada_cleanup_") {
			series, value, _ := strings.Cut(line, " ")
			samples[series] = value
		}
	}
	return samples
}

// sampleFloat answers a sample's value as a number.
func sampleFloat(t *testing.T, value string) float64 {
	t.Helper()
	v, err := strconv.ParseFloat(value, 64)
	require.NoError(t, err, value)
	return v
}

// armEveryStep makes every step of the claimed run succeed, the audit-log sweep included.
func armEveryStep(mockDB *datamocks.Database) {
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           30,
	}, nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, mock.Anything, auditLogDeleteBatchSize).Return(0, nil).Maybe()
}

// completionRecords answers the run's "worker task completed" records.
func completionRecords(capture *logtest.SlogCapture) []logtest.CapturedRecord {
	var found []logtest.CapturedRecord
	for _, r := range capture.Records() {
		if r.Message == "worker task completed" {
			found = append(found, r)
		}
	}
	return found
}

func TestWorker_PerformTask_AFullRunIsCountedCompletedAndTimed(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	mockDB := datamocks.NewDatabase(t)
	reg := metrics.NewRegistry()
	worker := New(mockDB, reg)

	// One step takes a measurable while, so the duration has something to measure.
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { time.Sleep(20 * time.Millisecond) }).Return(nil).Once()
	armEveryStep(mockDB)

	before := time.Now()
	worker.performTask(context.Background())
	after := time.Now()

	samples := cleanupSamples(t, reg)
	assert.Equal(t, "1", samples[`goiabada_cleanup_runs_total{outcome="completed"}`])
	assert.NotContains(t, samples, `goiabada_cleanup_runs_total{outcome="failed"}`)
	assert.NotContains(t, samples, `goiabada_cleanup_runs_total{outcome="interrupted"}`)

	lastSuccess := sampleFloat(t, samples["goiabada_cleanup_last_success_timestamp_seconds"])
	assert.GreaterOrEqual(t, lastSuccess, float64(before.Unix()))
	assert.LessOrEqual(t, lastSuccess, float64(after.Unix()+1))

	// The completion record carries the duration, at its unchanged message and level, and the gauge
	// is set from the same measurement.
	records := completionRecords(capture)
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelInfo, records[0].Level)
	duration, ok := records[0].Attrs["duration"].(time.Duration)
	require.True(t, ok, "the completion record carries a duration: %v", records[0].Attrs)
	assert.GreaterOrEqual(t, duration, 20*time.Millisecond)
	assert.LessOrEqual(t, duration, after.Sub(before))
	assert.Equal(t, duration.Seconds(), sampleFloat(t, samples["goiabada_cleanup_last_run_duration_seconds"]))
}

func TestWorker_PerformTask_ARunWithAFailedStepIsCountedFailed(t *testing.T) {
	tests := []struct {
		name string
		arm  func(mockDB *datamocks.Database)
		// completes is whether the run reaches its end and writes the completion record: every step
		// ran, one of them failed.
		completes bool
	}{
		{"a delete fails", func(mockDB *datamocks.Database) {
			mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).
				Return(errors.New("delete failed")).Once()
		}, true},
		{"the audit-log sweep fails", func(mockDB *datamocks.Database) {
			mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, mock.Anything, auditLogDeleteBatchSize).
				Return(0, errors.New("delete failed")).Once()
		}, true},
		{"the settings row cannot be read", func(mockDB *datamocks.Database) {
			mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
				Return(nil, errors.New("database is down")).Once()
		}, false},
		{"the settings row is absent", func(mockDB *datamocks.Database) {
			mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil).Once()
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			mockDB := datamocks.NewDatabase(t)
			reg := metrics.NewRegistry()
			worker := New(mockDB, reg)
			test.arm(mockDB)
			armEveryStep(mockDB)

			worker.performTask(context.Background())

			samples := cleanupSamples(t, reg)
			assert.Equal(t, "1", samples[`goiabada_cleanup_runs_total{outcome="failed"}`])
			assert.NotContains(t, samples, `goiabada_cleanup_runs_total{outcome="completed"}`)
			assert.Equal(t, "0", samples["goiabada_cleanup_last_success_timestamp_seconds"],
				"a failed run is no success")
			assert.Positive(t, sampleFloat(t, samples["goiabada_cleanup_last_run_duration_seconds"]),
				"a failed run still took the time it took")
			if test.completes {
				assert.Len(t, completionRecords(capture), 1)
			} else {
				assert.Empty(t, completionRecords(capture))
			}
		})
	}
}

func TestWorker_PerformTask_ARunCutShortByShutdownIsCountedInterrupted(t *testing.T) {
	tests := []struct {
		name string
		arm  func(mockDB *datamocks.Database, cancel context.CancelFunc)
	}{
		{"between steps", func(mockDB *datamocks.Database, cancel context.CancelFunc) {
			mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).
				Run(func(mock.Arguments) { cancel() }).Return(nil).Once()
		}},
		{"inside the audit-log sweep, its last step", func(mockDB *datamocks.Database, cancel context.CancelFunc) {
			mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, mock.Anything, auditLogDeleteBatchSize).
				Run(func(mock.Arguments) { cancel() }).Return(auditLogDeleteBatchSize, nil).Once()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			mockDB := datamocks.NewDatabase(t)
			reg := metrics.NewRegistry()
			worker := New(mockDB, reg)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			test.arm(mockDB, cancel)
			armEveryStep(mockDB)

			worker.performTask(ctx)

			samples := cleanupSamples(t, reg)
			assert.Equal(t, "1", samples[`goiabada_cleanup_runs_total{outcome="interrupted"}`])
			assert.NotContains(t, samples, `goiabada_cleanup_runs_total{outcome="completed"}`)
			assert.Equal(t, "0", samples["goiabada_cleanup_last_success_timestamp_seconds"])
			assert.Empty(t, completionRecords(capture), "a run cut short did not complete")
		})
	}
}

// Every run is counted, and the last success is the last run that completed: a failed run after it
// leaves it standing.
func TestWorker_PerformTask_TheLastSuccessOutlivesALaterFailure(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	reg := metrics.NewRegistry()
	worker := New(mockDB, reg)

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(errors.New("delete failed")).Once()
	armEveryStep(mockDB)

	worker.performTask(context.Background())
	lastSuccess := cleanupSamples(t, reg)["goiabada_cleanup_last_success_timestamp_seconds"]
	require.Positive(t, sampleFloat(t, lastSuccess))

	worker.performTask(context.Background())

	samples := cleanupSamples(t, reg)
	assert.Equal(t, "1", samples[`goiabada_cleanup_runs_total{outcome="completed"}`])
	assert.Equal(t, "1", samples[`goiabada_cleanup_runs_total{outcome="failed"}`])
	assert.Equal(t, lastSuccess, samples["goiabada_cleanup_last_success_timestamp_seconds"])
}

// Only the instance that wins the claim runs, so only it counts a run: a lost claim is no run.
func TestWorker_RunIfClaimed_ALostClaimCountsNoRun(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	reg := metrics.NewRegistry()
	worker := New(mockDB, reg)
	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()

	worker.runIfClaimed(context.Background())

	assert.Equal(t, map[string]string{
		"goiabada_cleanup_last_run_duration_seconds":      "0",
		"goiabada_cleanup_last_success_timestamp_seconds": "0",
	}, cleanupSamples(t, reg))
}
