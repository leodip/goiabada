package cleanup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Brand assets no brand uses are swept by the claimed task once they are a day old (#813 decision
// 2): an asset is stored at its upload and attached only when a brand is saved naming it, so a day
// leaves an editor that uploaded a file and has not saved yet all the time it needs. The sweep is
// the only thing that deletes assets. The data tier holds what the delete does with the cutoff.

// The sweep is handed a cutoff a day in the past, after the pre-registration sweep and before the
// settings row is read, since it needs nothing from settings.
func TestWorker_PerformTask_SweepsUnattachedBrandAssetsADayBack(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB, metrics.NewRegistry())

	var order []string
	var createdBefore time.Time
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRevokedAccessTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { order = append(order, "pre-registrations") }).Return(nil).Once()
	mockDB.On("DeleteUnattachedBrandAssets", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			order = append(order, "brand assets")
			createdBefore = args.Get(2).(time.Time)
		}).Return(3, nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Run(func(mock.Arguments) { order = append(order, "settings") }).Return(nil, nil).Once()

	before := time.Now().UTC()
	worker.performTask(context.Background())
	after := time.Now().UTC()

	mockDB.AssertExpectations(t)
	assert.Equal(t, []string{"pre-registrations", "brand assets", "settings"}, order)
	assert.False(t, createdBefore.Before(before.Add(-24*time.Hour)),
		"cutoff %v is further back than a day from the start of the run", createdBefore)
	assert.False(t, createdBefore.After(after.Add(-24*time.Hour)),
		"cutoff %v is less than a day behind the end of the run, so it would sweep an upload an editor "+
			"has not saved yet", createdBefore)
}

// A failing sweep, such as one racing a Save that attaches an old asset and meeting the slot's
// foreign key, is logged and every step after it still runs; the next run sweeps what this one left.
func TestWorker_PerformTask_ContinuesAfterTheBrandAssetSweepFails(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	registry := metrics.NewRegistry()
	worker := New(mockDB, registry)

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRevokedAccessTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteUnattachedBrandAssets", mock.Anything, mock.Anything, mock.Anything).
		Return(0, errors.New("foreign key violation")).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}, nil).Once()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	ranEveryStep, stepFailed := worker.sweep(context.Background())

	mockDB.AssertExpectations(t)
	assert.True(t, ranEveryStep)
	assert.True(t, stepFailed, "the run is counted as failed")
}

// A shutdown during the pre-registration sweep stops the run before this one, and a shutdown during
// this one stops it before the settings read.
func TestWorker_PerformTask_StopsAroundTheBrandAssetSweepWhenCancelled(t *testing.T) {
	expectUpToPreRegistrations := func(mockDB *datamocks.Database) {
		mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteExpiredRevokedAccessTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	}

	t.Run("cancelled during the pre-registration sweep", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		worker := New(mockDB, metrics.NewRegistry())
		ctx, cancel := context.WithCancel(context.Background())
		expectUpToPreRegistrations(mockDB)
		mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { cancel() }).Return(nil).Once()

		worker.performTask(ctx)

		mockDB.AssertNotCalled(t, "DeleteUnattachedBrandAssets", mock.Anything, mock.Anything, mock.Anything)
		mockDB.AssertExpectations(t)
	})

	t.Run("cancelled during this sweep", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		worker := New(mockDB, metrics.NewRegistry())
		ctx, cancel := context.WithCancel(context.Background())
		expectUpToPreRegistrations(mockDB)
		mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteUnattachedBrandAssets", mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { cancel() }).Return(0, nil).Once()

		worker.performTask(ctx)

		mockDB.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything, mock.Anything)
		mockDB.AssertExpectations(t)
	})
}
