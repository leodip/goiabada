package middleware

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/constants"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4's adapter half (#433 decision 8). audit.Log asks this for its two switches, and the
// answer is the settings MiddlewareSettings already put on the request when there are any, which
// is what keeps #212 item 2's saved read: an audited request reads the settings row once, not once
// more per event.

// The settings on the context answer, and the strict mock is given no GetSettingsById
// expectation, so a read of the row anyway fails the test as an unexpected call.
func TestAuditSwitches_AnswersFromTheRequestsSettings(t *testing.T) {
	combinations := []audit.Switches{
		{Console: false, Database: false},
		{Console: true, Database: false},
		{Console: false, Database: true},
		{Console: true, Database: true},
	}

	for _, want := range combinations {
		mockDB := mocks_data.NewDatabase(t)
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
			AuditLogsInConsoleEnabled:  want.Console,
			AuditLogsInDatabaseEnabled: want.Database,
		})

		got, err := NewAuditSwitches(mockDB).AuditSwitches(ctx)

		require.NoError(t, err)
		assert.Equal(t, want, got)
		mockDB.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything, mock.Anything)
	}
}

// Nothing usable on the context means the row is read, which is every root registration, the rate
// limiter's tiers and the background workers. The typed nil is the shape worth its own case: the
// assertion succeeds on a (*models.Settings)(nil), so a guard reading only its second result would
// dereference it and panic in the audit path of every event.
func TestAuditSwitches_ReadsTheRowWhenTheContextHasNoSettings(t *testing.T) {
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nothing on the context", ctx: context.Background()},
		{
			name: "a typed nil on the context",
			ctx:  context.WithValue(context.Background(), constants.ContextKeySettings, (*models.Settings)(nil)),
		},
		{
			name: "a value of another type on the context",
			ctx:  context.WithValue(context.Background(), constants.ContextKeySettings, "not a settings row"),
		},
	}

	for _, tc := range contexts {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			mockDB.On("GetSettingsById", tc.ctx, mock.Anything, int64(1)).Return(&models.Settings{
				AuditLogsInConsoleEnabled:  true,
				AuditLogsInDatabaseEnabled: false,
			}, nil).Once()

			var got audit.Switches
			var err error
			assert.NotPanics(t, func() {
				got, err = NewAuditSwitches(mockDB).AuditSwitches(tc.ctx)
			})

			require.NoError(t, err)
			assert.Equal(t, audit.Switches{Console: true, Database: false}, got)
			mockDB.AssertExpectations(t)
		})
	}
}

// A failed read and a missing row are both returned, for Log to record as a lost event, rather
// than answered with switches nobody chose.
func TestAuditSwitches_ARowThatCannotBeReadIsAnError(t *testing.T) {
	t.Run("the read fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, assert.AnError).Once()

		got, err := NewAuditSwitches(mockDB).AuditSwitches(context.Background())

		require.ErrorIs(t, err, assert.AnError)
		assert.Equal(t, audit.Switches{}, got)
	})

	t.Run("there is no row", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil).Once()

		var got audit.Switches
		var err error
		assert.NotPanics(t, func() {
			got, err = NewAuditSwitches(mockDB).AuditSwitches(context.Background())
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "the settings row does not exist")
		assert.Equal(t, audit.Switches{}, got)
	})
}
