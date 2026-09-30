package userconsent

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	consentUserId   = int64(7)
	consentClientId = int64(3)
)

func TestRecord_CreatesAConsentWhenNoneIsStored(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("GetConsentByUserIdAndClientId", mock.Anything, (*sql.Tx)(nil), consentUserId, consentClientId).Return(nil, nil)

	var created *models.UserConsent
	db.On("CreateUserConsent", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) {
			created = args.Get(2).(*models.UserConsent)
			created.Id = 11
		}).
		Return(nil)

	before := time.Now().UTC()
	consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid profile")
	require.NoError(t, err)

	assert.Same(t, created, consent, "the row returned is the row written")
	assert.Equal(t, int64(11), consent.Id)
	assert.Equal(t, consentUserId, consent.UserId)
	assert.Equal(t, consentClientId, consent.ClientId)
	assert.Equal(t, "openid profile", consent.Scope)
	require.True(t, consent.GrantedAt.Valid, "a new consent records when it was granted")
	assert.False(t, consent.GrantedAt.Time.Before(before))
	assert.Equal(t, time.UTC, consent.GrantedAt.Time.Location())
	db.AssertNotCalled(t, "UpdateUserConsent", mock.Anything, mock.Anything, mock.Anything)
}

func TestRecord_ReplacesAStoredConsentWhole(t *testing.T) {
	grantedAt := sql.NullTime{Time: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), Valid: true}
	stored := &models.UserConsent{
		Id: 5, UserId: consentUserId, ClientId: consentClientId, Scope: "openid profile email", GrantedAt: grantedAt,
	}
	db := mocks_data.NewDatabase(t)
	db.On("GetConsentByUserIdAndClientId", mock.Anything, (*sql.Tx)(nil), consentUserId, consentClientId).Return(stored, nil)
	db.On("UpdateUserConsent", mock.Anything, (*sql.Tx)(nil), stored).Return(nil)

	consent, err := Record(context.Background(), db, consentUserId, consentClientId, "email")
	require.NoError(t, err)

	assert.Same(t, stored, consent)
	assert.Equal(t, int64(5), consent.Id, "the stored row is rewritten, not a second one created")
	assert.Equal(t, "email", consent.Scope, "the scope is replaced, not appended to")
	assert.Equal(t, grantedAt, consent.GrantedAt, "a rewrite leaves GrantedAt alone")
	db.AssertNotCalled(t, "CreateUserConsent", mock.Anything, mock.Anything, mock.Anything)
}

func TestRecord_Failures(t *testing.T) {
	boom := errors.New("boom")

	t.Run("the read failing writes nothing", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		db.On("GetConsentByUserIdAndClientId", mock.Anything, (*sql.Tx)(nil), consentUserId, consentClientId).Return(nil, boom)

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, consent)
		db.AssertNotCalled(t, "CreateUserConsent", mock.Anything, mock.Anything, mock.Anything)
		db.AssertNotCalled(t, "UpdateUserConsent", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("the create failing returns no row", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		db.On("GetConsentByUserIdAndClientId", mock.Anything, (*sql.Tx)(nil), consentUserId, consentClientId).Return(nil, nil)
		db.On("CreateUserConsent", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(boom)

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, consent)
	})

	t.Run("the update failing returns no row", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		db.On("GetConsentByUserIdAndClientId", mock.Anything, (*sql.Tx)(nil), consentUserId, consentClientId).
			Return(&models.UserConsent{Id: 5, UserId: consentUserId, ClientId: consentClientId}, nil)
		db.On("UpdateUserConsent", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(boom)

		consent, err := Record(context.Background(), db, consentUserId, consentClientId, "openid")
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, consent)
	})
}
