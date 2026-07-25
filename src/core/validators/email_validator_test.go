package validators

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestValidateEmailAddress(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewEmailValidator(mockDB)

	tests := []struct {
		name         string
		email        string
		expectedCode string
	}{
		{"Valid email", "test@example.com", ""},
		{"Invalid email - no @", "testexample.com", i18n.ErrCodeEmailInvalidFormat},
		{"Invalid email - no domain", "test@.com", i18n.ErrCodeEmailInvalidFormat},
		{"Invalid email - double dots", "test..email@example.com", i18n.ErrCodeEmailInvalidFormat},
		{"Invalid email - starting with dot", ".test@example.com", i18n.ErrCodeEmailInvalidFormat},
		{"Invalid email - ending with dot", "test.@example.com", i18n.ErrCodeEmailInvalidFormat},
		{"Valid email with subdomains", "test@subdomain.example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEmailAddress(tt.email)
			if tt.expectedCode == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				locErr, ok := err.(*i18n.LocalizedError)
				assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
				if ok {
					assert.Equal(t, tt.expectedCode, locErr.Code)
				}
			}
		})
	}
}

func TestValidateEmailUpdate(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewEmailValidator(mockDB)

	subject1 := uuid.New()
	subject2 := uuid.New()

	tests := []struct {
		name         string
		input        ValidateEmailInput
		mockSetup    func()
		expectedCode string
		expectedArgs map[string]any
	}{
		{
			name: "Valid email update",
			input: ValidateEmailInput{
				Email:             "new@example.com",
				EmailConfirmation: "new@example.com",
				Subject:           subject1.String(),
			},
			mockSetup: func() {
				mockDB.On("GetUserBySubject", mock.Anything, subject1.String()).Return(&models.User{Subject: subject1}, nil)
				mockDB.On("GetUserByEmail", mock.Anything, "new@example.com").Return(nil, nil)
			},
		},
		{
			name: "Empty email",
			input: ValidateEmailInput{
				Email:             "",
				EmailConfirmation: "",
				Subject:           subject1.String(),
			},
			mockSetup:    func() {},
			expectedCode: i18n.ErrCodeEmailRequired,
		},
		{
			name: "Email too long",
			input: ValidateEmailInput{
				Email:             "thisemailaddressiswaytoolongandexceedsthemaximumlengthof60characters@example.com",
				EmailConfirmation: "thisemailaddressiswaytoolongandexceedsthemaximumlengthof60characters@example.com",
				Subject:           subject1.String(),
			},
			mockSetup:    func() {},
			expectedCode: i18n.ErrCodeEmailTooLong,
			expectedArgs: map[string]any{"max": 60},
		},
		{
			name: "Email mismatch",
			input: ValidateEmailInput{
				Email:             "new@example.com",
				EmailConfirmation: "different@example.com",
				Subject:           subject1.String(),
			},
			mockSetup:    func() {},
			expectedCode: i18n.ErrCodeEmailConfirmationMismatch,
		},
		{
			name: "Email already registered",
			input: ValidateEmailInput{
				Email:             "existing@example.com",
				EmailConfirmation: "existing@example.com",
				Subject:           subject1.String(),
			},
			mockSetup: func() {
				mockDB.On("GetUserBySubject", mock.Anything, subject1.String()).Return(&models.User{Subject: subject1}, nil)
				mockDB.On("GetUserByEmail", mock.Anything, "existing@example.com").Return(&models.User{Subject: subject2}, nil)
			},
			expectedCode: i18n.ErrCodeEmailAlreadyRegistered,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			err := validator.ValidateEmailUpdate(&tt.input)
			if tt.expectedCode == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				locErr, ok := err.(*i18n.LocalizedError)
				assert.True(t, ok, "expected *i18n.LocalizedError, got %T", err)
				if ok {
					assert.Equal(t, tt.expectedCode, locErr.Code)
					if tt.expectedArgs != nil {
						assert.Equal(t, tt.expectedArgs, locErr.Args)
					}
				}
			}
		})
	}
}

// =============================================================================
// Tests for ValidateEmailChange
//
// Used by the admin and account APIs to change an address without a
// confirmation field. Changing an email is an account-recovery path, so the
// uniqueness check is what stops one account from claiming another's address.
// =============================================================================

func TestValidateEmailChange_Accepted(t *testing.T) {
	subject := uuid.New()

	t.Run("address is free", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		validator := NewEmailValidator(mockDB)

		mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(
			&models.User{Id: 1, Subject: subject}, nil).Once()
		mockDB.On("GetUserByEmail", mock.Anything, "new@example.com").Return(nil, nil).Once()

		err := validator.ValidateEmailChange("new@example.com", subject.String())

		assert.NoError(t, err)
	})

	t.Run("address already belongs to the same user", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		validator := NewEmailValidator(mockDB)

		user := &models.User{Id: 1, Subject: subject}
		mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(user, nil).Once()
		mockDB.On("GetUserByEmail", mock.Anything, "same@example.com").Return(user, nil).Once()

		err := validator.ValidateEmailChange("same@example.com", subject.String())

		assert.NoError(t, err, "keeping your own address must not be reported as taken")
	})

	t.Run("exactly 60 characters", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		validator := NewEmailValidator(mockDB)

		email := strings.Repeat("a", 60-len("@example.com")) + "@example.com"
		assert.Len(t, email, 60)

		mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(
			&models.User{Id: 1, Subject: subject}, nil).Once()
		mockDB.On("GetUserByEmail", mock.Anything, email).Return(nil, nil).Once()

		err := validator.ValidateEmailChange(email, subject.String())

		assert.NoError(t, err)
	})
}

func TestValidateEmailChange_AddressTakenByAnotherUser(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewEmailValidator(mockDB)

	subject := uuid.New()
	otherSubject := uuid.New()

	mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(
		&models.User{Id: 1, Subject: subject}, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "taken@example.com").Return(
		&models.User{Id: 2, Subject: otherSubject}, nil).Once()

	err := validator.ValidateEmailChange("taken@example.com", subject.String())

	assertLocalizedErrorCode(t, err, i18n.ErrCodeEmailAlreadyRegistered)
}

// Presence, format and length are all checked before any database lookup, so
// none of these cases may reach the mock.
func TestValidateEmailChange_RejectedBeforeAnyLookup(t *testing.T) {
	testCases := []struct {
		name         string
		email        string
		expectedCode string
	}{
		{"empty", "", i18n.ErrCodeEmailRequired},
		{"no at sign", "notanemail", i18n.ErrCodeEmailInvalidFormat},
		{"no domain", "user@", i18n.ErrCodeEmailInvalidFormat},
		{"no local part", "@example.com", i18n.ErrCodeEmailInvalidFormat},
		{"double dots", "us..er@example.com", i18n.ErrCodeEmailInvalidFormat},
		{"leading dot", ".user@example.com", i18n.ErrCodeEmailInvalidFormat},
		{"trailing dot in local part", "user.@example.com", i18n.ErrCodeEmailInvalidFormat},
		{"single-character tld", "user@example.c", i18n.ErrCodeEmailInvalidFormat},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// NewDatabase(t) fails the test on any unexpected call, which is what
			// proves the short circuit.
			validator := NewEmailValidator(mocks_data.NewDatabase(t))

			err := validator.ValidateEmailChange(tc.email, uuid.New().String())

			assertLocalizedErrorCode(t, err, tc.expectedCode)
		})
	}
}

func TestValidateEmailChange_TooLong(t *testing.T) {
	validator := NewEmailValidator(mocks_data.NewDatabase(t))

	email := strings.Repeat("a", 50) + "@example.com"
	assert.Greater(t, len(email), 60)

	err := validator.ValidateEmailChange(email, uuid.New().String())

	assertLocalizedErrorCode(t, err, i18n.ErrCodeEmailTooLong)

	locErr, ok := err.(*i18n.LocalizedError)
	assert.True(t, ok)
	if ok {
		assert.Equal(t, 60, locErr.Args["max"], "the message must carry the limit for interpolation")
	}
}

func TestValidateEmailChange_DatabaseErrorsPropagate(t *testing.T) {
	subject := uuid.New()
	dbErr := errors.New("database is down")

	t.Run("GetUserBySubject fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		validator := NewEmailValidator(mockDB)

		mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(nil, dbErr).Once()

		err := validator.ValidateEmailChange("new@example.com", subject.String())

		assert.Error(t, err)
		_, isLocalized := err.(*i18n.LocalizedError)
		assert.False(t, isLocalized, "a database failure is not a validation error")
	})

	t.Run("GetUserByEmail fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		validator := NewEmailValidator(mockDB)

		mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(
			&models.User{Id: 1, Subject: subject}, nil).Once()
		mockDB.On("GetUserByEmail", mock.Anything, "new@example.com").Return(nil, dbErr).Once()

		err := validator.ValidateEmailChange("new@example.com", subject.String())

		assert.Error(t, err)
		_, isLocalized := err.(*i18n.LocalizedError)
		assert.False(t, isLocalized)
	})
}

// An unresolvable subject is rejected outright rather than quietly bypassing the
// uniqueness check. The earlier `user != nil` guard avoided the nil dereference by
// making the whole comparison false, which reported the change as valid even when
// the address belonged to another account: a uniqueness gate that fails open.
// NewDatabase(t) fails the test on any unexpected call, so the absence of a
// GetUserByEmail expectation also proves the function short circuits.
func TestValidateEmailChange_UnresolvableSubjectReturnsError(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewEmailValidator(mockDB)

	mockDB.On("GetUserBySubject", mock.Anything, "unknown-subject").Return(nil, nil).Once()

	err := validator.ValidateEmailChange("new@example.com", "unknown-subject")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subject not found: unknown-subject")
	_, isLocalized := err.(*i18n.LocalizedError)
	assert.False(t, isLocalized, "an unresolvable subject is not a user-facing validation error")
}

// The three validators that resolve a subject before a uniqueness comparison all
// behave the same way on an unresolvable one. This guards against the guard being
// reintroduced in only one of them.
func TestSubjectResolutionIsConsistentAcrossValidators(t *testing.T) {
	t.Run("ValidateEmailChange", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetUserBySubject", mock.Anything, "unknown-subject").Return(nil, nil).Once()

		err := NewEmailValidator(mockDB).ValidateEmailChange("new@example.com", "unknown-subject")

		assert.ErrorContains(t, err, "subject not found")
	})

	t.Run("ValidateEmailUpdate", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetUserBySubject", mock.Anything, "unknown-subject").Return(nil, nil).Once()

		err := NewEmailValidator(mockDB).ValidateEmailUpdate(&ValidateEmailInput{
			Email:             "new@example.com",
			EmailConfirmation: "new@example.com",
			Subject:           "unknown-subject",
		})

		assert.ErrorContains(t, err, "subject not found")
	})

	t.Run("ValidateProfile", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("GetUserBySubject", mock.Anything, "unknown-subject").Return(nil, nil).Once()

		err := NewProfileValidator(mockDB).ValidateProfile(&ValidateProfileInput{
			Username: "jdoe",
			Subject:  "unknown-subject",
		})

		assert.ErrorContains(t, err, "subject not found")
	})
}

// Unlike ValidateEmailUpdate, this function takes no confirmation value and so
// never emits ErrCodeEmailConfirmationMismatch.
func TestValidateEmailChange_DoesNotCheckConfirmation(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewEmailValidator(mockDB)

	subject := uuid.New()
	mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(
		&models.User{Id: 1, Subject: subject}, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "new@example.com").Return(nil, nil).Once()

	err := validator.ValidateEmailChange("new@example.com", subject.String())

	assert.NoError(t, err)
}

// ValidateEmailUpdate requires the subject to resolve to a real user. A stale or
// forged subject is an error rather than a localized validation failure, and must
// not panic on the nil comparison that follows.
func TestValidateEmailUpdate_UnresolvableSubjectReturnsError(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewEmailValidator(mockDB)

	mockDB.On("GetUserBySubject", mock.Anything, "unknown-subject").Return(nil, nil).Once()

	err := validator.ValidateEmailUpdate(&ValidateEmailInput{
		Email:             "new@example.com",
		EmailConfirmation: "new@example.com",
		Subject:           "unknown-subject",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subject not found: unknown-subject")
	_, isLocalized := err.(*i18n.LocalizedError)
	assert.False(t, isLocalized, "an unresolvable subject is not a user-facing validation error")
}
