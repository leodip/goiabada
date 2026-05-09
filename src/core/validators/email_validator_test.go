package validators

import (
	"testing"

	"github.com/google/uuid"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
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
