package validators

import (
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestValidateEmailAddress(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewEmailValidator(mockDB)

	tests := []struct {
		name          string
		email         string
		expectedError string
	}{
		{"Valid email", "test@example.com", ""},
		{"Invalid email - no @", "testexample.com", "Please enter a valid email address."},
		{"Invalid email - no domain", "test@.com", "Please enter a valid email address."},
		{"Invalid email - double dots", "test..email@example.com", "Please enter a valid email address."},
		{"Invalid email - starting with dot", ".test@example.com", "Please enter a valid email address."},
		{"Invalid email - ending with dot", "test.@example.com", "Please enter a valid email address."},
		{"Valid email with subdomains", "test@subdomain.example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEmailAddress(tt.email)
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				customErr, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedError, customErr.GetDescription())
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
		name          string
		input         ValidateEmailInput
		mockSetup     func()
		expectedError string
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
			expectedError: "",
		},
		{
			name: "Empty email",
			input: ValidateEmailInput{
				Email:             "",
				EmailConfirmation: "",
				Subject:           subject1.String(),
			},
			mockSetup:     func() {},
			expectedError: "Please enter an email address.",
		},
		{
			name: "Email too long",
			input: ValidateEmailInput{
				Email:             "thisemailaddressiswaytoolongandexceedsthemaximumlengthof60characters@example.com",
				EmailConfirmation: "thisemailaddressiswaytoolongandexceedsthemaximumlengthof60characters@example.com",
				Subject:           subject1.String(),
			},
			mockSetup:     func() {},
			expectedError: "The email address cannot exceed a maximum length of 60 characters.",
		},
		{
			name: "Email mismatch",
			input: ValidateEmailInput{
				Email:             "new@example.com",
				EmailConfirmation: "different@example.com",
				Subject:           subject1.String(),
			},
			mockSetup:     func() {},
			expectedError: "The email and email confirmation entries must be identical.",
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
			expectedError: "Apologies, but this email address is already registered.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			err := validator.ValidateEmailUpdate(&tt.input)
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				customErr, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedError, customErr.GetDescription())
			}
		})
	}
}
