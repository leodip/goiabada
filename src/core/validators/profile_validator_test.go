package validators

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
)

func TestValidateName(t *testing.T) {
	validator := NewProfileValidator(nil)
	ctx := context.Background()

	tests := []struct {
		name      string
		inputName string
		nameField string
		wantErr   bool
	}{
		{"Valid name", "John Doe", "given name", false},
		{"Valid name with hyphen", "Mary-Jane", "given name", false},
		{"Valid name with apostrophe", "O'Connor", "family name", false},
		{"Too short", "A", "given name", true},
		{"Too long", "ThisNameIsTooLongAndExceedsTheMaximumAllowedLength", "given name", true},
		{"Invalid characters", "John123", "given name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateName(ctx, tt.inputName, tt.nameField)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateProfile_ValidInput(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	subject := uuid.New()
	input := ValidateProfileInput{
		Username:    "johndoe",
		GivenName:   "John",
		MiddleName:  "William",
		FamilyName:  "Doe",
		Nickname:    "Johnny",
		Website:     "https://johndoe.com",
		Gender:      "1",
		DateOfBirth: "1990-01-01",
		ZoneInfo:    "America/New_York",
		Locale:      "en-US",
		Subject:     subject.String(),
	}

	mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(&models.User{Subject: subject}, nil)
	mockDB.On("GetUserByUsername", mock.Anything, "johndoe").Return(nil, nil)

	err := validator.ValidateProfile(ctx, &input)
	assert.NoError(t, err)
}

func TestValidateProfile_UsernameAlreadyTaken(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	subject := uuid.New()
	input := ValidateProfileInput{
		Username: "existinguser",
		Subject:  subject.String(),
	}

	mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(&models.User{Subject: subject}, nil)
	mockDB.On("GetUserByUsername", mock.Anything, "existinguser").Return(&models.User{Subject: uuid.New()}, nil)

	err := validator.ValidateProfile(ctx, &input)
	assert.Error(t, err)
	assert.Equal(t, "Sorry, this username is already taken.", err.(*customerrors.ErrorDetail).GetDescription())
}

func TestValidateProfile_UsernameFormat(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name        string
		username    string
		expectError bool
	}{
		{"Valid: letters only", "validusername", false},
		{"Valid: letters and numbers", "valid123username", false},
		{"Valid: letters, numbers, and underscore", "valid_user_name123", false},
		{"Valid: minimum length", "ab", false},
		{"Valid: maximum length", "abcdefghijklmnopqrstuvwx", false},
		{"Invalid: starts with number", "1invalidusername", true},
		{"Invalid: starts with underscore", "_invalidusername", true},
		{"Invalid: contains space", "invalid username", true},
		{"Invalid: contains hyphen", "invalid-username", true},
		{"Invalid: contains special characters", "invalid@username", true},
		{"Invalid: too short", "a", true},
		{"Invalid: too long", "abcdefghijklmnopqrstuvwxy", true},
		{"Invalid: empty string", "", false}, // Note: empty is allowed as per current implementation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := uuid.New()
			input := ValidateProfileInput{
				Username: tt.username,
				Subject:  subject.String(),
			}

			if len(tt.username) > 0 {
				mockDB.On("GetUserBySubject", mock.Anything, subject.String()).Return(&models.User{Subject: subject}, nil).Once()
				mockDB.On("GetUserByUsername", mock.Anything, tt.username).Return(nil, nil).Once()
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, "Usernames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.", err.(*customerrors.ErrorDetail).GetDescription())
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateProfile_Names(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name        string
		givenName   string
		middleName  string
		familyName  string
		expectError bool
		errorField  string
	}{
		{"All valid names", "John", "William", "Doe", false, ""},
		{"Valid with spaces", "Mary Jane", "Ann Marie", "Smith Johnson", false, ""},
		{"Valid with hyphens", "Jean-Paul", "Marie-Claire", "Smith-Jones", false, ""},
		{"Valid with apostrophes", "John", "D'Arcy", "O'Connor", false, ""},
		{"Given name too short", "J", "William", "Doe", true, "given name"},
		{"Middle name too short", "John", "W", "Doe", true, "middle name"},
		{"Family name too short", "John", "William", "D", true, "family name"},
		{"Given name too long", "Johnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn", "William", "Doe", true, "given name"},
		{"Middle name too long", "John", "Williammmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm", "Doe", true, "middle name"},
		{"Family name too long", "John", "William", "Doeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", true, "family name"},
		{"Given name with invalid characters", "John123", "William", "Doe", true, "given name"},
		{"Middle name with invalid characters", "John", "William123", "Doe", true, "middle name"},
		{"Family name with invalid characters", "John", "William", "Doe123", true, "family name"},
		{"Empty names", "", "", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := ValidateProfileInput{
				GivenName:  tt.givenName,
				MiddleName: tt.middleName,
				FamilyName: tt.familyName,
				Subject:    uuid.New().String(),
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				errorDetail, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok, "Error should be of type *customerrors.ErrorDetail")
				assert.Contains(t, errorDetail.GetDescription(), tt.errorField)
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateProfile_Nickname(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name        string
		nickname    string
		expectError bool
	}{
		{"Valid: letters only", "validnickname", false},
		{"Valid: letters and numbers", "valid123nickname", false},
		{"Valid: letters, numbers, and underscore", "valid_nick_name123", false},
		{"Valid: minimum length", "ab", false},
		{"Valid: maximum length", "abcdefghijklmnopqrstuvwx", false},
		{"Invalid: starts with number", "1invalidnickname", true},
		{"Invalid: starts with underscore", "_invalidnickname", true},
		{"Invalid: contains space", "invalid nickname", true},
		{"Invalid: contains hyphen", "invalid-nickname", true},
		{"Invalid: contains special characters", "invalid@nickname", true},
		{"Invalid: too short", "a", true},
		{"Invalid: too long", "abcdefghijklmnopqrstuvwxy", true},
		{"Valid: empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := uuid.New()
			input := ValidateProfileInput{
				Nickname: tt.nickname,
				Subject:  subject.String(),
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				errorDetail, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok, "Error should be of type *customerrors.ErrorDetail")
				assert.Equal(t, "Nicknames must start with a letter and consist only of letters, numbers, and underscores. They must be between 2 and 24 characters long.", errorDetail.GetDescription())
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateProfile_Website(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name        string
		website     string
		expectError bool
	}{
		{"Valid: http protocol", "http://example.com", false},
		{"Valid: https protocol", "https://example.com", false},
		{"Valid: with www", "www.example.com", false},
		{"Valid: subdomain", "http://blog.example.com", false},
		{"Valid: with path", "https://example.com/path", false},
		{"Valid: with query parameters", "https://example.com/path?param=value", false},
		{"Valid: domain with hyphen", "http://my-website.example.com", false},
		{"Valid: top-level domain with 2 letters", "http://example.co", false},
		{"Valid: top-level domain with more than 2 letters", "http://example.info", false},
		{"Valid: multiple subdomains", "https://sub1.sub2.example.com", false},
		{"Valid: hyphen in domain", "https://my-example.com", false},
		{"Invalid: IP address", "http://192.168.1.1", true},
		{"Invalid: localhost", "http://localhost", true},
		{"Invalid: missing top-level domain", "http://example", true},
		{"Invalid: space in URL", "https://example .com", true},
		{"Invalid: special characters", "https://example!.com", true},
		{"Invalid: double dot in domain", "https://example..com", true},
		{"Invalid: starts with dot", "https://.example.com", true},
		{"Invalid: ends with dot", "https://example.com.", true},
		{"Invalid: ftp protocol", "ftp://example.com", true},
		{"Invalid: hyphen at start of domain part", "https://-example.com", true},
		{"Invalid: hyphen at end of domain part", "https://example-.com", true},
		{"Valid: empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := uuid.New()
			input := ValidateProfileInput{
				Website: tt.website,
				Subject: subject.String(),
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				errorDetail, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok, "Error should be of type *customerrors.ErrorDetail")
				assert.Equal(t, "Please enter a valid website URL.", errorDetail.GetDescription())
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateProfile_WebsiteLength(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name        string
		website     string
		expectError bool
	}{
		{
			name:        "Valid: Empty string",
			website:     "",
			expectError: false,
		},
		{
			name:        "Valid: Short URL",
			website:     "https://example.com",
			expectError: false,
		},
		{
			name:        "Valid: URL with 96 characters",
			website:     "https://www.example.com/very/long/path/that/is/exactly/ninety/six/characters/long/including/abcd",
			expectError: false,
		},
		{
			name:        "Invalid: URL with 97 characters",
			website:     "https://www.example.com/very/long/path/that/is/exactly/ninety/six/characters/long/including/abcde",
			expectError: true,
		},
		{
			name:        "Invalid: Very long URL",
			website:     "https://www.example.com/extremely/long/path/that/significantly/exceeds/the/ninety/six/character/limit/and/should/definitely/trigger/an/error/response/from/the/validation/function",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := uuid.New()
			input := ValidateProfileInput{
				Website: tt.website,
				Subject: subject.String(),
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				errorDetail, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok, "Error should be of type *customerrors.ErrorDetail")
				assert.Equal(t, "Please ensure the website URL is no longer than 96 characters.", errorDetail.GetDescription())
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateProfile_DateOfBirth(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	// Helper function to get a date string for a given number of years ago
	yearsAgo := func(years int) string {
		return time.Now().AddDate(-years, 0, 0).Format("2006-01-02")
	}

	// Helper function to get a future date string
	futureDate := func(days int) string {
		return time.Now().AddDate(0, 0, days).Format("2006-01-02")
	}

	tests := []struct {
		name        string
		dateOfBirth string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid: Empty string",
			dateOfBirth: "",
			expectError: false,
		},
		{
			name:        "Valid: Correct format (30 years ago)",
			dateOfBirth: yearsAgo(30),
			expectError: false,
		},
		{
			name:        "Valid: Correct format (today)",
			dateOfBirth: time.Now().Format("2006-01-02"),
			expectError: false,
		},
		{
			name:        "Invalid: Future date",
			dateOfBirth: futureDate(1),
			expectError: true,
			errorMsg:    "The date of birth can't be in the future.",
		},
		{
			name:        "Invalid: Incorrect format (DD-MM-YYYY)",
			dateOfBirth: "01-01-2000",
			expectError: true,
			errorMsg:    "The date of birth is invalid. Please use the format YYYY-MM-DD.",
		},
		{
			name:        "Invalid: Incorrect format (YYYY/MM/DD)",
			dateOfBirth: "2000/01/01",
			expectError: true,
			errorMsg:    "The date of birth is invalid. Please use the format YYYY-MM-DD.",
		},
		{
			name:        "Invalid: Non-existent date",
			dateOfBirth: "2022-02-30",
			expectError: true,
			errorMsg:    "The date of birth is invalid. Please use the format YYYY-MM-DD.",
		},
		{
			name:        "Invalid: Non-numeric characters",
			dateOfBirth: "20xx-01-01",
			expectError: true,
			errorMsg:    "The date of birth is invalid. Please use the format YYYY-MM-DD.",
		},
		{
			name:        "Valid: Leap year",
			dateOfBirth: "2000-02-29",
			expectError: false,
		},
		{
			name:        "Invalid: Leap year in non-leap year",
			dateOfBirth: "2001-02-29",
			expectError: true,
			errorMsg:    "The date of birth is invalid. Please use the format YYYY-MM-DD.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := uuid.New()
			input := ValidateProfileInput{
				DateOfBirth: tt.dateOfBirth,
				Subject:     subject.String(),
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				errorDetail, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok, "Error should be of type *customerrors.ErrorDetail")
				assert.Equal(t, tt.errorMsg, errorDetail.GetDescription())
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateProfile_ZoneInfo(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name        string
		zoneInfo    string
		expectError bool
	}{
		{
			name:        "Valid: Empty string",
			zoneInfo:    "",
			expectError: false,
		},
		{
			name:        "Valid: Common time zone",
			zoneInfo:    "America/New_York",
			expectError: false,
		},
		{
			name:        "Valid: Another common time zone",
			zoneInfo:    "Europe/London",
			expectError: false,
		},
		{
			name:        "Invalid: Non-existent time zone",
			zoneInfo:    "Invalid/TimeZone",
			expectError: true,
		},
		{
			name:        "Invalid: Misspelled time zone",
			zoneInfo:    "America/NewYork",
			expectError: true,
		},
		{
			name:        "Invalid: Lowercase time zone",
			zoneInfo:    "america/new_york",
			expectError: true,
		},
		{
			name:        "Invalid: Just continent",
			zoneInfo:    "America",
			expectError: true,
		},
		{
			name:        "Invalid: Just city",
			zoneInfo:    "London",
			expectError: true,
		},
		{
			name:        "Invalid: Numeric time zone",
			zoneInfo:    "+05:00",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := uuid.New()
			input := ValidateProfileInput{
				ZoneInfo: tt.zoneInfo,
				Subject:  subject.String(),
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				errorDetail, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok, "Error should be of type *customerrors.ErrorDetail")
				assert.Equal(t, "The zone info is invalid.", errorDetail.GetDescription())
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateProfile_Locale(t *testing.T) {
	mockDB := new(mocks_data.Database)
	validator := NewProfileValidator(mockDB)
	ctx := context.Background()

	tests := []struct {
		name        string
		locale      string
		expectError bool
	}{
		{
			name:        "Valid: Empty string",
			locale:      "",
			expectError: false,
		},
		{
			name:        "Valid: Common locale",
			locale:      "en-US",
			expectError: false,
		},
		{
			name:        "Valid: Another common locale",
			locale:      "fr-FR",
			expectError: false,
		},
		{
			name:        "Valid: Language only",
			locale:      "de",
			expectError: false,
		},
		{
			name:        "Valid: Language with script",
			locale:      "zh-Hans",
			expectError: false,
		},
		{
			name:        "Invalid: Non-existent locale",
			locale:      "xx-XX",
			expectError: true,
		},
		{
			name:        "Invalid: Misspelled locale",
			locale:      "en-USA",
			expectError: true,
		},
		{
			name:        "Invalid: Incorrect format",
			locale:      "english_US",
			expectError: true,
		},
		{
			name:        "Invalid: Just country code",
			locale:      "US",
			expectError: true,
		},
		{
			name:        "Invalid: Lowercase locale",
			locale:      "en-us",
			expectError: true,
		},
		{
			name:        "Invalid: Uppercase locale",
			locale:      "EN-US",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := uuid.New()
			input := ValidateProfileInput{
				Locale:  tt.locale,
				Subject: subject.String(),
			}

			err := validator.ValidateProfile(ctx, &input)

			if tt.expectError {
				assert.Error(t, err)
				errorDetail, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok, "Error should be of type *customerrors.ErrorDetail")
				assert.Equal(t, "The locale is invalid.", errorDetail.GetDescription())
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}
