package oauth

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestAuthContext_SetScope(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty", "", ""},
		{"Single", "openid", "openid"},
		{"Multiple", "openid profile email", "openid profile email"},
		{"Duplicate", "openid profile openid", "openid profile"},
		{"ExtraSpaces", "  openid   profile  ", "openid profile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthContext{}
			ac.SetScope(tt.input)
			assert.Equal(t, tt.expected, ac.Scope)
		})
	}
}

func TestAuthContext_HasScope(t *testing.T) {
	ac := &AuthContext{Scope: "openid profile email"}

	assert.True(t, ac.HasScope("openid"))
	assert.True(t, ac.HasScope("profile"))
	assert.True(t, ac.HasScope("email"))
	assert.False(t, ac.HasScope("address"))
	assert.False(t, ac.HasScope(""))

	ac.Scope = ""
	assert.False(t, ac.HasScope("openid"))
}

func TestAuthContext_ParseRequestedMaxAge(t *testing.T) {
	tests := []struct {
		name     string
		maxAge   string
		expected *int
	}{
		{"Empty", "", nil},
		{"Valid", "300", intPtr(300)},
		{"Invalid", "abc", nil},
		{"Zero", "0", intPtr(0)},
		{"Negative", "-100", intPtr(-100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthContext{MaxAge: tt.maxAge}
			result := ac.ParseRequestedMaxAge()
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestAuthContext_SetAcrLevel(t *testing.T) {
	tests := []struct {
		name           string
		targetAcr      enums.AcrLevel
		userSessionAcr string
		expected       string
		expectError    bool
	}{
		{"NoUserSession", enums.AcrLevel1, "", "urn:goiabada:pwd", false},
		{"Target Level1 Session Level 1", enums.AcrLevel1, "urn:goiabada:pwd", "urn:goiabada:pwd", false},
		{"Target Level1 Session Level 2", enums.AcrLevel1, "urn:goiabada:pwd:otp_ifpossible", "urn:goiabada:pwd:otp_ifpossible", false},
		{"Target Level1 Session Level 3", enums.AcrLevel1, "urn:goiabada:pwd:otp_mandatory", "urn:goiabada:pwd:otp_mandatory", false},
		{"Target Level2 Session Level 1", enums.AcrLevel2, "urn:goiabada:pwd", "urn:goiabada:pwd:otp_ifpossible", false},
		{"Target Level2 Session Level 2", enums.AcrLevel2, "urn:goiabada:pwd:otp_ifpossible", "urn:goiabada:pwd:otp_ifpossible", false},
		{"Target Level2 Session Level 3", enums.AcrLevel2, "urn:goiabada:pwd:otp_mandatory", "urn:goiabada:pwd:otp_mandatory", false},
		{"Target Level3 Session Level 1", enums.AcrLevel3, "urn:goiabada:pwd", "urn:goiabada:pwd:otp_mandatory", false},
		{"Target Level3 Session Level 2", enums.AcrLevel3, "urn:goiabada:pwd:otp_ifpossible", "urn:goiabada:pwd:otp_mandatory", false},
		{"Target Level3 Session Level 3", enums.AcrLevel3, "urn:goiabada:pwd:otp_mandatory", "urn:goiabada:pwd:otp_mandatory", false},
		{"InvalidUserSessionAcr", enums.AcrLevel1, "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthContext{}
			var userSession *models.UserSession
			if tt.userSessionAcr != "" {
				userSession = &models.UserSession{AcrLevel: tt.userSessionAcr}
			}
			err := ac.SetAcrLevel(tt.targetAcr, userSession)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, ac.AcrLevel)
			}
		})
	}
}

func TestAuthContext_ParseRequestedAcrValues(t *testing.T) {
	tests := []struct {
		name      string
		acrValues string
		expected  []enums.AcrLevel
	}{
		{"Empty", "", []enums.AcrLevel{}},
		{"SingleValid", "urn:goiabada:pwd", []enums.AcrLevel{enums.AcrLevel1}},
		{"MultipleValid", "urn:goiabada:pwd urn:goiabada:pwd:otp_ifpossible", []enums.AcrLevel{enums.AcrLevel1, enums.AcrLevel2}},
		{"DuplicateValues", "urn:goiabada:pwd urn:goiabada:pwd", []enums.AcrLevel{enums.AcrLevel1}},
		{"MixedValidInvalid", "urn:goiabada:pwd invalid urn:goiabada:pwd:otp_mandatory", []enums.AcrLevel{enums.AcrLevel1, enums.AcrLevel3}},
		{"AllInvalid", "invalid1 invalid2", []enums.AcrLevel{}},
		{"ExtraSpaces", "  urn:goiabada:pwd   urn:goiabada:pwd:otp_ifpossible  ", []enums.AcrLevel{enums.AcrLevel1, enums.AcrLevel2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthContext{RequestedAcrValues: tt.acrValues}
			result := ac.ParseRequestedAcrValues()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func intPtr(i int) *int {
	return &i
}
