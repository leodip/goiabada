package adminresourcehandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/validators"
)

// The permission form asks this endpoint whether a value is acceptable before it saves, and the
// save goes to PUT /api/v1/admin/resources/{id}/permissions, which refuses angle brackets. The two
// therefore have to answer the same way, and before #275 they did not: the pre-check detected
// markup by sanitizing and comparing, so every tag on the sanitizer's allowlist passed here and was
// refused on save.
//
// Both dependencies are the real implementations rather than mocks. Neither reaches a database or
// a template: HttpHelper only encodes JSON on these paths, and IdentifierValidator is a regex. A
// mocked IdentifierValidator in particular would prove nothing about the identifier case below,
// which is entirely about what the handler hands it.
func validatePermissionResponse(t *testing.T, identifier string, description string) ValidatePermissionResult {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"permissionIdentifier": identifier,
		"description":          description,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/admin/resources/validate-permission", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler := HandleAdminResourceValidatePermissionPost(
		handlerhelpers.NewHttpHelper(nil),
		validators.NewIdentifierValidator(),
	)
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var result ValidatePermissionResult
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&result))
	return result
}

func TestValidatePermissionPost_DescriptionAngleBrackets(t *testing.T) {
	htmlNotAllowed := i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsDescriptionHtmlNotAllowed, nil).
		Localize(nil)

	testCases := []struct {
		name        string
		description string
		valid       bool
	}{
		// The case the compare used to accept: the sanitizer's allowlist kept <b> intact, so the
		// value came back unchanged and this endpoint said yes to what the API says no to.
		{name: "an allowlisted tag is refused", description: "<b>x</b>", valid: false},
		{name: "an opening bracket is refused", description: "a < b", valid: false},
		// The character the sanitizer rewrote to "&gt;" rather than dropping.
		{name: "a bare closing bracket is refused", description: "x > y", valid: false},
		{name: "plain text is accepted", description: "Reads the audit log", valid: true},
		// Ampersands are ordinary text and stay accepted (decision 2).
		{name: "an ampersand is accepted", description: "Tom & Jerry", valid: true},
		{name: "an empty description is accepted", description: "", valid: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePermissionResponse(t, "some-permission", tc.description)

			assert.Equal(t, tc.valid, result.Valid)
			if tc.valid {
				assert.Empty(t, result.Error)
			} else {
				assert.Equal(t, htmlNotAllowed, result.Error)
			}
		})
	}
}

// The identifier reached ValidateIdentifier sanitized, so "valid<b" arrived as "valid" and this
// endpoint reported a well-formed identifier the user had not typed. It is now checked raw.
func TestValidatePermissionPost_TheIdentifierIsValidatedRaw(t *testing.T) {
	invalidFormat := i18n.NewLocalizedError(i18n.ErrCodeIdentifierInvalidFormat, nil).Localize(nil)

	result := validatePermissionResponse(t, "valid<b", "")
	assert.False(t, result.Valid, "the identifier the user typed is what gets validated")
	assert.Equal(t, invalidFormat, result.Error)

	result = validatePermissionResponse(t, "valid", "")
	assert.True(t, result.Valid)
}
