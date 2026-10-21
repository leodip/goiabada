package render

import (
	"errors"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// A refusal names the field its error code maps to, wrapped or not, and no field for a code the map
// does not hold or an error the API did not answer.
func TestErrorField(t *testing.T) {
	refusal := func(code string) error {
		return &apiclient.APIError{Code: code, Message: "refused", StatusCode: http.StatusBadRequest}
	}

	assert.Equal(t, "website", ErrorField(refusal(i18n.ErrCodeProfileWebsiteInvalid), ProfileErrorFields))
	assert.Equal(t, "website", ErrorField(errs.Wrap(refusal(i18n.ErrCodeProfileWebsiteInvalid), "updating the profile"), ProfileErrorFields),
		"a wrapped refusal names its field too")
	assert.Equal(t, "addressCountry", ErrorField(refusal(i18n.ErrCodeAddressCountryInvalid), AddressErrorFields))
	assert.Equal(t, "phoneNumber", ErrorField(refusal(i18n.ErrCodePhoneNumberTooShort), PhoneErrorFields))

	assert.Empty(t, ErrorField(refusal(i18n.ErrCodeAddressAngleBrackets), AddressErrorFields),
		"angle brackets are refused in whichever field holds them, so the refusal names none")
	assert.Empty(t, ErrorField(refusal("VALIDATION_ERROR"), ProfileErrorFields), "a code the map does not hold")
	assert.Empty(t, ErrorField(errors.New("connection refused"), ProfileErrorFields), "an error the API did not answer")
	assert.Empty(t, ErrorField(nil, ProfileErrorFields))
}

// A VALIDATION_ERROR, which names no field, is about the first required field sent blank, in the
// order given; a code the map holds still wins, and any other refusal names a field only through it.
func TestErrorFieldOrBlank(t *testing.T) {
	refusal := func(code string) error {
		return &apiclient.APIError{Code: code, Message: "refused", StatusCode: http.StatusBadRequest}
	}
	fields := map[string]string{"AUTHENTICATION_FAILED": "currentPassword"}
	current := func(value string) RequiredField { return RequiredField{Name: "currentPassword", Value: value} }
	next := func(value string) RequiredField { return RequiredField{Name: "newPassword", Value: value} }

	assert.Equal(t, "currentPassword", ErrorFieldOrBlank(refusal("VALIDATION_ERROR"), fields, current(""), next("")),
		"both blank: the first the API checks")
	assert.Equal(t, "newPassword", ErrorFieldOrBlank(refusal("VALIDATION_ERROR"), fields, current("old"), next(" ")),
		"blank as the API reads it, spaces alone")
	assert.Equal(t, "currentPassword", ErrorFieldOrBlank(refusal("AUTHENTICATION_FAILED"), fields, current("old"), next("new")),
		"a code the map holds")
	assert.Empty(t, ErrorFieldOrBlank(refusal("VALIDATION_ERROR"), fields, current("old"), next("new")),
		"nothing sent blank: the refusal is about something else")
	assert.Empty(t, ErrorFieldOrBlank(refusal("NOT_FOUND"), fields, current("")),
		"another code names no field however the form was sent")
	assert.Empty(t, ErrorFieldOrBlank(errors.New("connection refused"), fields, current("")),
		"an error the API did not answer")
}
