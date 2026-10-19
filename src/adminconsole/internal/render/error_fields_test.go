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
