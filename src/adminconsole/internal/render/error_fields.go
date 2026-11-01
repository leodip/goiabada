package render

import (
	"errors"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/i18n"
)

// ErrorField answers the form field a refusal from the admin API is about, read off its error code
// in fields, which maps each code the form can meet to the field's name; empty for any other error,
// and for a code that names no one field. A form redrawn beside the refusal marks that field
// invalid, names the notice from it and focuses it (#617).
func ErrorField(err error, fields map[string]string) string {
	var apiErr *apiclient.APIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	return fields[apiErr.Code]
}

// RequiredField is a field a form must not send blank, and the value it sent.
type RequiredField struct {
	Name  string
	Value string
}

// ErrorFieldOrBlank is ErrorField, and for the admin API's VALIDATION_ERROR, the one code it
// answers a required value left out with, which names no field, the first of required sent blank,
// listed in the order the API checks them.
func ErrorFieldOrBlank(err error, fields map[string]string, required ...RequiredField) string {
	if field := ErrorField(err, fields); field != "" {
		return field
	}
	var apiErr *apiclient.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "VALIDATION_ERROR" {
		return ""
	}
	for _, field := range required {
		if strings.TrimSpace(field.Value) == "" {
			return field.Name
		}
	}
	return ""
}

// ProfileErrorFields are the profile form's, which the account profile page and the admin user
// profile page both post.
var ProfileErrorFields = map[string]string{
	i18n.ErrCodeProfileUsernameInvalid:   "username",
	i18n.ErrCodeProfileUsernameTaken:     "username",
	i18n.ErrCodeProfileGivenNameInvalid:  "givenName",
	i18n.ErrCodeProfileMiddleNameInvalid: "middleName",
	i18n.ErrCodeProfileFamilyNameInvalid: "familyName",
	i18n.ErrCodeProfileNicknameInvalid:   "nickname",
	i18n.ErrCodeProfileNicknameTooLong:   "nickname",
	// The nickname is the profile form's one field the angle-bracket rule guards, so
	// its refusal names it, unlike the address family's shared code.
	i18n.ErrCodeProfileNicknameAngleBrackets: "nickname",
	i18n.ErrCodeProfileWebsiteInvalid:        "website",
	i18n.ErrCodeProfileWebsiteTooLong:        "website",
	i18n.ErrCodeProfileGenderInvalid:         "gender",
	i18n.ErrCodeProfileDobInvalidFormat:      "dateOfBirth",
	i18n.ErrCodeProfileDobInFuture:           "dateOfBirth",
	i18n.ErrCodeProfileZoneInfoInvalid:       "zoneInfo",
	i18n.ErrCodeProfileLocaleInvalid:         "locale",
	i18n.ErrCodeProfilePageLanguageInvalid:   "pageLanguage",
}

// AddressErrorFields are the address form's. Angle brackets are refused in whichever field holds
// them, so that refusal names none.
var AddressErrorFields = map[string]string{
	i18n.ErrCodeAddressLine1TooLong:      "addressLine1",
	i18n.ErrCodeAddressLine2TooLong:      "addressLine2",
	i18n.ErrCodeAddressLocalityTooLong:   "addressLocality",
	i18n.ErrCodeAddressRegionTooLong:     "addressRegion",
	i18n.ErrCodeAddressPostalCodeTooLong: "addressPostalCode",
	i18n.ErrCodeAddressCountryInvalid:    "addressCountry",
}

// PhoneErrorFields are the phone form's.
var PhoneErrorFields = map[string]string{
	i18n.ErrCodePhoneCountryInvalid:  "phoneCountryUniqueId",
	i18n.ErrCodePhoneCountryRequired: "phoneCountryUniqueId",
	i18n.ErrCodePhoneNumberRequired:  "phoneNumber",
	i18n.ErrCodePhoneNumberTooShort:  "phoneNumber",
	i18n.ErrCodePhoneNumberTooLong:   "phoneNumber",
	i18n.ErrCodePhoneSimplePattern:   "phoneNumber",
	i18n.ErrCodePhoneInvalidFormat:   "phoneNumber",
}

// AttributeErrorFields are the attribute form's, which a user's and a group's attribute pages both
// post: the key, which the API requires and validates as an identifier, and the value, which it
// bounds, a user's under VALUE_TOO_LONG and a group's under its catalog key.
var AttributeErrorFields = map[string]string{
	i18n.ErrCodeAttributeKeyRequired:        "attributeKey",
	i18n.ErrCodeIdentifierInvalidFormat:     "attributeKey",
	i18n.ErrCodeIdentifierTooShort:          "attributeKey",
	i18n.ErrCodeIdentifierTooLong:           "attributeKey",
	i18n.ErrCodeAttributeValueTooLong:       "attributeValue",
	"VALUE_TOO_LONG":                        "attributeValue",
	i18n.ErrCodeAttributeValueAngleBrackets: "attributeValue",
}
