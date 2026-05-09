package validators

import (
	"regexp"
	"strings"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/phonecountries"
)

type PhoneValidator struct {
	database data.Database
}

func NewPhoneValidator(database data.Database) *PhoneValidator {
	return &PhoneValidator{
		database: database,
	}
}

type ValidatePhoneInput struct {
	PhoneCountryUniqueId string
	PhoneNumber          string
	PhoneNumberVerified  bool
}

func (val *PhoneValidator) ValidatePhone(input *ValidatePhoneInput) error {
	// i18n surface: C — admin/account API.
	if len(input.PhoneCountryUniqueId) > 0 {
		phoneCountries := phonecountries.Get()

		found := false
		for _, c := range phoneCountries {
			if c.UniqueId == input.PhoneCountryUniqueId {
				found = true
				break
			}
		}

		if !found {
			return i18n.NewLocalizedError(i18n.ErrCodePhoneCountryInvalid, nil)
		}

		if len(input.PhoneNumber) == 0 {
			return i18n.NewLocalizedError(i18n.ErrCodePhoneNumberRequired, nil)
		}
	}

	if len(input.PhoneNumber) > 0 {
		// Remove spaces and hyphens for length check and pattern matching
		cleanNumber := strings.ReplaceAll(strings.ReplaceAll(input.PhoneNumber, " ", ""), "-", "")

		// Check minimum length
		if len(cleanNumber) < 6 {
			return i18n.NewLocalizedError(i18n.ErrCodePhoneNumberTooShort, map[string]any{"min": 6})
		}

		// Check for simple patterns
		if isSimplePattern(cleanNumber) {
			return i18n.NewLocalizedError(i18n.ErrCodePhoneSimplePattern, nil)
		}

		pattern := `^[0-9]+([- ]?[0-9]+)*$`
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		if !regex.MatchString(input.PhoneNumber) {
			return i18n.NewLocalizedError(i18n.ErrCodePhoneInvalidFormat, nil)
		}
		if len(input.PhoneNumber) > 30 {
			return i18n.NewLocalizedError(i18n.ErrCodePhoneNumberTooLong, map[string]any{"max": 30})
		}

		if len(input.PhoneCountryUniqueId) == 0 {
			return i18n.NewLocalizedError(i18n.ErrCodePhoneCountryRequired, nil)
		}
	}

	return nil
}

func isSimplePattern(number string) bool {
	// Check for all repeated digits (e.g., 00000, 111111111, etc.)
	if len(number) > 0 && strings.Count(number, string(number[0])) == len(number) {
		return true
	}

	// Check for sequential ascending digits
	ascending := "0123456789"
	if strings.Contains(ascending, number) {
		return true
	}

	// Check for sequential descending digits
	descending := "9876543210"
	return strings.Contains(descending, number)
}
