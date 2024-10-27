package validators

import (
	"fmt"
	"strings"

	"regexp"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
)

type IdentifierValidator struct {
	database data.Database
}

func NewIdentifierValidator(database data.Database) *IdentifierValidator {
	return &IdentifierValidator{
		database: database,
	}
}

func (val *IdentifierValidator) ValidateIdentifier(identifier string, enforceMinLength bool) error {
	const maxLength = 38
	if len(identifier) > maxLength {
		return customerrors.NewErrorDetail("", fmt.Sprintf("The identifier cannot exceed a maximum length of %v characters.", maxLength))
	}

	if enforceMinLength {
		const minLength = 3
		if len(identifier) < minLength {
			return customerrors.NewErrorDetail("", fmt.Sprintf("The identifier must be at least %v characters long.", minLength))
		}
	}

	matchErrorMsg := "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."

	match, _ := regexp.MatchString("^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$", identifier)
	if !match {
		return customerrors.NewErrorDetail("", matchErrorMsg)
	}

	// check if identifier has 2 dashes or underscores in a row
	if strings.Contains(identifier, "--") || strings.Contains(identifier, "__") {
		return customerrors.NewErrorDetail("", matchErrorMsg)
	}

	return nil
}
