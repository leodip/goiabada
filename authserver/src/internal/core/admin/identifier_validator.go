package core

import (
	"fmt"

	"regexp"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
)

type IdentifierValidator struct {
	database *data.Database
}

func NewIdentifierValidator(database *data.Database) *IdentifierValidator {
	return &IdentifierValidator{
		database: database,
	}
}

func (val *IdentifierValidator) ValidateIdentifier(identifier string) error {
	const maxLength = 32
	if len(identifier) > maxLength {
		return customerrors.NewValidationError("", fmt.Sprintf("The identifier cannot exceed a maximum length of %v characters.", maxLength))
	}

	const minLength = 3
	if len(identifier) < minLength {
		return customerrors.NewValidationError("", fmt.Sprintf("The identifier must be at least %v characters long.", minLength))
	}

	match, _ := regexp.MatchString("^[a-zA-Z][a-zA-Z0-9]*(?:[_-][a-zA-Z0-9]+)*[a-zA-Z0-9]$", identifier)

	if !match {
		return customerrors.NewValidationError("", "Invalid identifier format. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.")
	}

	return nil
}