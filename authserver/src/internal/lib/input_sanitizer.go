package lib

import (
	"fmt"
	"log/slog"

	"github.com/sym01/htmlsanitizer"
)

type InputSanitizer struct {
}

func NewInputSanitizer() *InputSanitizer {
	return &InputSanitizer{}
}

func (i *InputSanitizer) Sanitize(str string) string {
	sanitizedHTML, err := htmlsanitizer.SanitizeString(str)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to sanitize string: %+v", err))
		return str
	}
	return sanitizedHTML
}
