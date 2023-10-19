package core

import (
	"github.com/microcosm-cc/bluemonday"
)

type InputSanitizer struct {
}

func NewInputSanitizer() *InputSanitizer {
	return &InputSanitizer{}
}

func (i *InputSanitizer) Sanitize(str string) string {

	p := bluemonday.StrictPolicy()
	p.AllowStandardURLs()

	sanitized := p.Sanitize(str)
	return sanitized
}
