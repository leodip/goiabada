package core

import (
	"html"

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

	// sanitizing twice to allow apostrophes, and at the same time,
	// to avoid entries like &lt;script&gt; from becoming <script>
	// some discussions:
	// https://github.com/microcosm-cc/bluemonday/issues/28
	// https://github.com/microcosm-cc/bluemonday/issues/74

	sanitized := p.Sanitize(str)
	unescaped := html.UnescapeString(sanitized)
	sanitized = p.Sanitize(unescaped)
	return html.UnescapeString(sanitized)
}
