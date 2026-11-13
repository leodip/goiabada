package apihandlers

import (
	"strings"

	"github.com/leodip/goiabada/authserver/internal/customcss"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
)

// A brand's custom CSS in the admin API (#816 decision 4): the customCss member of a create and an
// update, checked by customcss before it is stored, and refused at /customCss in the error answer's
// error_field with a sentence naming the line it is about.

// customCSSRefusalCodes are the refusal codes of customcss's rules.
var customCSSRefusalCodes = map[customcss.Rule]string{
	customcss.RuleTooLarge:  i18n.ErrCodeBrandCustomCSSTooLarge,
	customcss.RuleImport:    i18n.ErrCodeBrandCustomCSSImport,
	customcss.RuleURL:       i18n.ErrCodeBrandCustomCSSURL,
	customcss.RuleFunction:  i18n.ErrCodeBrandCustomCSSFunction,
	customcss.RuleMalformed: i18n.ErrCodeBrandCustomCSSMalformed,
}

// validateBrandCustomCSS answers the custom CSS a create or an update sends as it is stored: as it
// was written, with each CRLF and each CR alone made a line feed, and "" when it is blank. The CSS
// as stored is what customcss.Check reads, so the 64 KB cap is measured on it and a refusal's line
// is counted on it.
func validateBrandCustomCSS(sent string) (string, error) {
	css := strings.ReplaceAll(strings.ReplaceAll(sent, "\r\n", "\n"), "\r", "\n")
	if strings.TrimSpace(css) == "" {
		return "", nil
	}
	refusal := customcss.Check(css)
	if refusal == nil {
		return css, nil
	}
	code, ok := customCSSRefusalCodes[refusal.Rule]
	if !ok {
		code = i18n.ErrCodeBrandCustomCSSMalformed
	}
	args := map[string]any{"line": refusal.Line}
	if refusal.Rule == customcss.RuleTooLarge {
		args = map[string]any{"max": customcss.MaxBytes}
	}
	return "", refusalAt(i18n.NewLocalizedError(code, args), "customCss")
}

// brandCustomCSSAudit adds the size of a brand's custom CSS in bytes, as stored, to the details of
// a brand write's audit event, and never its text. A brand with none adds nothing.
func brandCustomCSSAudit(brand *record.Brand, details map[string]interface{}) {
	if brand.CustomCSS == "" {
		return
	}
	details["custom_css_bytes"] = len(brand.CustomCSS)
}
