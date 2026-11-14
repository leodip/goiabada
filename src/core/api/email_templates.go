package api

// The admin API's email templates (#818 decision 10), in the settings domain: an administrator's
// edit of the subject, the button label and the body of one of Goiabada's emails, in one of the six
// built-in languages. One language of one email is the resource that is saved and reset.

// The status of one language of an email template (#818 decision 8): default when it has no edit,
// edited when its edit is sent, and invalid when its edit breaks a rule of the release that is
// running, so the built-in text is sent instead.
const (
	EmailTemplateStatusDefault = "default"
	EmailTemplateStatusEdited  = "edited"
	EmailTemplateStatusInvalid = "invalid"
)

// The fields of an email template's text, as editedFields and a problem's field name them: the
// request's own member names.
const (
	EmailTemplateFieldSubject     = "subject"
	EmailTemplateFieldButtonLabel = "buttonLabel"
	EmailTemplateFieldBody        = "body"
)

// EmailTemplateLanguageStatusResponse is one language of an email as the list gives it.
type EmailTemplateLanguageStatusResponse struct {
	Language string `json:"language"`
	Status   string `json:"status"`
}

// EmailTemplateSummaryResponse is one email as the list gives it: its identifier and the status of
// each of the six languages, in the order of the built-in languages, English first.
type EmailTemplateSummaryResponse struct {
	Id        string                                `json:"id"`
	Languages []EmailTemplateLanguageStatusResponse `json:"languages"`
}

// GetEmailTemplatesResponse is every email, grouped as Goiabada lists them.
type GetEmailTemplatesResponse struct {
	EmailTemplates []EmailTemplateSummaryResponse `json:"emailTemplates"`
}

// EmailTemplatePlaceholderResponse is one placeholder an email offers: its name, written {{name}}
// in a text, whether the body cannot do without it, and whether the subject may use it.
type EmailTemplatePlaceholderResponse struct {
	Name      string `json:"name"`
	Required  bool   `json:"required"`
	InSubject bool   `json:"inSubject"`
}

// EmailTemplateTextResponse is one language's text. ButtonLabel is there for an email with a
// button only.
type EmailTemplateTextResponse struct {
	Subject     string  `json:"subject"`
	ButtonLabel *string `json:"buttonLabel,omitempty"`
	Body        string  `json:"body"`
}

// EmailTemplateProblemResponse is one rule an invalid edit breaks: the field it is in, the rule,
// the placeholder it is about, as written between the braces, for a rule about one, and the
// sentence a save would refuse it with, in the caller's language.
type EmailTemplateProblemResponse struct {
	Field       string `json:"field"`
	Rule        string `json:"rule"`
	Placeholder string `json:"placeholder,omitempty"`
	Message     string `json:"message"`
}

// EmailTemplateLanguageResponse is one language of an email. BuiltInText is what Goiabada ships;
// EditorText is the edit laid over it, as the administrator last saved it, also when the status is
// invalid. EditedFields names the fields the edit holds, empty for none. Problems lists what an
// invalid edit breaks, and is empty otherwise. The email is sent with EditorText unless the status
// is invalid, when it is sent with BuiltInText.
type EmailTemplateLanguageResponse struct {
	Language     string                         `json:"language"`
	Status       string                         `json:"status"`
	BuiltInText  EmailTemplateTextResponse      `json:"builtInText"`
	EditorText   EmailTemplateTextResponse      `json:"editorText"`
	EditedFields []string                       `json:"editedFields"`
	Problems     []EmailTemplateProblemResponse `json:"problems"`
}

// EmailTemplateResponse is one email: the placeholders it offers, whether it has a button, and
// each of the six languages, English first.
type EmailTemplateResponse struct {
	Id           string                             `json:"id"`
	HasButton    bool                               `json:"hasButton"`
	Placeholders []EmailTemplatePlaceholderResponse `json:"placeholders"`
	Languages    []EmailTemplateLanguageResponse    `json:"languages"`
}

// GetEmailTemplateResponse is the read of one email.
type GetEmailTemplateResponse struct {
	EmailTemplate EmailTemplateResponse `json:"emailTemplate"`
}

// SaveEmailTemplateRequest is the whole text of one language. ButtonLabel is for an email with a
// button, and refused for one without.
type SaveEmailTemplateRequest struct {
	Subject     string `json:"subject"`
	ButtonLabel string `json:"buttonLabel"`
	Body        string `json:"body"`
}

// PreviewEmailTemplateRequest is a text of one language to preview, saved or not: its subject, its
// button label for an email with a button, and its body, with the brand to draw it in, the default
// brand when BrandId is left out.
type PreviewEmailTemplateRequest struct {
	Subject     string `json:"subject"`
	ButtonLabel string `json:"buttonLabel"`
	Body        string `json:"body"`
	BrandId     *int64 `json:"brandId,omitempty"`
}

// PreviewEmailTemplateResponse is the email a preview draws, with the sample values: its subject,
// the HTML document it is sent as, and its plain-text part.
type PreviewEmailTemplateResponse struct {
	Subject string `json:"subject"`
	Html    string `json:"html"`
	Text    string `json:"text"`
}

// SendTestEmailTemplateRequest is a text of one language to send to To as a recipient would get
// it, with the preview's sample values, in the brand BrandId names or the default brand.
type SendTestEmailTemplateRequest struct {
	To          string `json:"to"`
	Subject     string `json:"subject"`
	ButtonLabel string `json:"buttonLabel"`
	Body        string `json:"body"`
	BrandId     *int64 `json:"brandId,omitempty"`
}
