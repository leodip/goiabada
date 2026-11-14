package apimapping

import (
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// EmailTemplateEdits are the stored edits of one email, by language.
type EmailTemplateEdits map[string]*record.EmailTemplate

// EmailTemplateProblemMessage is the sentence a save refuses a problem with, in the caller's
// language.
type EmailTemplateProblemMessage func(email *emailtemplate.Email, problem emailtemplate.Problem) string

// emailTemplateFields names a format's field as the API does, by the request's member names.
var emailTemplateFields = map[emailtemplate.Field]string{
	emailtemplate.FieldSubject:     api.EmailTemplateFieldSubject,
	emailtemplate.FieldButtonLabel: api.EmailTemplateFieldButtonLabel,
	emailtemplate.FieldBody:        api.EmailTemplateFieldBody,
}

// EmailTemplateField is the API's name for a field of the format: subject, buttonLabel or body.
func EmailTemplateField(field emailtemplate.Field) string {
	return emailTemplateFields[field]
}

// EmailTemplateStatus is the status of lang of email given its stored edit, nil for none (#818
// decision 8), judged by the release that is running: default with no edit, invalid when the edit
// breaks a rule, with the problems, and edited otherwise.
func EmailTemplateStatus(email *emailtemplate.Email, lang string, edit *record.EmailTemplate) (string, emailtemplate.Problems) {
	if edit == nil {
		return api.EmailTemplateStatusDefault, nil
	}
	if _, problems := email.TextToSend(lang, edit); len(problems) > 0 {
		return api.EmailTemplateStatusInvalid, problems
	}
	return api.EmailTemplateStatusEdited, nil
}

// ToEmailTemplateSummaryResponse is email as the list gives it, each built-in language with its
// status.
func ToEmailTemplateSummaryResponse(email *emailtemplate.Email, edits EmailTemplateEdits) api.EmailTemplateSummaryResponse {
	languages := make([]api.EmailTemplateLanguageStatusResponse, 0, len(emailtemplate.Languages))
	for _, lang := range emailtemplate.Languages {
		status, _ := EmailTemplateStatus(email, lang, edits[lang])
		languages = append(languages, api.EmailTemplateLanguageStatusResponse{Language: lang, Status: status})
	}
	return api.EmailTemplateSummaryResponse{Id: email.ID, Languages: languages}
}

// ToEmailTemplateResponse is the read of one email: its placeholders, whether it has a button, and
// each built-in language.
func ToEmailTemplateResponse(email *emailtemplate.Email, edits EmailTemplateEdits, message EmailTemplateProblemMessage) api.EmailTemplateResponse {
	placeholders := make([]api.EmailTemplatePlaceholderResponse, 0, len(email.Placeholders))
	for _, p := range email.Placeholders {
		placeholders = append(placeholders, api.EmailTemplatePlaceholderResponse{Name: p.Name, Required: p.Required, InSubject: p.InSubject()})
	}
	languages := make([]api.EmailTemplateLanguageResponse, 0, len(emailtemplate.Languages))
	for _, lang := range emailtemplate.Languages {
		languages = append(languages, ToEmailTemplateLanguageResponse(email, lang, edits[lang], message))
	}
	return api.EmailTemplateResponse{
		Id: email.ID, HasButton: email.HasButton(), Placeholders: placeholders, Languages: languages,
	}
}

// ToEmailTemplateLanguageResponse is lang of email given its stored edit, nil for none: the
// built-in text, the editor's text (the edit laid over the built-in text, given as stored also
// when it is invalid), the fields the edit holds, the status and an invalid edit's problems.
func ToEmailTemplateLanguageResponse(email *emailtemplate.Email, lang string, edit *record.EmailTemplate,
	message EmailTemplateProblemMessage) api.EmailTemplateLanguageResponse {
	status, problems := EmailTemplateStatus(email, lang, edit)
	editedFields := []string{}
	if edit != nil {
		if edit.Subject.Valid {
			editedFields = append(editedFields, api.EmailTemplateFieldSubject)
		}
		if edit.ButtonLabel.Valid {
			editedFields = append(editedFields, api.EmailTemplateFieldButtonLabel)
		}
		if edit.Body.Valid {
			editedFields = append(editedFields, api.EmailTemplateFieldBody)
		}
	}
	problemResponses := make([]api.EmailTemplateProblemResponse, 0, len(problems))
	for _, p := range problems {
		problemResponses = append(problemResponses, api.EmailTemplateProblemResponse{
			Field: EmailTemplateField(p.Field), Rule: string(p.Rule), Placeholder: p.Placeholder, Message: message(email, p),
		})
	}
	return api.EmailTemplateLanguageResponse{
		Language:     lang,
		Status:       status,
		BuiltInText:  toEmailTemplateTextResponse(email, email.BuiltIn[lang]),
		EditorText:   toEmailTemplateTextResponse(email, email.EditedText(lang, edit)),
		EditedFields: editedFields,
		Problems:     problemResponses,
	}
}

// toEmailTemplateTextResponse is a text, its button label there for an email with a button, or for
// a stored edit that holds one although its email has none, which is invalid.
func toEmailTemplateTextResponse(email *emailtemplate.Email, text emailtemplate.Text) api.EmailTemplateTextResponse {
	response := api.EmailTemplateTextResponse{Subject: text.Subject, Body: text.Body}
	if email.HasButton() || text.ButtonLabel != "" {
		label := text.ButtonLabel
		response.ButtonLabel = &label
	}
	return response
}
