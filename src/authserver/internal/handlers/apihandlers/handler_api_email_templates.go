package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// The admin API's email templates (#818 decisions 7 to 10, 13 and 17), in the settings domain: an
// administrator's edit of the subject, the button label and the body of one of the 19 emails, in
// one of the six built-in languages. One language of one email is what is saved and reset, so two
// administrators working on different languages never overwrite each other.
//
// A stored edit holds only the fields that differ from the built-in text, and its validity is
// judged whenever it is read, by the release that is running, never stored. Saving and resetting
// decide what users' mail says, which is reserved to authserver:manage as where it goes is
// (decision 9), so both writes meet the settings ceiling after the request's own 404 and 400 answers.

// emailTemplatesReader is what the list and the read need: every stored edit.
type emailTemplatesReader interface {
	GetAllEmailTemplates(ctx context.Context, tx *sql.Tx) ([]record.EmailTemplate, error)
}

// emailTemplateSaver is what a save needs: storing an edit, or removing it when the text saved is
// the built-in one.
type emailTemplateSaver interface {
	SaveEmailTemplate(ctx context.Context, tx *sql.Tx, edit *record.EmailTemplate) error
	DeleteEmailTemplate(ctx context.Context, tx *sql.Tx, emailTemplate string, language string) (bool, error)
}

// emailTemplateResetter is what a reset needs: removing an edit.
type emailTemplateResetter interface {
	DeleteEmailTemplate(ctx context.Context, tx *sql.Tx, emailTemplate string, language string) (bool, error)
}

// emailTemplateEdits reads every stored edit, by email and language. A row for an email or a
// language this release does not have is left out: nothing reads it.
func emailTemplateEdits(ctx context.Context, database emailTemplatesReader) (map[string]apimapping.EmailTemplateEdits, error) {
	rows, err := database.GetAllEmailTemplates(ctx, nil)
	if err != nil {
		return nil, errs.Wrap(err, "database error getting the email template edits")
	}
	edits := make(map[string]apimapping.EmailTemplateEdits)
	for i := range rows {
		row := &rows[i]
		if edits[row.EmailTemplate] == nil {
			edits[row.EmailTemplate] = apimapping.EmailTemplateEdits{}
		}
		edits[row.EmailTemplate][row.Language] = row
	}
	return edits, nil
}

// emailTemplateFromPath is the email the {email} path value names, its identifier exactly,
// answering 404 when there is none.
func emailTemplateFromPath(w http.ResponseWriter, r *http.Request) (*emailtemplate.Email, bool) {
	email, ok := emailtemplate.Lookup(r.PathValue("email"))
	if !ok {
		writeEmailTemplateNotFound(w)
		return nil, false
	}
	return email, true
}

// emailTemplateLanguageFromPath is the email and the language the {email} and {language} path
// values name, answering 404 for an email there is none of or a language that is not exactly one of
// the six built-in tags.
func emailTemplateLanguageFromPath(w http.ResponseWriter, r *http.Request) (*emailtemplate.Email, string, bool) {
	email, ok := emailTemplateFromPath(w, r)
	if !ok {
		return nil, "", false
	}
	lang := r.PathValue("language")
	if !slices.Contains(emailtemplate.Languages, lang) {
		writeEmailTemplateNotFound(w)
		return nil, "", false
	}
	return email, lang, true
}

func writeEmailTemplateNotFound(w http.ResponseWriter) {
	writeJSONError(w, "Email template not found", "NOT_FOUND", http.StatusNotFound)
}

// HandleEmailTemplatesGet lists the 19 emails, each with its six languages' status.
func HandleEmailTemplatesGet(database emailTemplatesReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		edits, err := emailTemplateEdits(r.Context(), database)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		emails := emailtemplate.BuiltIns()
		response := api.GetEmailTemplatesResponse{EmailTemplates: make([]api.EmailTemplateSummaryResponse, 0, len(emails))}
		for _, email := range emails {
			response.EmailTemplates = append(response.EmailTemplates, apimapping.ToEmailTemplateSummaryResponse(email, edits[email.ID]))
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleEmailTemplateGet reads one email: its placeholders, whether it has a button, and each
// language's built-in text, editor's text, edited fields, status and problems.
func HandleEmailTemplateGet(database emailTemplatesReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, ok := emailTemplateFromPath(w, r)
		if !ok {
			return
		}
		edits, err := emailTemplateEdits(r.Context(), database)
		if err != nil {
			writeInternalServerError(w, r, err, "email_template", email.ID)
			return
		}
		writeJSON(w, r, http.StatusOK, api.GetEmailTemplateResponse{
			EmailTemplate: apimapping.ToEmailTemplateResponse(email, edits[email.ID], emailTemplateProblemMessage(r.Context())),
		})
	}
}

// HandleEmailTemplatePut saves the whole text of one language. A text a rule refuses is answered
// 400 with the first problem; one that passes is stored as the fields that differ from the built-in
// text of the language, and a text identical to it removes the edit, as a reset does.
func HandleEmailTemplatePut(database emailTemplateSaver, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, lang, ok := emailTemplateLanguageFromPath(w, r)
		if !ok {
			return
		}
		var req api.SaveEmailTemplateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		text := emailtemplate.Text{Subject: req.Subject, ButtonLabel: req.ButtonLabel, Body: normalizeLineBreaks(req.Body)}
		if problems := email.Check(text); len(problems) > 0 {
			writeValidationError(w, r, emailTemplateRefusalAt(email, problems[0]))
			return
		}
		if !settingsCeilingAllows(w, r, auditLogger) {
			return
		}

		edit := emailTemplateEditOf(email, lang, text)
		if !edit.HasEditedField() {
			deleted, err := database.DeleteEmailTemplate(r.Context(), nil, email.ID, lang)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error removing the email template edit"),
					"email_template", email.ID, "language", lang)
				return
			}
			if deleted {
				logEmailTemplateReset(r, auditLogger, email, lang)
			}
			writeJSON(w, r, http.StatusOK, apimapping.ToEmailTemplateLanguageResponse(email, lang, nil, emailTemplateProblemMessage(r.Context())))
			return
		}

		if err := database.SaveEmailTemplate(r.Context(), nil, edit); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error saving the email template edit"),
				"email_template", email.ID, "language", lang)
			return
		}
		var editedFields []string
		if edit.Subject.Valid {
			editedFields = append(editedFields, string(emailtemplate.FieldSubject))
		}
		if edit.ButtonLabel.Valid {
			editedFields = append(editedFields, string(emailtemplate.FieldButtonLabel))
		}
		if edit.Body.Valid {
			editedFields = append(editedFields, string(emailtemplate.FieldBody))
		}
		auditLogger.Log(r.Context(), audit.EventUpdatedEmailTemplate, map[string]interface{}{
			"email_template": email.ID,
			"language":       lang,
			"edited_fields":  editedFields,
			"logged_in_user": callerSubject(r),
		})
		writeJSON(w, r, http.StatusOK, apimapping.ToEmailTemplateLanguageResponse(email, lang, edit, emailTemplateProblemMessage(r.Context())))
	}
}

// HandleEmailTemplateDelete resets one language to the built-in text: it removes the edit, and
// answers 204 also when there was none, which it does not audit.
func HandleEmailTemplateDelete(database emailTemplateResetter, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, lang, ok := emailTemplateLanguageFromPath(w, r)
		if !ok {
			return
		}
		if !settingsCeilingAllows(w, r, auditLogger) {
			return
		}
		deleted, err := database.DeleteEmailTemplate(r.Context(), nil, email.ID, lang)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error removing the email template edit"),
				"email_template", email.ID, "language", lang)
			return
		}
		if deleted {
			logEmailTemplateReset(r, auditLogger, email, lang)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func logEmailTemplateReset(r *http.Request, auditLogger AuditLogger, email *emailtemplate.Email, lang string) {
	auditLogger.Log(r.Context(), audit.EventResetEmailTemplate, map[string]interface{}{
		"email_template": email.ID,
		"language":       lang,
		"logged_in_user": callerSubject(r),
	})
}

// normalizeLineBreaks writes every line break of a body as one newline, as the built-in bodies
// are written, so a body sent back from a form, whose text area answers CRLF, is the built-in one
// when its words are.
func normalizeLineBreaks(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// emailTemplateEditOf is the edit that saving text in lang stores: each field that differs from the
// built-in text of lang, and NULL for each that does not, so it follows later releases (#818
// decision 7). An email with no button stores no button label.
func emailTemplateEditOf(email *emailtemplate.Email, lang string, text emailtemplate.Text) *record.EmailTemplate {
	builtIn := email.BuiltIn[lang]
	differing := func(value, builtIn string) sql.NullString {
		return sql.NullString{String: value, Valid: value != builtIn}
	}
	edit := &record.EmailTemplate{
		EmailTemplate: email.ID,
		Language:      lang,
		Subject:       differing(text.Subject, builtIn.Subject),
		Body:          differing(text.Body, builtIn.Body),
	}
	if email.HasButton() {
		edit.ButtonLabel = differing(text.ButtonLabel, builtIn.ButtonLabel)
	}
	return edit
}

// emailTemplateProblemMessage is the sentence a save refuses a problem with, in the language ctx
// names.
func emailTemplateProblemMessage(ctx context.Context) apimapping.EmailTemplateProblemMessage {
	return func(email *emailtemplate.Email, problem emailtemplate.Problem) string {
		return emailTemplateRefusal(email, problem).Localize(ctx)
	}
}

// emailTemplateRefusalAt is a save's refusal of a problem, about the member of the request body its
// field is.
func emailTemplateRefusalAt(email *emailtemplate.Email, problem emailtemplate.Problem) error {
	return refusalAt(emailTemplateRefusal(email, problem), apimapping.EmailTemplateField(problem.Field))
}

// emailTemplateRefusal is the refusal of one problem (#818 decision 3): the rule, and for a rule
// about a placeholder its name with its braces and what the email offers, or for the subject what
// the subject may use.
func emailTemplateRefusal(email *emailtemplate.Email, problem emailtemplate.Problem) *i18n.LocalizedError {
	placeholder := "{{" + problem.Placeholder + "}}"
	offered := func(inSubjectOnly bool) string {
		var names []string
		for _, p := range email.Placeholders {
			if !inSubjectOnly || p.InSubject() {
				names = append(names, "{{"+p.Name+"}}")
			}
		}
		return strings.Join(names, ", ")
	}
	switch problem.Rule {
	case emailtemplate.RuleEmpty:
		if problem.Field == emailtemplate.FieldButtonLabel {
			return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateButtonLabelRequired, nil)
		}
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateSubjectRequired, nil)
	case emailtemplate.RuleTooLong:
		switch problem.Field {
		case emailtemplate.FieldSubject:
			return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateSubjectTooLong, map[string]any{"max": record.EmailTemplateSubjectMaxLength})
		case emailtemplate.FieldButtonLabel:
			return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateButtonLabelTooLong, map[string]any{"max": record.EmailTemplateButtonLabelMaxLength})
		default:
			return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateBodyTooLong, map[string]any{"max": record.EmailTemplateBodyMaxLength})
		}
	case emailtemplate.RuleNotOneLine:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateSubjectNotOneLine, nil)
	case emailtemplate.RuleNoButton:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateNoButton, nil)
	case emailtemplate.RuleUnknownPlaceholder:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateUnknownPlaceholder,
			map[string]any{"placeholder": placeholder, "offered": offered(false)})
	case emailtemplate.RuleRequiredPlaceholderMissing:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateRequiredPlaceholderMissing,
			map[string]any{"placeholder": placeholder, "offered": offered(false)})
	case emailtemplate.RulePlaceholderNotInSubject:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplatePlaceholderNotInSubject,
			map[string]any{"placeholder": placeholder, "offered": offered(true)})
	case emailtemplate.RuleButtonNotAlone:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateButtonNotAlone, map[string]any{"placeholder": placeholder})
	case emailtemplate.RulePlaceholderInLinkDestination:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplatePlaceholderInLinkDestination,
			map[string]any{"placeholder": placeholder, "link": "{{" + emailtemplate.Link + "}}"})
	default:
		return i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateNothingToRead, nil)
	}
}
