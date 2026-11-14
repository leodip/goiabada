package main

import (
	"context"
	"database/sql"
	"log/slog"
	"slices"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// emailTemplateEdits is what the start reads every email template edit from. data.Database
// satisfies it.
type emailTemplateEdits interface {
	GetAllEmailTemplates(ctx context.Context, tx *sql.Tx) ([]record.EmailTemplate, error)
}

// logInvalidEmailTemplates writes the records a start carries for the email template edits this
// release finds invalid, one Warn for each, naming the email, the language and the rules broken, and
// never the text (#818 decision 8). Such an edit stays stored, and its email is sent with the
// built-in text of its language until an administrator corrects it or resets it; each send says so
// again. Nothing about validity is stored, so a rollback or a second server on another release
// judges the same row by its own rules.
//
// An edit of an email or a language this release does not have is sent with nothing, and so is not
// reported. A read that fails stops nothing: the edits are judged again at each send.
func logInvalidEmailTemplates(ctx context.Context, edits emailTemplateEdits) {
	stored, err := edits.GetAllEmailTemplates(ctx, nil)
	if err != nil {
		slog.WarnContext(ctx, "unable to read the email template edits, so they are not checked", "error", err)
		return
	}
	for i := range stored {
		edit := &stored[i]
		email, ok := emailtemplate.Lookup(edit.EmailTemplate)
		if !ok || !slices.Contains(emailtemplate.Languages, edit.Language) {
			continue
		}
		if _, problems := email.TextToSend(edit.Language, edit); len(problems) > 0 {
			slog.WarnContext(ctx, "the email template edit is invalid, so the email is sent with the built-in text until it is corrected or reset",
				"email_template", edit.EmailTemplate, "language", edit.Language, "problems", problems.Broken(),
				"remedy", "in the admin console, under Admin, Email, Email templates, correct the edit or reset it to the default")
		}
	}
}
