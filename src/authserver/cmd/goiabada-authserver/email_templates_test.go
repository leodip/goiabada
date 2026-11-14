package main

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// An email template edit a release has made invalid sends its email with the built-in text until
// it is fixed, so each start says so once for each, as a Warn naming the email and the language and
// never the text (#818 decision 8).

type editsReader struct {
	edits []record.EmailTemplate
	err   error
}

func (r editsReader) GetAllEmailTemplates(context.Context, *sql.Tx) ([]record.EmailTemplate, error) {
	return r.edits, r.err
}

func storedEdit(email, lang, subject, body string) record.EmailTemplate {
	edit := record.EmailTemplate{EmailTemplate: email, Language: lang}
	if subject != "" {
		edit.Subject = sql.NullString{String: subject, Valid: true}
	}
	if body != "" {
		edit.Body = sql.NullString{String: body, Valid: true}
	}
	return edit
}

func TestLogInvalidEmailTemplates_EachInvalidEditIsReportedOnce(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logInvalidEmailTemplates(context.Background(), editsReader{edits: []record.EmailTemplate{
		storedEdit("password_reset_link", "en", "Choose a new password", ""),
		storedEdit("account_deleted", "fr", "", "Bonjour {{name}}, voyez {{link}}."),
		storedEdit("password_reset_link", "de", strings.Repeat("Passwort ", 30), ""),
		storedEdit("welcome", "pt-BR", "", "Olá!\n\n{{button}}"),
	}})

	records := logs.Records()
	require.Len(t, records, 2, "the valid edits are not reported")
	for i, want := range []struct{ email, lang, problem string }{
		{"account_deleted", "fr", "body: unknown_placeholder"},
		{"password_reset_link", "de", "subject: too_long"},
	} {
		assert.Equal(t, slog.LevelWarn, records[i].Level)
		assert.Contains(t, records[i].Message, "built-in text")
		assert.Equal(t, want.email, records[i].Attrs["email_template"])
		assert.Equal(t, want.lang, records[i].Attrs["language"])
		assert.Equal(t, []string{want.problem}, records[i].Attrs["problems"])
	}
	text := logs.Text()
	assert.NotContains(t, text, "Bonjour", "never the text")
	assert.NotContains(t, text, "Passwort")
}

// An edit of an email or a language this release does not have is sent with nothing, so there is
// nothing to say about it; no edits at all, the usual start, writes nothing either.
func TestLogInvalidEmailTemplates_NothingToReport(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logInvalidEmailTemplates(context.Background(), editsReader{edits: []record.EmailTemplate{
		storedEdit("forgot_password", "en", "Reset", ""),
		storedEdit("password_reset_link", "nl", "Wachtwoord", ""),
	}})
	logInvalidEmailTemplates(context.Background(), editsReader{})

	assert.Empty(t, logs.Records())
}

// A read that fails stops nothing: the edits are checked again at each send.
func TestLogInvalidEmailTemplates_AFailedReadIsReported(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	logInvalidEmailTemplates(context.Background(), editsReader{err: errs.New("database unreachable")})

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Contains(t, records[0].Message, "email template")
	assert.Contains(t, logs.Text(), "database unreachable")
}
