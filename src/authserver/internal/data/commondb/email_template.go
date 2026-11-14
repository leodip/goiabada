package commondb

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// emailTemplateColumns is the email_templates table as scanEmailTemplate reads it.
var emailTemplateColumns = columnList{
	sqlite:   "id, created_at, updated_at, email_template, language, subject, button_label, body",
	mysql:    "id, created_at, updated_at, email_template, language, subject, button_label, body",
	postgres: "id, created_at, updated_at, email_template, language, subject, button_label, body",
	mssql:    "id, created_at, updated_at, email_template, language, subject, button_label, body",
}

// scanEmailTemplate reads one row selected with emailTemplateColumns.
func scanEmailTemplate(row rowScanner, edit *record.EmailTemplate) error {
	return row.Scan(
		&edit.Id,
		&edit.CreatedAt,
		&edit.UpdatedAt,
		&edit.EmailTemplate,
		&edit.Language,
		&edit.Subject,
		&edit.ButtonLabel,
		&edit.Body,
	)
}

// saveEmailTemplate is the one write an edit gets: an insert that, when the email and the language
// already have a row, replaces that row's fields instead, in each engine's own grammar. It is one
// statement so that two saves at once leave the last one's edit, where a read followed by an
// insert would refuse the second as a second row (#818 decision 7). The replace writes updated_at
// and the three fields, and leaves created_at and the key, which are dont-update. Each version
// answers the row's id, inserted or replaced: a RETURNING or OUTPUT row on SQLite, PostgreSQL and
// SQL Server, and on MySQL the driver's last insert id, which LAST_INSERT_ID(id) sets to the
// replaced row's.
//
// MySQL binds the replaced fields a second time, after the inserted ones: VALUES(column) is
// deprecated there, and a row alias needs 8.0.19. SQL Server has no insert-or-update, so its
// version is a MERGE under HOLDLOCK, which holds the key's range until the transaction ends, so a
// second MERGE of the same key waits and then finds the row instead of inserting another.
var saveEmailTemplate = statement{
	sqlite: "INSERT INTO email_templates (created_at, updated_at, email_template, language, subject, button_label, body) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?) " +
		"ON CONFLICT (email_template, language) DO UPDATE SET updated_at = excluded.updated_at, " +
		"subject = excluded.subject, button_label = excluded.button_label, body = excluded.body RETURNING id",
	mysql: "INSERT INTO email_templates (created_at, updated_at, email_template, language, subject, button_label, body) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?) " +
		"ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), updated_at = ?, subject = ?, button_label = ?, body = ?",
	postgres: "INSERT INTO email_templates (created_at, updated_at, email_template, language, subject, button_label, body) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7) " +
		"ON CONFLICT (email_template, language) DO UPDATE SET updated_at = excluded.updated_at, " +
		"subject = excluded.subject, button_label = excluded.button_label, body = excluded.body RETURNING id",
	mssql: "MERGE INTO email_templates WITH (HOLDLOCK) AS target " +
		"USING (VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7)) " +
		"AS source (created_at, updated_at, email_template, language, subject, button_label, body) " +
		"ON target.email_template = source.email_template AND target.language = source.language " +
		"WHEN MATCHED THEN UPDATE SET updated_at = source.updated_at, " +
		"subject = source.subject, button_label = source.button_label, body = source.body " +
		"WHEN NOT MATCHED THEN INSERT (created_at, updated_at, email_template, language, subject, button_label, body) " +
		"VALUES (source.created_at, source.updated_at, source.email_template, source.language, " +
		"source.subject, source.button_label, source.body) " +
		"OUTPUT INSERTED.id;",
}

var selectEmailTemplate = statement{
	sqlite: "SELECT " + emailTemplateColumns.sqlite + " FROM email_templates WHERE email_template = ? AND language = ?",
	mysql:  "SELECT " + emailTemplateColumns.mysql + " FROM email_templates WHERE email_template = ? AND language = ?",
	postgres: "SELECT " + emailTemplateColumns.postgres + " FROM email_templates " +
		"WHERE email_template = $1 AND language = $2",
	mssql: "SELECT " + emailTemplateColumns.mssql + " FROM email_templates " +
		"WHERE email_template = @p1 AND language = @p2",
}

var selectAllEmailTemplates = statement{
	sqlite:   "SELECT " + emailTemplateColumns.sqlite + " FROM email_templates ORDER BY id",
	mysql:    "SELECT " + emailTemplateColumns.mysql + " FROM email_templates ORDER BY id",
	postgres: "SELECT " + emailTemplateColumns.postgres + " FROM email_templates ORDER BY id",
	mssql:    "SELECT " + emailTemplateColumns.mssql + " FROM email_templates ORDER BY id",
}

var deleteEmailTemplate = statement{
	sqlite:   "DELETE FROM email_templates WHERE email_template = ? AND language = ?",
	mysql:    "DELETE FROM email_templates WHERE email_template = ? AND language = ?",
	postgres: "DELETE FROM email_templates WHERE email_template = $1 AND language = $2",
	mssql:    "DELETE FROM email_templates WHERE email_template = @p1 AND language = @p2",
}

// checkEmailTemplateKey refuses an email or a language that is empty, ends in a space or holds
// anything but printable ASCII, none of which an identifier or a built-in language tag does. A
// write matches its row with the engine's own =, and those are the two folds engineFoldedTheMatch
// describes: SQL Server pads a trailing space, and SQL Server and MySQL compare a precomposed
// character equal to its decomposed spelling. Refusing them keeps a write from landing on another
// email's or language's row.
func checkEmailTemplateKey(emailTemplate string, language string) error {
	for _, key := range []struct{ name, value string }{{"email template", emailTemplate}, {"language", language}} {
		if key.value == "" {
			return errs.Errorf("an email template edit needs its %s", key.name)
		}
		if strings.HasSuffix(key.value, " ") {
			return errs.Errorf("the %s %q of an email template edit ends in a space", key.name, key.value)
		}
		for _, r := range key.value {
			if r < ' ' || r > '~' {
				return errs.Errorf("the %s %q of an email template edit is not printable ASCII", key.name, key.value)
			}
		}
	}
	return nil
}

func (d *Database) SaveEmailTemplate(ctx context.Context, tx *sql.Tx, edit *record.EmailTemplate) error {

	if err := checkEmailTemplateKey(edit.EmailTemplate, edit.Language); err != nil {
		return err
	}
	if !edit.HasEditedField() {
		return errs.Errorf("the edit of email template %s in %s holds only the built-in text: delete its row instead",
			edit.EmailTemplate, edit.Language)
	}

	now := time.Now().UTC()
	originalCreatedAt := edit.CreatedAt
	originalUpdatedAt := edit.UpdatedAt
	edit.CreatedAt = sql.NullTime{Time: now, Valid: true}
	edit.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	args := []any{edit.CreatedAt, edit.UpdatedAt, edit.EmailTemplate, edit.Language, edit.Subject, edit.ButtonLabel, edit.Body}
	var id int64
	var err error
	if d.Dialect == data.MySQL {
		args = append(args, edit.UpdatedAt, edit.Subject, edit.ButtonLabel, edit.Body)
		id, err = d.insertReadingLastInsertId(ctx, tx, saveEmailTemplate.text(d.Dialect), "email template", args)
	} else {
		id, err = d.insertReadingReturnedId(ctx, tx, saveEmailTemplate.text(d.Dialect), "email template", args)
	}
	if err != nil {
		edit.CreatedAt = originalCreatedAt
		edit.UpdatedAt = originalUpdatedAt
		return err
	}

	edit.Id = id
	return nil
}

func (d *Database) GetEmailTemplate(ctx context.Context, tx *sql.Tx, emailTemplate string,
	language string) (*record.EmailTemplate, error) {

	edit, err := queryOne(ctx, d, tx, selectEmailTemplate.text(d.Dialect), []any{emailTemplate, language},
		scanEmailTemplate, "email template")
	if err != nil {
		return nil, err
	}
	// The engine may have folded a value this lookup did not ask for, as SQL Server pads a
	// trailing space for =; see engineFoldedTheMatch. An edit is used only for its own email and
	// language.
	if edit != nil && (engineFoldedTheMatch(edit.EmailTemplate, emailTemplate) ||
		engineFoldedTheMatch(edit.Language, language)) {
		return nil, nil
	}

	return edit, nil
}

func (d *Database) GetAllEmailTemplates(ctx context.Context, tx *sql.Tx) ([]record.EmailTemplate, error) {
	return queryAll(ctx, d, tx, nil, selectAllEmailTemplates.text(d.Dialect), nil, scanEmailTemplate, "email template")
}

func (d *Database) DeleteEmailTemplate(ctx context.Context, tx *sql.Tx, emailTemplate string,
	language string) (bool, error) {

	if err := checkEmailTemplateKey(emailTemplate, language); err != nil {
		return false, err
	}

	result, err := d.ExecSQL(ctx, tx, deleteEmailTemplate.text(d.Dialect), emailTemplate, language)
	if err != nil {
		return false, errs.Wrap(err, "unable to delete email template")
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to read the rows the email template delete removed")
	}

	return deleted > 0, nil
}
