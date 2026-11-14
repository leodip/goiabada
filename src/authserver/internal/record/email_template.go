package record

import "database/sql"

// The bounds of an email template edit's fields, in inputvalidation.TextLength's unit (#818
// decision 7). The subject and button label columns are as wide as their bounds; the body column
// is unbounded on every engine, since 20,000 is past what an NVARCHAR(n) holds, so the body's
// bound is the API's alone.
const (
	EmailTemplateSubjectMaxLength     = 200
	EmailTemplateButtonLabelMaxLength = 60
	EmailTemplateBodyMaxLength        = 20_000
)

// EmailTemplate is an administrator's edit of one email in one language (#818 decision 7).
// EmailTemplate is the email's identifier, such as password_reset_link, and Language one of the
// six built-in language tags; there is at most one row for the two. Holding them to the 19 emails
// and the six languages is the caller's: the data layer stores what it is given.
//
// The row holds only what differs from the built-in text: each of Subject, ButtonLabel and Body is
// NULL for a field left as the built-in text, so that field follows later releases, and a row has
// at least one of them. An edit whose text is the built-in one is not stored: its row is deleted.
// Nothing about whether an edit is valid is stored; that is judged whenever it is read (decision 8).
//
// The email and the language are the row's key and dont-update: a save of the same two replaces
// the fields of the row already there, and never moves a row to another email or language.
type EmailTemplate struct {
	Id            int64          `db:"id" fieldtag:"pk"`
	CreatedAt     sql.NullTime   `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt     sql.NullTime   `db:"updated_at"`
	EmailTemplate string         `db:"email_template" fieldtag:"dont-update"`
	Language      string         `db:"language" fieldtag:"dont-update"`
	Subject       sql.NullString `db:"subject"`
	ButtonLabel   sql.NullString `db:"button_label"`
	Body          sql.NullString `db:"body"`
}

// HasEditedField reports whether the edit holds at least one field that differs from the built-in
// text, which every stored row does.
func (e *EmailTemplate) HasEditedField() bool {
	return e.Subject.Valid || e.ButtonLabel.Valid || e.Body.Valid
}
