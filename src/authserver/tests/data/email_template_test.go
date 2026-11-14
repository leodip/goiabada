package datatests

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Email template edits (#818 decision 7) on every engine: an edit is one row for an email and a
// language, holding only the fields that differ from the built-in text, NULL for the others; what
// is saved reads back unchanged, at the API's bounds; a second save of the same email and language
// replaces the first, also when the two overlap; and a reset removes the row.
//
// The data layer stores any identifier it is given: holding one to the 19 emails and a language to
// the six built-in ones is its caller's. The tests here use an identifier of their own, so they
// share the tier's database with every other test.

func newEmailTemplateIdentifier() string {
	return "test_" + strings.ToLower(fake.LetterN(12))
}

func templateText(s string) sql.NullString {
	return sql.NullString{String: s, Valid: true}
}

func saveEmailTemplate(t *testing.T, edit *record.EmailTemplate) {
	t.Helper()
	require.NoError(t, database.SaveEmailTemplate(context.Background(), nil, edit))
}

// storedEmailTemplates answers every row stored for the email, whatever its language.
func storedEmailTemplates(t *testing.T, emailTemplate string) []record.EmailTemplate {
	t.Helper()
	all, err := database.GetAllEmailTemplates(context.Background(), nil)
	require.NoError(t, err)
	var rows []record.EmailTemplate
	for _, row := range all {
		if row.EmailTemplate == emailTemplate {
			rows = append(rows, row)
		}
	}
	return rows
}

func TestEmailTemplate_ASavedEditReadsBack(t *testing.T) {
	ctx := context.Background()
	email := newEmailTemplateIdentifier()

	edit := &record.EmailTemplate{
		EmailTemplate: email,
		Language:      "pt-BR",
		Subject:       templateText("Redefinir a senha"),
		ButtonLabel:   templateText("Redefinir"),
		Body:          templateText("Olá {{name}},\n\n{{button}}"),
	}
	before := time.Now().UTC().Add(-time.Second)
	saveEmailTemplate(t, edit)
	require.NotZero(t, edit.Id, "the save answers the row's id")

	got, err := database.GetEmailTemplate(ctx, nil, email, "pt-BR")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, edit.Id, got.Id)
	assert.Equal(t, email, got.EmailTemplate)
	assert.Equal(t, "pt-BR", got.Language)
	assert.Equal(t, templateText("Redefinir a senha"), got.Subject)
	assert.Equal(t, templateText("Redefinir"), got.ButtonLabel)
	assert.Equal(t, templateText("Olá {{name}},\n\n{{button}}"), got.Body)
	require.True(t, got.CreatedAt.Valid, "created_at is stamped")
	require.True(t, got.UpdatedAt.Valid, "updated_at is stamped")
	assert.True(t, got.CreatedAt.Time.After(before), "created_at is the save's time: %v", got.CreatedAt.Time)
	assert.True(t, got.UpdatedAt.Time.After(before), "updated_at is the save's time: %v", got.UpdatedAt.Time)

	rows := storedEmailTemplates(t, email)
	require.Len(t, rows, 1, "the list holds the edit")
	assert.Equal(t, *got, rows[0], "and reads it as the single read does")
}

func TestEmailTemplate_AFieldLeftAsTheBuiltInTextIsNull(t *testing.T) {
	ctx := context.Background()
	email := newEmailTemplateIdentifier()

	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "de", Subject: templateText("Willkommen")})

	got, err := database.GetEmailTemplate(ctx, nil, email, "de")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, templateText("Willkommen"), got.Subject)
	assert.False(t, got.ButtonLabel.Valid, "a button label not edited is NULL, not an empty label")
	assert.False(t, got.Body.Valid, "a body not edited is NULL, not an empty body")
}

func TestEmailTemplate_TheReadIsExactAndByLanguage(t *testing.T) {
	ctx := context.Background()
	email := newEmailTemplateIdentifier()
	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "fr", Subject: templateText("Bienvenue")})

	for _, c := range []struct{ email, language, why string }{
		{email, "en", "another language has no edit: the French one is never used for it"},
		{email, "FR", "a language in another case is another language"},
		{email, "fr ", "a trailing space is another language, though SQL Server pads for ="},
		{email + " ", "fr", "a trailing space is another email, though SQL Server pads for ="},
		{strings.ToUpper(email), "fr", "an email in another case is another email"},
		{newEmailTemplateIdentifier(), "fr", "an email with no edit"},
	} {
		got, err := database.GetEmailTemplate(ctx, nil, c.email, c.language)
		require.NoError(t, err)
		assert.Nilf(t, got, "%q in %q answers nil: %s", c.email, c.language, c.why)
	}
}

func TestEmailTemplate_TextAtTheAPIBoundsReadsBack(t *testing.T) {
	ctx := context.Background()
	email := newEmailTemplateIdentifier()

	// The bounds decision 7 holds an edit to, in inputvalidation.TextLength's unit, UTF-16 code
	// units: a subject of 200, half of them in astral characters, a button label of 60, and a body
	// of 20,000 in two- and three-byte UTF-8, past what an NVARCHAR(n) column holds.
	subject := strings.Repeat("😀", 50) + strings.Repeat("é", 100)
	button := strings.Repeat("😀", 10) + strings.Repeat("ß", 40)
	body := strings.Repeat("Sécurité — ", 1000) + strings.Repeat("ü", 9000)
	require.Len(t, []rune(body), 20_000)

	saveEmailTemplate(t, &record.EmailTemplate{
		EmailTemplate: email, Language: "es", Subject: templateText(subject), ButtonLabel: templateText(button), Body: templateText(body),
	})
	got, err := database.GetEmailTemplate(ctx, nil, email, "es")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, subject, got.Subject.String)
	assert.Equal(t, button, got.ButtonLabel.String)
	assert.Equal(t, body, got.Body.String)
}

func TestEmailTemplate_ASecondSaveReplacesTheEdit(t *testing.T) {
	ctx := context.Background()
	email := newEmailTemplateIdentifier()

	first := &record.EmailTemplate{
		EmailTemplate: email, Language: "it",
		Subject: templateText("Primo oggetto"), ButtonLabel: templateText("Primo"), Body: templateText("Primo testo."),
	}
	saveEmailTemplate(t, first)
	stored, err := database.GetEmailTemplate(ctx, nil, email, "it")
	require.NoError(t, err)
	require.NotNil(t, stored)

	time.Sleep(timestampTick)
	// The second save leaves the subject and the button label as the built-in text: the whole
	// edit is replaced, so they are cleared, not kept from the first save.
	second := &record.EmailTemplate{EmailTemplate: email, Language: "it", Body: templateText("Secondo testo.")}
	saveEmailTemplate(t, second)
	assert.Equal(t, first.Id, second.Id, "the save answers the id of the row it replaced")

	rows := storedEmailTemplates(t, email)
	require.Len(t, rows, 1, "one row for an email and a language")
	got := rows[0]
	assert.Equal(t, stored.Id, got.Id, "the row is the same row")
	assert.False(t, got.Subject.Valid, "the subject the second save left as the built-in text is cleared")
	assert.False(t, got.ButtonLabel.Valid, "and so is the button label")
	assert.Equal(t, templateText("Secondo testo."), got.Body)
	assert.True(t, stored.CreatedAt.Time.Equal(got.CreatedAt.Time),
		"created_at is the first save's: %v, %v", stored.CreatedAt.Time, got.CreatedAt.Time)
	assert.True(t, got.UpdatedAt.Time.After(stored.UpdatedAt.Time),
		"updated_at moves: %v, %v", stored.UpdatedAt.Time, got.UpdatedAt.Time)
}

func TestEmailTemplate_ASaveLeavesTheOtherLanguagesAndEmailsAlone(t *testing.T) {
	ctx := context.Background()
	email, other := newEmailTemplateIdentifier(), newEmailTemplateIdentifier()

	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "en", Subject: templateText("English")})
	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "fr", Subject: templateText("Français")})
	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: other, Language: "en", Subject: templateText("Other")})

	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "en", Subject: templateText("English, again")})

	for _, c := range []struct{ email, language, subject string }{
		{email, "en", "English, again"},
		{email, "fr", "Français"},
		{other, "en", "Other"},
	} {
		got, err := database.GetEmailTemplate(ctx, nil, c.email, c.language)
		require.NoError(t, err)
		require.NotNilf(t, got, "%s in %s", c.email, c.language)
		assert.Equalf(t, c.subject, got.Subject.String, "%s in %s", c.email, c.language)
	}
	assert.Len(t, storedEmailTemplates(t, email), 2, "one row for each language edited")
}

func TestEmailTemplate_AnEditWithNothingEditedIsRefused(t *testing.T) {
	email := newEmailTemplateIdentifier()

	err := database.SaveEmailTemplate(context.Background(), nil, &record.EmailTemplate{EmailTemplate: email, Language: "en"})
	require.Error(t, err, "an edit holding only the built-in text is a reset, never a row")
	assert.Empty(t, storedEmailTemplates(t, email), "nothing is stored")
}

func TestEmailTemplate_DeleteRemovesOneLanguageAndSaysWhetherThereWasAnEdit(t *testing.T) {
	ctx := context.Background()
	email := newEmailTemplateIdentifier()
	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "en", Body: templateText("English.")})
	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "de", Body: templateText("Deutsch.")})

	deleted, err := database.DeleteEmailTemplate(ctx, nil, email, "en")
	require.NoError(t, err)
	assert.True(t, deleted, "there was an edit to remove")

	gone, err := database.GetEmailTemplate(ctx, nil, email, "en")
	require.NoError(t, err)
	assert.Nil(t, gone, "the edit is removed")
	kept, err := database.GetEmailTemplate(ctx, nil, email, "de")
	require.NoError(t, err)
	require.NotNil(t, kept, "another language's edit is kept")
	assert.Equal(t, templateText("Deutsch."), kept.Body)

	deleted, err = database.DeleteEmailTemplate(ctx, nil, email, "en")
	require.NoError(t, err)
	assert.False(t, deleted, "a reset where there is no edit removes nothing")

	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "en", Body: templateText("English again.")})
	again, err := database.GetEmailTemplate(ctx, nil, email, "en")
	require.NoError(t, err)
	require.NotNil(t, again, "an email reset can be edited again")
	assert.Equal(t, templateText("English again."), again.Body)
}

// TestEmailTemplate_TwoOverlappingFirstSavesLeaveTheLastOne is decision 7's "of two saves at once
// the last wins" where it is hardest: neither save finds a row, so each would insert one. The first
// save is held open after its write; the second, for the same email and language, then waits on it
// and, once the first commits, replaces its edit instead of being refused as a second row.
//
// MySQL, PostgreSQL and SQL Server only: SQLite has one connection, so the second save would wait
// for the held first one forever rather than overlap it.
func TestEmailTemplate_TwoOverlappingFirstSavesLeaveTheLastOne(t *testing.T) {
	skipIfSQLite(t)
	ctx := context.Background()
	email := newEmailTemplateIdentifier()

	b := newBarrier(t, "the first email template save")
	first := make(chan error, 1)
	go func() {
		first <- database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			if err := database.SaveEmailTemplate(ctx, tx, &record.EmailTemplate{
				EmailTemplate: email, Language: "en", Subject: templateText("First"),
			}); err != nil {
				return err
			}
			b.arriveBefore(tx)
			return nil
		})
	}()
	b.awaitParked(t)

	second := make(chan error, 1)
	go func() {
		second <- database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			return database.SaveEmailTemplate(ctx, tx, &record.EmailTemplate{
				EmailTemplate: email, Language: "en", Subject: templateText("Second"), Body: templateText("Second body."),
			})
		})
	}()
	select {
	case err := <-second:
		t.Fatalf("the second save finished while the first held its uncommitted row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	b.releaseParked()
	require.NoError(t, awaitWorker(t, "the first email template save", first))
	require.NoError(t, awaitWorker(t, "the second email template save", second),
		"the second save replaces the first's edit, never refused as a second row")

	rows := storedEmailTemplates(t, email)
	require.Len(t, rows, 1, "one row for an email and a language")
	assert.Equal(t, templateText("Second"), rows[0].Subject, "the last save wins")
	assert.Equal(t, templateText("Second body."), rows[0].Body)
}

// TestEmailTemplate_AKeyAnEngineWouldFoldIsRefused: a save and a reset match their row with the
// engine's own =, which on SQL Server ignores a trailing space and on SQL Server and MySQL takes a
// decomposed accent for the precomposed one. A key no identifier or built-in language tag takes is
// refused, so neither lands on the row of the email and language it was folded into.
func TestEmailTemplate_AKeyAnEngineWouldFoldIsRefused(t *testing.T) {
	ctx := context.Background()
	email := newEmailTemplateIdentifier()
	saveEmailTemplate(t, &record.EmailTemplate{EmailTemplate: email, Language: "fr", Subject: templateText("Bienvenue")})

	for _, c := range []struct{ email, language, why string }{
		{email + " ", "fr", "an email ending in a space"},
		{email, "fr ", "a language ending in a space"},
		{email + "é", "fr", "an email that is not ASCII"},
		{email, "fŕ", "a language that is not ASCII"},
		{"", "fr", "no email"},
		{email, "", "no language"},
	} {
		err := database.SaveEmailTemplate(ctx, nil, &record.EmailTemplate{
			EmailTemplate: c.email, Language: c.language, Subject: templateText("Overwritten"),
		})
		require.Errorf(t, err, "a save of %s is refused", c.why)
		_, err = database.DeleteEmailTemplate(ctx, nil, c.email, c.language)
		require.Errorf(t, err, "a reset of %s is refused", c.why)
	}

	got, err := database.GetEmailTemplate(ctx, nil, email, "fr")
	require.NoError(t, err)
	require.NotNil(t, got, "the edit is still there")
	assert.Equal(t, templateText("Bienvenue"), got.Subject, "and unchanged")
	assert.Len(t, storedEmailTemplates(t, email), 1, "and nothing else is stored for the email")
}
