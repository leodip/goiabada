package emailtemplate

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// An administrator's edit of one email in one language (#818 decisions 7 and 8): the fields it
// holds laid over the built-in text, and the built-in text sent in its place, all of it, while a
// save would refuse it.

// edited is a stored field; a field left unset is NULL, the built-in text's.
func edited(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

func TestLookup_FindsAnEmailByItsIdentifier(t *testing.T) {
	email, ok := Lookup("password_reset_link")
	require.True(t, ok)
	assert.Same(t, PasswordResetLink, email)

	email, ok = Lookup("recovery_code_used")
	require.True(t, ok)
	assert.Same(t, RecoveryCodeUsed, email)

	for _, unknown := range []string{"", "forgot_password", "Password_Reset_Link", "password_reset_link "} {
		_, ok := Lookup(unknown)
		assert.False(t, ok, "%q names no email", unknown)
	}
}

// A field the edit leaves NULL reads the built-in text of the edit's language, so a release that
// corrects it reaches an administrator who only changed another field.
func TestEditedText_LaysTheEditedFieldsOverTheBuiltInText(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit *record.EmailTemplate
		want Text
	}{
		{"no edit is the built-in text", nil, Text{
			Subject:     "Réinitialisation du mot de passe",
			ButtonLabel: "Réinitialiser le mot de passe",
			Body:        PasswordResetLink.BuiltIn["fr"].Body,
		}},
		{"the subject alone", &record.EmailTemplate{Subject: edited("Votre lien")}, Text{
			Subject:     "Votre lien",
			ButtonLabel: "Réinitialiser le mot de passe",
			Body:        PasswordResetLink.BuiltIn["fr"].Body,
		}},
		{"the button label alone", &record.EmailTemplate{ButtonLabel: edited("Choisir un mot de passe")}, Text{
			Subject:     "Réinitialisation du mot de passe",
			ButtonLabel: "Choisir un mot de passe",
			Body:        PasswordResetLink.BuiltIn["fr"].Body,
		}},
		{"the body alone", &record.EmailTemplate{Body: edited("Bonjour {{name}}, {{link}}")}, Text{
			Subject:     "Réinitialisation du mot de passe",
			ButtonLabel: "Réinitialiser le mot de passe",
			Body:        "Bonjour {{name}}, {{link}}",
		}},
		{"every field", &record.EmailTemplate{
			Subject: edited("Votre lien"), ButtonLabel: edited("Ouvrir"), Body: edited("{{link}}"),
		}, Text{Subject: "Votre lien", ButtonLabel: "Ouvrir", Body: "{{link}}"}},
		{"a field stored empty is the edit's, not the built-in text's", &record.EmailTemplate{Subject: edited("")}, Text{
			Subject:     "",
			ButtonLabel: "Réinitialiser le mot de passe",
			Body:        PasswordResetLink.BuiltIn["fr"].Body,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := PasswordResetLink.EditedText("fr", tc.edit)
			assert.Equal(t, tc.want, got)
			if tc.want.Body == PasswordResetLink.BuiltIn["fr"].Body {
				assert.True(t, strings.HasPrefix(got.Body, "Bonjour {{name}},\n\nPour réinitialiser votre mot de passe"),
					"the French built-in body")
			}
		})
	}
}

// An email with no button has no button label in its built-in text, and an edit that holds one is
// laid over it all the same, for the check to refuse.
func TestEditedText_AButtonLabelOnAnEmailWithNoButtonIsKept(t *testing.T) {
	got := AccountDeleted.EditedText("en", &record.EmailTemplate{ButtonLabel: edited("Open")})
	assert.Equal(t, Text{Subject: "Your account was deleted", ButtonLabel: "Open", Body: AccountDeleted.BuiltIn["en"].Body}, got)
}

// The text sent is the editor's while the email's rules accept it, and otherwise the built-in text
// of the language, every field of it, even when one field alone breaks a rule (decision 8).
func TestTextToSend_AnInvalidEditSendsTheBuiltInTextWhole(t *testing.T) {
	builtIn := Text{
		Subject:     "Password reset",
		ButtonLabel: "Reset password",
		Body:        PasswordResetLink.BuiltIn["en"].Body,
	}
	for _, tc := range []struct {
		name         string
		edit         *record.EmailTemplate
		want         Text
		wantProblems Problems
	}{
		{"no edit", nil, builtIn, nil},
		{"a valid edit", &record.EmailTemplate{Subject: edited("Choose a new password"), Body: edited("Hi {{name}}, open {{link}}.")},
			Text{Subject: "Choose a new password", ButtonLabel: "Reset password", Body: "Hi {{name}}, open {{link}}."}, nil},
		{"a name the email no longer offers, in the body alone",
			&record.EmailTemplate{Subject: edited("Choose a new password"), Body: edited("Hi {{full_name}}, open {{link}}.")},
			builtIn, Problems{{Field: FieldBody, Rule: RuleUnknownPlaceholder, Placeholder: "full_name"}}},
		{"the required link missing", &record.EmailTemplate{Body: edited("Hi {{name}}.\n\n{{button}}")},
			builtIn, Problems{{Field: FieldBody, Rule: RuleRequiredPlaceholderMissing, Placeholder: "link"}}},
		{"a subject past its limit", &record.EmailTemplate{Subject: edited(strings.Repeat("x", 201)), Body: edited("Open {{link}}.")},
			builtIn, Problems{{Field: FieldSubject, Rule: RuleTooLong}}},
		{"a button label stored empty", &record.EmailTemplate{ButtonLabel: edited("")},
			builtIn, Problems{{Field: FieldButtonLabel, Rule: RuleEmpty}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, problems := PasswordResetLink.TextToSend("en", tc.edit)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantProblems, problems)
		})
	}
}

// Another email's and another language's rules are their own: an edit of the notice that an account
// was deleted offering no link is refused the link, which the password reset link offers.
func TestTextToSend_IsJudgedByItsOwnEmailsRules(t *testing.T) {
	edit := &record.EmailTemplate{Body: edited("Hello {{name}}, sign in again at {{link}}.")}

	_, problems := PasswordResetLink.TextToSend("de", edit)
	assert.Empty(t, problems)

	got, problems := AccountDeleted.TextToSend("de", edit)
	assert.Equal(t, Problems{{Field: FieldBody, Rule: RuleUnknownPlaceholder, Placeholder: "link"}}, problems)
	assert.Equal(t, AccountDeleted.BuiltIn["de"], got)
}
