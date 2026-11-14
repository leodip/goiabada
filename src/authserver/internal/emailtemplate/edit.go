package emailtemplate

import "github.com/leodip/goiabada/authserver/internal/record"

// Lookup answers the built-in definition of the email id names, its identifier exactly, and whether
// there is one.
func Lookup(id string) (*Email, bool) {
	for _, email := range builtIns {
		if email.ID == id {
			return email, true
		}
	}
	return nil, false
}

// EditedText answers lang's text as an administrator last saved it (#818 decisions 7 and 10): each
// field edit holds laid over the built-in text of lang, and each field it leaves NULL read from the
// built-in text, so that field follows later releases. A nil edit is the built-in text. The answer
// is not checked: an edit a later release made invalid is answered as stored.
func (e *Email) EditedText(lang string, edit *record.EmailTemplate) Text {
	text := e.BuiltIn[lang]
	if edit == nil {
		return text
	}
	if edit.Subject.Valid {
		text.Subject = edit.Subject.String
	}
	if edit.ButtonLabel.Valid {
		text.ButtonLabel = edit.ButtonLabel.String
	}
	if edit.Body.Valid {
		text.Body = edit.Body.String
	}
	return text
}

// TextToSend answers the text an email in lang is sent with, given its stored edit in lang, nil for
// none (#818 decision 8): the edited text while Check accepts it, and otherwise the built-in text of
// lang, every field of it even when one field alone breaks a rule, with the problems that made it
// fall back. Validity is judged here, by the release that is running, and never stored.
func (e *Email) TextToSend(lang string, edit *record.EmailTemplate) (Text, Problems) {
	builtIn := e.BuiltIn[lang]
	if edit == nil {
		return builtIn, nil
	}
	text := e.EditedText(lang, edit)
	if problems := e.Check(text); len(problems) > 0 {
		return builtIn, problems
	}
	return text, nil
}
