// Package personname writes a person's full name from the given, middle and family names a profile
// carries. It is the one statement of how a full name is ordered: the auth server writes the OIDC
// "name" claim and the emails' {{name}} with it, and the admin console every name it shows, so a
// user reads the same in a token, an email and the console (#662 decision 2).
//
// It is a package of its own, as core/gender and core/passwordrules are, because both applications
// write a full name and must write the same one, and neither reaches the other's packages.
package personname

import (
	"strings"
	"unicode"
)

// FullName is the full name the three parts write. When the given and the family name are each
// written in Han, Hiragana, Katakana or Hangul, it is the family name followed by the given name
// with no space: 山田 and 太郎 read 山田太郎, 김 and 민준 김민준. OpenID Connect Core section 5.1 orders
// the name claim "according to the End-User's locale and preferences", and those scripts write a
// name family first; the rule reads the name alone, so a user's full name is the same in every
// application and on every page (#662 decision 1).
//
// Two names written wholly in katakana keep the given name first, with its space, since such a
// name is most likely a foreign one written as it is spoken: ジョン and スミス read "ジョン スミス".
// A middle name keeps the given name first unless it too is in those scripts, when the name reads
// family, given, middle with no spaces. Every other name is the parts it has, given, middle,
// family, joined by spaces.
func FullName(givenName, middleName, familyName string) string {
	foreign := whollyKatakana(givenName) && whollyKatakana(familyName)
	if inEastAsianScript(givenName) && inEastAsianScript(familyName) && !foreign &&
		(middleName == "" || inEastAsianScript(middleName)) {

		return strings.TrimSpace(familyName + givenName + middleName)
	}

	parts := make([]string, 0, 3)
	for _, part := range []string{givenName, middleName, familyName} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// inEastAsianScript reports whether part has a letter and every letter of it is a Han, Hiragana,
// Katakana or Hangul letter, or one of the letters those names are written with that Go's tables
// class as Common. Only letters are asked about, so the punctuation, the marks written on a letter
// and the joiners the name rule accepts inside a part never disqualify it, the combining voiced
// marks (U+3099, U+309A) among them. Go's tables already class 々 as Han, the kana iteration marks
// as Hiragana and Katakana, and ヶ and ヵ as Katakana.
func inEastAsianScript(part string) bool {
	hasLetter := false
	for _, r := range part {
		if !unicode.IsLetter(r) {
			continue
		}
		hasLetter = true
		if !unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) &&
			!commonKanaLetter(r) && r != '〆' {

			return false
		}
	}
	return hasLetter
}

// whollyKatakana reports whether part has a letter and every letter of it is a Katakana letter,
// full-width or half-width, or one of the Common letters katakana is written with.
func whollyKatakana(part string) bool {
	hasLetter := false
	for _, r := range part {
		if !unicode.IsLetter(r) {
			continue
		}
		hasLetter = true
		if !unicode.Is(unicode.Katakana, r) && !commonKanaLetter(r) {
			return false
		}
	}
	return hasLetter
}

// commonKanaLetter reports whether r is one of the letters kana is written with that Go's tables
// class as Common rather than as Hiragana or Katakana: the prolonged sound mark ー (U+30FC) and its
// half-width form (U+FF70), and the half-width voiced and semi-voiced sound marks (U+FF9E, U+FF9F),
// which half-width katakana writes as letters of their own (ｼﾞｭﾝ).
func commonKanaLetter(r rune) bool {
	switch r {
	case 'ー', 'ｰ', 'ﾞ', 'ﾟ':
		return true
	}
	return false
}
