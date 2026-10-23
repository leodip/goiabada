// Package passwordblocklist holds the two whole-password checks NIST SP 800-63B-4 section 3.1.1.2
// asks of a new password under the nist policy: that it is not one of the passwords attackers try
// first, and that it is not the account's own details or the app's name, or a simple derivative of
// them.
//
// The list is data_generated.go, which generate/main.go writes from three public lists pinned by
// SHA-256 (see that file, or run `version-manager.sh generate passwordblocklist`): the UK NCSC's
// 100,000 most used passwords, Pwdb's top 1,000,000 and xato's top 1,000,000, each source and its
// licence named in the generated file's header. It keeps only the 16,051 entries the policy could
// otherwise accept, 15 characters or more and at most bcrypt's 72 bytes (#550 decisions 4 and 5).
//
// The package imports the standard library alone, because the setup wizard links it through the
// first administrator's rule, and links whatever it imports.
package passwordblocklist

import (
	"strings"
	"unicode"
)

// IsCommon reports whether password, lowercased, is an entry of the list. The whole password is
// compared, never a substring or a word within it, which the section requires ("The entire password
// SHALL be subject to comparison, not substrings or words that might be contained therein"), and
// case is ignored, so the capitalised variants attackers try beside each entry are refused too.
func IsCommon(password string) bool {
	entry := strings.ToLower(password)
	// The list's entries are delimited by newlines, so a password holding one would otherwise be
	// matched against two entries and the newline between them.
	if entry == "" || strings.Contains(entry, "\n") {
		return false
	}
	return strings.Contains(list, "\n"+entry+"\n")
}

// IsTooClose reports whether password is one of words or a simple derivative of one, the
// "context-specific words, such as the name of the service, the username, and derivatives thereof"
// the section lists among expected passwords (#550 decision 6).
//
// The password and each word are read lowercased, both as they are and with the digits, symbols
// and spaces at either end trimmed. The password is too close when one of its readings is one of a
// word's readings, or that reading repeated: for the app name Goiabada, goiabada2026!!!!! and
// GoiabadaGoiabada are refused, while a passphrase that merely contains the name is not. A word
// that reads as empty is skipped, so an absent username refuses nothing.
func IsTooClose(password string, words ...string) bool {
	candidates := readings(password)
	for _, word := range words {
		for _, w := range readings(word) {
			for _, c := range candidates {
				if isRepetitionOf(c, w) {
					return true
				}
			}
		}
	}
	return false
}

// readings returns s lowercased, and lowercased with every character that is not a letter trimmed
// from both ends, leaving out an empty one.
func readings(s string) []string {
	lower := strings.ToLower(s)
	trimmed := strings.TrimFunc(lower, func(r rune) bool { return !unicode.IsLetter(r) })
	out := make([]string, 0, 2)
	for _, r := range []string{lower, trimmed} {
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

// isRepetitionOf reports whether s is word written one or more times over.
func isRepetitionOf(s, word string) bool {
	if len(s)%len(word) != 0 {
		return false
	}
	return strings.Repeat(word, len(s)/len(word)) == s
}
