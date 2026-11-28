// Package typedcode reads a code as a person typed it, before it is compared: a one-time code from
// an authenticator app, a recovery code or an emailed verification code (#662 decision 9). A
// Japanese keyboard in kana mode types full-width digits (１２３４５６) and letters (ＡＢＣＤ), and a
// keyboard of another script types that script's digits, where the code holds ASCII ones. Each
// typed string still names exactly one code, so nothing that was refused becomes another code.
//
// It reads characters and nothing more: what a check trims, drops or folds the case of is the
// check's own, before or after.
package typedcode

import (
	"strings"
	"unicode"
)

// Digits returns code with every Unicode decimal digit (general category Nd), in any script, written
// as its ASCII digit. Everything else is left as it is: a number that is not a decimal digit, such as
// a circled digit or a superscript, a letter, a space and a punctuation mark.
func Digits(code string) string {
	return strings.Map(asciiDigit, code)
}

// DigitsAndLatin is Digits that also writes every full-width Latin letter, capital or small, as its
// ASCII letter: the reading of a code that holds letters, a recovery code and a verification code.
// The full-width punctuation beside the letters, the full-width hyphen among it, is left as it is.
func DigitsAndLatin(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'Ａ' && r <= 'Ｚ':
			return 'A' + (r - 'Ａ')
		case r >= 'ａ' && r <= 'ｚ':
			return 'a' + (r - 'ａ')
		}
		return asciiDigit(r)
	}, code)
}

// asciiDigit writes a decimal digit as its ASCII digit. Unicode encodes every decimal digit in a run
// of ten consecutive code points, 0 to 9 in order, a promise of its stability policy, so a digit's
// value is its place in its run. Runs can follow one another with no gap, as the five runs of
// mathematical digits from U+1D7CE do, so the place is counted from the first digit of the unbroken
// stretch the digit is in, ten to a run; a stretch is at most fifty long.
func asciiDigit(r rune) rune {
	if r < 0x80 || !unicode.Is(unicode.Nd, r) {
		return r
	}
	place := 0
	for p := r - 1; unicode.Is(unicode.Nd, p); p-- {
		place++
	}
	return '0' + rune(place%10)
}
