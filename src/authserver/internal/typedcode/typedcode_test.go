package typedcode

import (
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
)

// Each expected value is written out, from the Unicode code charts, not derived the way the
// package derives it (#662 decision 9).
func TestDigits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typed string
		want  string
	}{
		{"ASCII digits stay as they are", "123456", "123456"},
		{"full-width digits, as a Japanese keyboard in kana mode types them", "１２３４５６", "123456"},
		{"Arabic-Indic digits", "٠١٢٣٤٥٦٧٨٩", "0123456789"},
		{"Extended Arabic-Indic digits", "۰۱۲۳۴۵۶۷۸۹", "0123456789"},
		{"Devanagari digits", "०१२३४५६७८९", "0123456789"},
		{"Bengali digits", "০১২৩৪৫৬৭৮৯", "0123456789"},
		{"Thai digits", "๐๑๒๓๔๕๖๗๘๙", "0123456789"},
		{"a mix of scripts in one code", "1２٣४५6", "123456"},
		// U+1D7CE to U+1D7FF are five runs of ten mathematical digits with no gap between them,
		// so a digit's value is its place in its run, not in the block.
		{"mathematical bold digits", "𝟎𝟗", "09"},
		{"mathematical double-struck digits, which follow the bold ones directly", "𝟘𝟙𝟡", "019"},
		{"mathematical monospace digits, the last run of the block", "𝟶𝟿", "09"},
		// Numbers that are not decimal digits (general category No and Nl) are left alone.
		{"a circled digit, a superscript, a fraction and a Roman numeral stay", "①²½Ⅻ", "①²½Ⅻ"},
		{"letters stay, full-width ones too", "abcＡＢＣ", "abcＡＢＣ"},
		{"spaces stay where they are, inside and around", " 12 34　56　", " 12 34　56　"},
		{"punctuation stays, the full-width hyphen too", "12-34－56", "12-34－56"},
		{"nothing typed", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Digits(tc.typed))
		})
	}
}

func TestDigitsAndLatin(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typed string
		want  string
	}{
		{"a verification code typed wholly in full-width", "ＡＢＣＤ１２３４", "ABCD1234"},
		{"and in lower case", "ａｂｃｄ１２３４", "abcd1234"},
		{"every full-width capital", "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
		{"every full-width small letter", "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ", "abcdefghijklmnopqrstuvwxyz"},
		{"a full-width letter in a recovery code", "7kq2-ｍ9xh-4trw", "7kq2-m9xh-4trw"},
		{"digits in another script beside full-width letters", "ＡＢＣＤ١٢३4", "ABCD1234"},
		{"ASCII stays as it is", "ABCD1234", "ABCD1234"},
		// Only the Latin letters: the full-width signs beside them in the block are not read.
		{"full-width punctuation and the ideographic space stay", "＠［｀｛－　", "＠［｀｛－　"},
		{"a letter of another script stays", "αЖあ", "αЖあ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, DigitsAndLatin(tc.typed))
		})
	}
}

// Digits reads a digit's value from its place in a run of ten, which holds only while Go's tables
// keep Unicode's promise that decimal digits come in whole runs of ten, 0 to 9 in order. This holds
// the promise over every table the package can be built with, and each digit to an ASCII one.
func TestDigits_EveryDecimalDigitIsReadAsAnASCIIDigit(t *testing.T) {
	block := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.Is(unicode.Nd, r) {
			if block%10 != 0 {
				t.Fatalf("a run of decimal digits ending before %U is %d long, not whole runs of ten", r, block)
			}
			block = 0
			continue
		}
		want := string(rune('0' + block%10))
		block++
		if got := Digits(string(r)); got != want {
			t.Fatalf("%U read as %q, want %q", r, got, want)
		}
	}
}
