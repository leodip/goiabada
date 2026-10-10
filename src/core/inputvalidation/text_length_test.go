package inputvalidation

import (
	"strings"
	"testing"
)

// The unit is a UTF-16 code unit, what SQL Server's nvarchar and a browser's maxlength count: one
// for every letter of the Basic Multilingual Plane, accented, Cyrillic or Han, two for a character
// beyond it. Bytes would give the é row 2 and the Han row 3.
func TestTextLength(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"empty", "", 0},
		{"ASCII", "Goiabada", 8},
		{"accented Latin", "José", 4},
		{"Cyrillic", "Гойабада", 8},
		{"Han", "番石榴", 3},
		{"an emoji outside the BMP counts two", "ok 👍", 5},
		{"thirty é", strings.Repeat("é", 30), 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TextLength(tc.text); got != tc.want {
				t.Errorf("TextLength(%q) = %d, want %d", tc.text, got, tc.want)
			}
		})
	}
}
