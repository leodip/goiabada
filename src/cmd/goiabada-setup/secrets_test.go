package main

import (
	"strings"
	"testing"
)

// Every generated password is 16 letters and digits holding all three classes, so SQL Server takes
// it as an SA password: a plain draw had no digit one time in 17 (#430). Two thousand draws miss a
// password without a digit, were the redraw gone, with probability 0.94^2000.
func TestGeneratePassword_SixteenLettersAndDigitsOfThreeClasses(t *testing.T) {
	seen := map[string]bool{}
	for range 2000 {
		password := generatePassword()
		if len(password) != generatedPasswordLength {
			t.Fatalf("generated %q, want %d characters", password, generatedPasswordLength)
		}
		for _, c := range password {
			if !strings.ContainsRune(generatedAlphabet, c) {
				t.Fatalf("generated %q, holding %q outside the alphabet", password, c)
			}
		}
		if !hasThreeClasses(password) {
			t.Fatalf("generated %q, without an uppercase letter, a lowercase letter and a digit", password)
		}
		seen[password] = true
	}
	if len(seen) < 2000 {
		t.Errorf("2000 draws gave %d distinct passwords", len(seen))
	}
}

func TestHasThreeClasses(t *testing.T) {
	cases := map[string]bool{
		"abcdefghABCDEFG1": true,
		"1aA":              true,
		"abcdefghABCDEFGH": false, // the password SQL Server 2022 refused
		"abcdefgh12345678": false,
		"ABCDEFGH12345678": false,
		"":                 false,
		"ÀÉ1aé":            false, // only ASCII counts, the alphabet being ASCII
		"ÀÉ1aB":            true,
	}
	for s, want := range cases {
		if got := hasThreeClasses(s); got != want {
			t.Errorf("hasThreeClasses(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestGenerateSecret_LettersAndDigitsOfTheLengthAsked(t *testing.T) {
	for _, length := range []int{1, 60} {
		secret := generateSecret(length)
		if len(secret) != length {
			t.Errorf("generateSecret(%d) = %q", length, secret)
		}
		if strings.Trim(secret, generatedAlphabet) != "" {
			t.Errorf("generateSecret(%d) = %q, outside the alphabet", length, secret)
		}
	}
	if first, second := generateSecret(60), generateSecret(60); first == second {
		t.Error("two 60-character secrets are equal")
	}
}
