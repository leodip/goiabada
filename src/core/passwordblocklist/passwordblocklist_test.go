package passwordblocklist

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The listed passwords here were read off the union the agreement measured, not off the generated
// file, so a regeneration that lost them fails (#550 decision 5).
func TestIsCommon_RefusesAListedPasswordWhateverItsCase(t *testing.T) {
	for _, password := range []string{
		"passwordpassword",
		"PasswordPassword",
		"PASSWORDPASSWORD",
		"1qaz2wsx3edc4rfv",
		"QwertyuiopASDFGHJKL",
		"iloveyouiloveyou",
		"passwordpasswor",
	} {
		t.Run(password, func(t *testing.T) {
			assert.True(t, IsCommon(password))
		})
	}
}

// NIST SP 800-63B-4 section 3.1.1.2: "The entire password SHALL be subject to comparison, not
// substrings or words that might be contained therein". A password containing a listed one, or a
// listed one with a character added, is a different password.
func TestIsCommon_ComparesTheWholePassword(t *testing.T) {
	for name, password := range map[string]string{
		"a passphrase containing a listed password": "my passwordpassword is long",
		"a listed password with a character added":  "passwordpasswordx",
		"a listed password with a digit added":      "passwordpassword1",
		"a listed password with a space before it":  " passwordpassword",
		"a listed password's first 14 characters":   "passwordpasswo",
		"a listed password's last characters":       "asswordpassword",
		"empty":                                     "",
		"two listed passwords on two lines":         "olamilekan20001\noldschoolkilla68",
		"a listed password and a newline":           "passwordpassword\n",
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, IsCommon(password))
		})
	}
}

// The examples are decision 6's own: the email jane.doe@example.com, its local part, the username
// janedoe and the app name Goiabada.
var janeDoesWords = []string{"jane.doe@example.com", "jane.doe", "janedoe", "Goiabada"}

func TestIsTooClose_RefusesTheWordsAndTheirSimpleDerivatives(t *testing.T) {
	for name, password := range map[string]string{
		"the email address":                       "jane.doe@example.com",
		"the email address in capitals":           "JANE.DOE@EXAMPLE.COM",
		"the email address with a year after it":  "jane.doe@example.com2026",
		"the local part padded with a year":       "jane.doe2026!!!!!!",
		"the app name padded with a year":         "goiabada2026!!!!!",
		"the app name repeated":                   "goiabadagoiabada",
		"the app name repeated three times":       "GoiabadaGoiabadaGoiabada",
		"the username repeated and padded":        "JaneDoeJaneDoe2026",
		"the app name padded on both ends":        "!!2026goiabadagoiabada2026!!",
		"the app name between spaces and digits":  "  1 goiabada 2  ",
		"the local part repeated":                 "jane.doejane.doe",
		"the username in mixed case and repeated": "jAnEdOeJaNeDoE",
	} {
		t.Run(name, func(t *testing.T) {
			assert.True(t, IsTooClose(password, janeDoesWords...))
		})
	}
}

func TestIsTooClose_AcceptsAPassphraseThatMerelyContainsAWord(t *testing.T) {
	for name, password := range map[string]string{
		"a passphrase naming the user and the app":  "jane doe likes goiabada jam",
		"the app name repeated with a letter added": "goiabadagoiabadax",
		"the app name with a letter inside":         "goiabadaxgoiabada",
		"the app name and the username":             "goiabadajanedoe",
		"a year padded with the app name inside":    "2026goiabada2026goiabada",
		"unrelated words":                           "correct horse battery staple",
		"digits alone":                              "123456789012345",
		"symbols alone":                             "!!!!!!!!!!!!!!!!",
		"empty":                                     "",
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, IsTooClose(password, janeDoesWords...))
		})
	}
}

// A word is compared lowercased and with its own digits and symbols trimmed too, so a username
// ending in digits still catches the password that is it, padded.
func TestIsTooClose_ReadsTheWordsAsThePasswordIsRead(t *testing.T) {
	cases := []struct {
		name     string
		password string
		words    []string
	}{
		{"a word in capitals", "goiabadagoiabada", []string{"GOIABADA"}},
		{"a username ending in digits, padded", "jdoe99!!!!!!!!!!", []string{"jdoe99"}},
		{"a username ending in digits, repeated", "jdoe99jdoe99jdoe99", []string{"jdoe99"}},
		{"a username starting with digits, padded", "99jdoe!!!!!!!!!!", []string{"99jdoe"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.True(t, IsTooClose(c.password, c.words...))
		})
	}
}

// An empty word, or one with no letter in it, is not a word every password repeats.
func TestIsTooClose_AWordWithNothingInItRefusesNothing(t *testing.T) {
	for name, words := range map[string][]string{
		"no words":       nil,
		"an empty word":  {""},
		"symbols alone":  {"!!!"},
		"digits alone":   {"2026"},
		"spaces alone":   {"   "},
		"a word and two": {"", "!!!", "goiabada"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, IsTooClose("correct horse battery staple", words...))
		})
	}
	assert.True(t, IsTooClose("2026202620262026", "2026"), "a word of digits is still the word itself, repeated")
}

// The committed list, held to what the generator promises of it (#550 decisions 4 and 5): the 16,051
// entries of the three sources that the nist policy could otherwise accept, each lowercase, unique,
// sorted, at least 15 characters and at most bcrypt's 72 bytes.
func TestList_HoldsItsInvariants(t *testing.T) {
	require.True(t, strings.HasPrefix(list, "\n"), "the list opens with the newline every entry is matched after")
	require.True(t, strings.HasSuffix(list, "\n"), "the list closes with the newline every entry is matched before")
	entries := strings.Split(strings.Trim(list, "\n"), "\n")

	assert.Len(t, entries, 16051)
	seen := make(map[string]bool, len(entries))
	for i, e := range entries {
		require.NotEmpty(t, e, "entry %d", i)
		assert.True(t, utf8.ValidString(e), "entry %d is not UTF-8: %q", i, e)
		assert.Equal(t, strings.ToLower(e), e, "entry %d is not lowercase", i)
		assert.GreaterOrEqual(t, utf8.RuneCountInString(e), 15, "entry %d is under 15 characters: %q", i, e)
		assert.LessOrEqual(t, len(e), 72, "entry %d is over 72 bytes: %q", i, e)
		assert.False(t, seen[e], "entry %d is a duplicate: %q", i, e)
		seen[e] = true
		if i > 0 {
			assert.Less(t, entries[i-1], e, "entry %d is out of order", i)
		}
	}
}

// Every entry is refused by IsCommon, so nothing in how the list is held hides one from the check.
func TestList_EveryEntryIsCommon(t *testing.T) {
	entries := strings.Split(strings.Trim(list, "\n"), "\n")
	require.NotEmpty(t, entries)
	for _, e := range entries {
		if !IsCommon(e) {
			t.Errorf("IsCommon(%q) = false for a listed entry", e)
		}
	}
}
