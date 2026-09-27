package locales

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

func TestAll_SpotChecks(t *testing.T) {
	all := All()
	for id, name := range map[string]string{
		"en":    "English",
		"es":    "Spanish",
		"fr":    "French",
		"zh-CN": "Chinese (China)",
		"pt-BR": "Portuguese (Brazil)",
	} {
		t.Run(id, func(t *testing.T) {
			assert.Contains(t, all, Locale{Id: id, Name: name})
		})
	}
}

// TestAll_Count pins the table's size, so a row lost in an edit shows here rather than as a
// user whose stored locale the validator stops accepting.
func TestAll_Count(t *testing.T) {
	assert.Len(t, All(), 563)
}

func TestAll_UniqueIds(t *testing.T) {
	seen := make(map[string]bool)
	for _, l := range All() {
		if seen[l.Id] {
			t.Errorf("duplicate Id %q", l.Id)
		}
		seen[l.Id] = true
	}
}

func TestAll_NonEmptyFields(t *testing.T) {
	for i, l := range All() {
		if l.Id == "" {
			t.Errorf("entry %d has an empty Id", i)
		}
		if l.Name == "" {
			t.Errorf("entry %d (%q) has an empty Name", i, l.Id)
		}
	}
}

// TestAll_ParseAsBCP47 holds every Id to being a well-formed BCP 47 tag, which is what the OIDC
// locale claim carries (OIDC Core 1.0 section 5.1). It also pins which ids are deprecated: those
// four canonicalize to another tag and stay only because stored profiles may hold them, so a new
// deprecated id is a finding rather than something to add here.
func TestAll_ParseAsBCP47(t *testing.T) {
	var deprecated []string
	for _, l := range All() {
		tag, err := language.Parse(l.Id)
		if err != nil {
			t.Errorf("Id %q is not a BCP 47 tag: %v", l.Id, err)
			continue
		}
		if tag.String() != l.Id {
			deprecated = append(deprecated, l.Id)
		}
	}
	assert.ElementsMatch(t, []string{"sh", "sh-BA", "tl", "tl-PH"}, deprecated)
}

func TestAll_Isolation(t *testing.T) {
	first := All()
	first[0].Name = "mutated"
	slices.Reverse(first)

	second := All()
	assert.Equal(t, Locale{Id: "af", Name: "Afrikaans"}, second[0])
	assert.NotEqual(t, first[0], second[0])
}

// TestByID_EqualsScan: for every entry, the lookup returns what a scan of All would find.
func TestByID_EqualsScan(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() returned no locales")
	}
	for _, want := range all {
		got, ok := ByID(want.Id)
		if !ok {
			t.Errorf("ByID(%q) not found", want.Id)
			continue
		}
		assert.Equalf(t, want, got, "ByID(%q)", want.Id)
	}
}

// TestByID_Misses: the lookup is exact, as the scan it replaced was. "fil" is what the stored "tl"
// canonicalizes to, and is not in the table: nothing canonicalizes on the way in.
func TestByID_Misses(t *testing.T) {
	for _, id := range []string{"xx-XX", "", "PT-BR", "pt-br", "pt_BR", " pt-BR", "fil"} {
		t.Run(id, func(t *testing.T) {
			l, ok := ByID(id)
			assert.False(t, ok)
			assert.Equal(t, Locale{}, l)
		})
	}
}

func TestByID_Isolation(t *testing.T) {
	l, ok := ByID("pt-BR")
	if !ok {
		t.Fatal("pt-BR not found")
	}
	l.Name = "mutated"

	again, _ := ByID("pt-BR")
	assert.Equal(t, "Portuguese (Brazil)", again.Name)
}
