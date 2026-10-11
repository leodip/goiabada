package phonecountries

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/countries"
	"github.com/stretchr/testify/assert"
)

func TestAll_CountAndUniqueness(t *testing.T) {
	pcs := All()
	if len(pcs) == 0 {
		t.Fatal("All() returned empty slice")
	}

	// One entry per (country, calling code). The datahub dataset gives every
	// country a single code except the Dominican Republic (3), so the total is
	// 250 - 1 + 3 = 252. (biter777 had many multi-code territories; datahub
	// collapses them — see the migration plan.)
	total := 0
	for _, c := range countries.All() {
		total += len(c.CallingCodes)
	}
	assert.Len(t, pcs, total, "one phone entry per (country, code)")
	assert.Len(t, pcs, 252, "expected 252 phone entries for the current dataset")

	seenId := map[string]bool{}
	seenName := map[string]bool{}
	for _, pc := range pcs {
		assert.Falsef(t, seenId[pc.UniqueId], "duplicate UniqueId %q", pc.UniqueId)
		seenId[pc.UniqueId] = true
		assert.Falsef(t, seenName[pc.Name], "duplicate Name %q", pc.Name)
		seenName[pc.Name] = true
	}
}

// TestAll_CallingCodeFormat asserts every calling code keeps the "+NN" form
// (countries stores digits without '+'; build must prepend it) and that the
// label embeds the same "+NN".
func TestAll_CallingCodeFormat(t *testing.T) {
	for _, pc := range All() {
		if !strings.HasPrefix(pc.CallingCode, "+") {
			t.Errorf("%s: CallingCode %q missing '+'", pc.UniqueId, pc.CallingCode)
			continue
		}
		if strings.HasPrefix(pc.CallingCode, "++") {
			t.Errorf("%s: CallingCode %q has a double '+'", pc.UniqueId, pc.CallingCode)
		}
		digits := strings.TrimPrefix(pc.CallingCode, "+")
		if digits == "" || strings.ContainsFunc(digits, func(r rune) bool { return r < '0' || r > '9' }) {
			t.Errorf("%s: CallingCode %q is not '+' followed by digits", pc.UniqueId, pc.CallingCode)
		}
		if !strings.Contains(pc.Name, pc.CallingCode) {
			t.Errorf("%s: Name %q does not embed CallingCode %q", pc.UniqueId, pc.Name, pc.CallingCode)
		}
	}
}

// TestByUniqueID_SpotChecks verifies specific entries by UniqueId (stable
// across CLDR name changes), covering the migration's calling-code changes and
// supplements.
func TestByUniqueID_SpotChecks(t *testing.T) {
	want := map[string]string{ // UniqueId -> CallingCode
		"BRA_0": "+55",
		"USA_0": "+1",
		"VAT_0": "+3906", // prefix-changed (biter777 had +3906698)
		"ABW_0": "+297",  // AW collapsed from two codes to one
		"XKX_0": "+383",  // Kosovo supplement
		"UMI_0": "+1",    // UM supplement
		"DOM_0": "+1809", // Dominican Republic has three codes
		"DOM_1": "+1829",
		"DOM_2": "+1849",
	}
	for id, code := range want {
		pc, ok := ByUniqueID(id)
		if !ok {
			t.Errorf("%s: missing", id)
			continue
		}
		assert.Equalf(t, id, pc.UniqueId, "%s unique id", id)
		assert.Equalf(t, code, pc.CallingCode, "%s calling code", id)
	}

	// Removed countries and collapsed second codes must NOT appear.
	for _, gone := range []string{"ANT_0", "YUG_0", "ABW_1", "JAM_1", "MYT_1", "PRI_1", "BES_1"} {
		if _, ok := ByUniqueID(gone); ok {
			t.Errorf("%s should not exist after migration", gone)
		}
	}
}

// TestAll_UniqueIdFormat checks the UniqueId is "<Alpha3>_<index>".
func TestAll_UniqueIdFormat(t *testing.T) {
	for _, pc := range All() {
		parts := strings.Split(pc.UniqueId, "_")
		if len(parts) != 2 || len(parts[0]) != 3 {
			t.Errorf("UniqueId %q not in <Alpha3>_<index> form", pc.UniqueId)
		}
	}
}

// TestAll_Isolation verifies All hands out a copy: a caller that edits and
// re-sorts its result changes neither the next All nor a lookup.
func TestAll_Isolation(t *testing.T) {
	first := All()
	for i := range first {
		first[i].CallingCode = "+999"
		first[i].UniqueId = "XXX_" + first[i].UniqueId
	}
	for i, j := 0, len(first)-1; i < j; i, j = i+1, j-1 {
		first[i], first[j] = first[j], first[i]
	}

	second := All()
	assert.Len(t, second, 252)
	assert.Equal(t, second, build(countries.All()), "All changed after a caller edited its copy")
	br, ok := ByUniqueID("BRA_0")
	if assert.True(t, ok, "BRA_0 found") {
		assert.Equal(t, "+55", br.CallingCode)
	}
}

// TestByUniqueID_EqualsScan holds the index to the list: every entry All
// returns is found by its UniqueId, field for field.
func TestByUniqueID_EqualsScan(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() returned no entries")
	}
	for _, want := range all {
		got, ok := ByUniqueID(want.UniqueId)
		if !ok {
			t.Errorf("ByUniqueID(%q) not found", want.UniqueId)
			continue
		}
		assert.Equalf(t, want, got, "ByUniqueID(%q)", want.UniqueId)
	}
}

// TestByUniqueID_Misses: the lookup is exact, as the scans it replaced were.
func TestByUniqueID_Misses(t *testing.T) {
	for _, id := range []string{"ZZZ_0", "", "bra_0", "BRA_9", "BRA", " BRA_0", "BR_0"} {
		t.Run(id, func(t *testing.T) {
			pc, ok := ByUniqueID(id)
			assert.False(t, ok)
			assert.Equal(t, PhoneCountry{}, pc)
		})
	}
}

// TestAll_Order pins the order the list has always rendered in: countries by
// name, byte-wise, then each country's codes in stored order.
func TestAll_Order(t *testing.T) {
	var want []string
	sorted := countries.All()
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].Name < sorted[j-1].Name; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	for _, c := range sorted {
		for _, code := range c.CallingCodes {
			want = append(want, c.Alpha2+" +"+code)
		}
	}

	var got []string
	for _, pc := range All() {
		got = append(got, pc.Alpha2+" "+pc.CallingCode)
	}
	assert.Equal(t, want, got)
	if assert.NotEmpty(t, got) {
		assert.Equal(t, "AF +93", got[0], "Afghanistan sorts first")
	}
}

// TestBuild_SixCodes: a country with more than five calling codes builds one
// entry per code. The v0.7 builder panicked above five, at request time (#432).
func TestBuild_SixCodes(t *testing.T) {
	codes := []string{"1", "2", "3", "4", "5", "6"}
	var got []PhoneCountry
	assert.NotPanics(t, func() {
		got = build([]countries.Country{{Name: "Six", Alpha2: "SX", Alpha3: "SIX", Emoji: "x", CallingCodes: codes}})
	})
	if assert.Len(t, got, 6) {
		for i, pc := range got {
			assert.Equal(t, "SIX_"+string(rune('0'+i)), pc.UniqueId)
			assert.Equal(t, "+"+codes[i], pc.CallingCode)
		}
	}
}
