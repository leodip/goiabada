package phonecountries

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/countries"
	"github.com/stretchr/testify/assert"
)

func TestGet_CountAndUniqueness(t *testing.T) {
	pcs := Get()
	if len(pcs) == 0 {
		t.Fatal("Get() returned empty slice")
	}

	// One entry per (country, calling code). The datahub dataset gives every
	// country a single code except the Dominican Republic (3), so the total is
	// 250 - 1 + 3 = 252. (biter777 had many multi-code territories; datahub
	// collapses them — see the migration plan.)
	total := 0
	for _, c := range countries.AllInfo() {
		total += len(c.CallingCodes)
	}
	assert.Equal(t, total, len(pcs), "one phone entry per (country, code)")
	assert.Equal(t, 252, len(pcs), "expected 252 phone entries for the current dataset")

	seenId := map[string]bool{}
	seenName := map[string]bool{}
	for _, pc := range pcs {
		assert.Falsef(t, seenId[pc.UniqueId], "duplicate UniqueId %q", pc.UniqueId)
		seenId[pc.UniqueId] = true
		assert.Falsef(t, seenName[pc.Name], "duplicate Name %q", pc.Name)
		seenName[pc.Name] = true
	}
}

// TestGet_CallingCodeFormat asserts every calling code keeps the "+NN" form
// (countries stores digits without '+'; Get must prepend it) and that the label
// embeds the same "+NN".
func TestGet_CallingCodeFormat(t *testing.T) {
	for _, pc := range Get() {
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

// TestGet_SpotChecks verifies specific entries by UniqueId (stable across CLDR
// name changes), covering the migration's calling-code changes and supplements.
func TestGet_SpotChecks(t *testing.T) {
	byId := map[string]PhoneCountry{}
	for _, pc := range Get() {
		byId[pc.UniqueId] = pc
	}

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
		pc, ok := byId[id]
		if !ok {
			t.Errorf("%s: missing", id)
			continue
		}
		assert.Equalf(t, code, pc.CallingCode, "%s calling code", id)
	}

	// Removed countries and collapsed second codes must NOT appear.
	for _, gone := range []string{"ANT_0", "YUG_0", "ABW_1", "JAM_1", "MYT_1", "PRI_1", "BES_1"} {
		if _, ok := byId[gone]; ok {
			t.Errorf("%s should not exist after migration", gone)
		}
	}
}

// TestGet_UniqueIdFormat checks the UniqueId is "<Alpha3>_<index>".
func TestGet_UniqueIdFormat(t *testing.T) {
	for _, pc := range Get() {
		parts := strings.Split(pc.UniqueId, "_")
		if len(parts) != 2 || len(parts[0]) != 3 {
			t.Errorf("UniqueId %q not in <Alpha3>_<index> form", pc.UniqueId)
		}
	}
}
