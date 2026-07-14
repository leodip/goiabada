package countries

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func findByA2(list []Country, a2 string) (Country, bool) {
	for _, c := range list {
		if c.Alpha2 == a2 {
			return c, true
		}
	}
	return Country{}, false
}

// TestAllInfo_Isolation verifies AllInfo returns a fresh outer slice with copied
// CallingCodes, so a caller that sorts/mutates one result cannot affect another.
func TestAllInfo_Isolation(t *testing.T) {
	first := AllInfo()
	for i := range first {
		if first[i].Alpha2 == "BR" {
			first[i].CallingCodes[0] = "999" // mutate inner slice
		}
	}
	sort.Slice(first, func(i, j int) bool { return first[i].Name > first[j].Name }) // mutate order

	second := AllInfo()
	br, ok := findByA2(second, "BR")
	if !ok {
		t.Fatal("BR missing from second AllInfo()")
	}
	if !reflect.DeepEqual(br.CallingCodes, []string{"55"}) {
		t.Errorf("AllInfo not isolated: BR.CallingCodes = %v, want [55]", br.CallingCodes)
	}
	// second must still be in alpha-2 order (unaffected by first's re-sort).
	for i := 1; i < len(second); i++ {
		if second[i-1].Alpha2 > second[i].Alpha2 {
			t.Fatalf("AllInfo order corrupted at %d: %q > %q", i, second[i-1].Alpha2, second[i].Alpha2)
		}
	}
}

// TestByAlpha2_Isolation verifies the returned CallingCodes is a copy.
func TestByAlpha2_Isolation(t *testing.T) {
	c1, ok := ByAlpha2("BR")
	if !ok {
		t.Fatal("BR not found")
	}
	c1.CallingCodes[0] = "999"
	c2, _ := ByAlpha2("BR")
	if c2.CallingCodes[0] != "55" {
		t.Errorf("ByAlpha2 not isolated: BR.CallingCodes[0] = %q, want 55", c2.CallingCodes[0])
	}
}

// TestByAlpha2_NotFound covers absent codes and case-sensitivity.
func TestByAlpha2_NotFound(t *testing.T) {
	for _, code := range []string{"AN", "YU", "ZZ", "", "br", "xk", "USA"} {
		if c, ok := ByAlpha2(code); ok {
			t.Errorf("ByAlpha2(%q) = (%v, true), want not found", code, c)
		}
	}
}

// TestDatasetCallingCodes asserts the exact post-migration calling codes for the
// 17 changed countries plus the XK/UM supplements and a couple of controls.
// These are dataset-DIFFERENCE tests: they intentionally encode the new
// (breaking) values, not backward compatibility with biter777.
func TestDatasetCallingCodes(t *testing.T) {
	want := map[string][]string{
		// The 17 changed countries (new datahub values).
		"AW": {"297"}, "AX": {"358"}, "BQ": {"599"}, "CC": {"61"}, "CW": {"599"},
		"CX": {"61"}, "GG": {"44"}, "HM": {"672"}, "IM": {"44"}, "JE": {"44"},
		"JM": {"1876"}, "PN": {"870"}, "PR": {"1"}, "SJ": {"47"}, "TF": {"262"},
		"VA": {"3906"}, "YT": {"262"},
		// Supplements.
		"XK": {"383"}, "UM": {"1"},
		// Controls (unchanged).
		"BR": {"55"}, "US": {"1"},
	}
	for a2, codes := range want {
		c, ok := ByAlpha2(a2)
		if !ok {
			t.Errorf("%s: missing", a2)
			continue
		}
		if !reflect.DeepEqual(c.CallingCodes, codes) {
			t.Errorf("%s: CallingCodes = %v, want %v", a2, c.CallingCodes, codes)
		}
	}
}

// TestSupplements checks the supplemented entries' full shape.
func TestSupplements(t *testing.T) {
	xk, ok := ByAlpha2("XK")
	if !ok {
		t.Fatal("XK missing")
	}
	if xk.Alpha3 != "XKX" || xk.Name != "Kosovo" || xk.Emoji != "🇽🇰" {
		t.Errorf("XK = %+v, want alpha3=XKX name=Kosovo emoji=🇽🇰", xk)
	}
	um, ok := ByAlpha2("UM")
	if !ok {
		t.Fatal("UM missing")
	}
	if um.Alpha3 != "UMI" || !reflect.DeepEqual(um.CallingCodes, []string{"1"}) {
		t.Errorf("UM = %+v, want alpha3=UMI codes=[1]", um)
	}
}

// TestRemovedCountriesAbsent verifies AN/YU (and their alpha-3) are gone.
func TestRemovedCountriesAbsent(t *testing.T) {
	for _, a2 := range []string{"AN", "YU"} {
		if _, ok := ByAlpha2(a2); ok {
			t.Errorf("alpha-2 %s should be absent", a2)
		}
	}
	for _, c := range AllInfo() {
		if c.Alpha3 == "ANT" || c.Alpha3 == "YUG" {
			t.Errorf("alpha-3 %s should be absent", c.Alpha3)
		}
	}
}

// TestCallingCodesHaveNoPlus asserts codes are stored as digits without '+'.
func TestCallingCodesHaveNoPlus(t *testing.T) {
	for _, c := range AllInfo() {
		for _, code := range c.CallingCodes {
			if strings.ContainsAny(code, "+ -") {
				t.Errorf("%s: calling code %q must be digits only", c.Alpha2, code)
			}
			for _, r := range code {
				if r < '0' || r > '9' {
					t.Errorf("%s: calling code %q has non-digit %q", c.Alpha2, code, r)
				}
			}
		}
	}
}

// TestDatasetIntegrity checks the whole dataset's structural invariants.
func TestDatasetIntegrity(t *testing.T) {
	all := AllInfo()
	if len(all) != 250 {
		t.Errorf("dataset size = %d, want 250", len(all))
	}
	seen2 := map[string]bool{}
	seen3 := map[string]bool{}
	for _, c := range all {
		if !isUpperN(c.Alpha2, 2) {
			t.Errorf("%q: invalid alpha-2", c.Alpha2)
		}
		if !isUpperN(c.Alpha3, 3) {
			t.Errorf("%q (%s): invalid alpha-3", c.Alpha3, c.Alpha2)
		}
		if seen2[c.Alpha2] {
			t.Errorf("duplicate alpha-2 %q", c.Alpha2)
		}
		if seen3[c.Alpha3] {
			t.Errorf("duplicate alpha-3 %q", c.Alpha3)
		}
		seen2[c.Alpha2] = true
		seen3[c.Alpha3] = true
		if c.Name == "" {
			t.Errorf("%s: empty name", c.Alpha2)
		}
		if len(c.CallingCodes) == 0 {
			t.Errorf("%s: empty calling codes", c.Alpha2)
		}
		if c.Emoji == "" {
			t.Errorf("%s: empty emoji", c.Alpha2)
		}
	}
}

func isUpperN(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}
