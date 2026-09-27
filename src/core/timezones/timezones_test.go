package timezones

import (
	"slices"
	"testing"
	"time"
	// The binaries import the same fallback, so a zone loads here exactly when it loads there,
	// whatever zoneinfo the machine running the test has (#432).
	_ "time/tzdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAll_Count pins the table's size at the pinned release, so a row lost in a regeneration
// shows here rather than as a user whose stored zone the validator stops accepting.
func TestAll_Count(t *testing.T) {
	assert.Len(t, All(), 423)
}

func TestAll_SpotChecks(t *testing.T) {
	all := All()
	for _, want := range []Zone{
		{CountryCode: "BR", Zone: "America/Sao_Paulo", CountryName: "Brazil", Comments: "Brazil (southeast: GO, DF, MG, ES, RJ, SP, PR, SC, RS)"},
		{CountryCode: "DE", Zone: "Europe/Berlin", CountryName: "Germany", Comments: "most of Germany"},
		{CountryCode: "SE", Zone: "Europe/Berlin", CountryName: "Sweden", Comments: "most of Germany"},
		{CountryCode: "US", Zone: "America/New_York", CountryName: "United States", Comments: "Eastern (most areas)"},
	} {
		t.Run(want.CountryName+"/"+want.Zone, func(t *testing.T) {
			assert.Contains(t, all, want)
		})
	}
}

// TestAll_EveryZoneLoads is what replaced the load both servers ran at startup: a zone the
// runtime cannot load fails here, not at a server's start (#49, #432).
func TestAll_EveryZoneLoads(t *testing.T) {
	all := All()
	require.NotEmpty(t, all)
	for _, z := range all {
		if _, err := time.LoadLocation(z.Zone); err != nil {
			t.Errorf("zone %q (%s) does not load: %v", z.Zone, z.CountryName, err)
		}
	}
}

// The (country name, zone) pair is what a profile stores and the picker selects by, so it must
// name one row; (country code, zone) is the same row by code.
func TestAll_PairsAreUnique(t *testing.T) {
	byName := map[[2]string]bool{}
	byCode := map[[2]string]bool{}
	for _, z := range All() {
		name := [2]string{z.CountryName, z.Zone}
		code := [2]string{z.CountryCode, z.Zone}
		if byName[name] {
			t.Errorf("duplicate (CountryName, Zone) %v", name)
		}
		if byCode[code] {
			t.Errorf("duplicate (CountryCode, Zone) %v", code)
		}
		byName[name] = true
		byCode[code] = true
	}
}

func TestAll_SortedByCountryNameThenZone(t *testing.T) {
	all := All()
	for i := 1; i < len(all); i++ {
		prev, cur := all[i-1], all[i]
		if prev.CountryName > cur.CountryName || (prev.CountryName == cur.CountryName && prev.Zone >= cur.Zone) {
			t.Errorf("row %d (%s, %s) sorts before row %d (%s, %s)", i, cur.CountryName, cur.Zone, i-1, prev.CountryName, prev.Zone)
		}
	}
}

func TestAll_Fields(t *testing.T) {
	for i, z := range All() {
		if len(z.CountryCode) != 2 || z.CountryCode[0] < 'A' || z.CountryCode[0] > 'Z' || z.CountryCode[1] < 'A' || z.CountryCode[1] > 'Z' {
			t.Errorf("row %d: CountryCode %q is not two upper-case letters", i, z.CountryCode)
		}
		if z.Zone == "" {
			t.Errorf("row %d (%s): empty Zone", i, z.CountryCode)
		}
		if z.CountryName == "" {
			t.Errorf("row %d (%s): empty CountryName", i, z.CountryCode)
		}
	}
}

func TestAll_Isolation(t *testing.T) {
	first := All()
	want := first[0]
	first[0].CountryName = "mutated"
	slices.Reverse(first)

	second := All()
	assert.Equal(t, want, second[0])
	assert.NotEqual(t, first[0], second[0])
}

// TestByZone_EqualsFilter: for every zone ID, the lookup returns exactly the rows a filter of All
// would find, in table order.
func TestByZone_EqualsFilter(t *testing.T) {
	all := All()
	require.NotEmpty(t, all)
	shared := 0
	for _, id := range zoneIDs(all) {
		var want []Zone
		for _, z := range all {
			if z.Zone == id {
				want = append(want, z)
			}
		}
		if len(want) > 1 {
			shared++
		}
		assert.Equalf(t, want, ByZone(id), "ByZone(%q)", id)
	}
	// 34 of the 312 zone IDs are listed under more than one country at 2026c; the lookup must
	// answer every row for those, which a first-match lookup would not.
	assert.Equal(t, 34, shared, "zone IDs listed under more than one country")
}

// TestByZone_Misses: the lookup is exact, as the scan it replaced was.
func TestByZone_Misses(t *testing.T) {
	for _, id := range []string{"Not/AZone", "", "america/sao_paulo", "America/Sao_Paulo ", "Sao_Paulo"} {
		t.Run(id, func(t *testing.T) {
			assert.Nil(t, ByZone(id))
		})
	}
}

func TestByZone_Isolation(t *testing.T) {
	rows := ByZone("Europe/Berlin")
	require.Greater(t, len(rows), 1)
	want := rows[0]
	rows[0].CountryName = "mutated"
	slices.Reverse(rows)

	again := ByZone("Europe/Berlin")
	assert.Equal(t, want, again[0])
	assert.Equal(t, want, All()[slices.IndexFunc(All(), func(z Zone) bool { return z.Zone == "Europe/Berlin" })])
}

func zoneIDs(all []Zone) []string {
	var ids []string
	seen := map[string]bool{}
	for _, z := range all {
		if !seen[z.Zone] {
			seen[z.Zone] = true
			ids = append(ids, z.Zone)
		}
	}
	return ids
}
