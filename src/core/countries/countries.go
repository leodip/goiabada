// Package countries provides self-maintained ISO 3166-1 country reference data
// (names, alpha-2/alpha-3 codes, flag emoji, and ITU-T E.164 calling codes).
//
// The data lives in data_generated.go, which is regenerated from the datahub
// `datasets/country-codes` dataset by generate/main.go (see that file, or run
// `version-manager.sh generate countries`). This package intentionally has no
// third-party dependencies — it replaced github.com/biter777/countries.
package countries

// Country holds ISO 3166-1 reference data for a single country/territory.
//
// CallingCodes are ITU-T E.164 country calling codes as DIGITS WITHOUT the
// leading '+' (a country may have zero, one, or several). Renderers and
// persisters prepend '+' themselves — see phonecountries.Get().
type Country struct {
	// Name is the CLDR (en) display name. It is a rarely-shown display
	// fallback but is also the sort key used by callers.
	Name string
	// Alpha2 is the upper-case ISO 3166-1 alpha-2 code, e.g. "BR".
	Alpha2 string
	// Alpha3 is the upper-case ISO 3166-1 alpha-3 code, e.g. "BRA".
	Alpha3 string
	// Emoji is the flag emoji derived from Alpha2.
	Emoji string
	// CallingCodes are E.164 calling codes as digits only, without '+'.
	CallingCodes []string
}

// byAlpha2 indexes the generated data by alpha-2 code for O(1) lookup. It is
// built once at package initialization from the generated slice (package-level
// variables are initialized before init runs, so `countries` is populated).
var byAlpha2 map[string]Country

func init() {
	byAlpha2 = make(map[string]Country, len(countries))
	for _, c := range countries {
		byAlpha2[c.Alpha2] = c
	}
}

// AllInfo returns every country. It returns a FRESH outer slice on every call,
// and each returned Country's CallingCodes is a copy, so callers may sort or
// otherwise mutate the result in place without affecting the package's data or
// other callers.
func AllInfo() []Country {
	out := make([]Country, len(countries))
	for i, c := range countries {
		out[i] = c
		out[i].CallingCodes = cloneCodes(c.CallingCodes)
	}
	return out
}

// ByAlpha2 looks up a country by its upper-case ISO 3166-1 alpha-2 code. It
// returns the country and true when found, or the zero Country and false
// otherwise. Lookup is case-sensitive (upper-case only). The returned
// Country's CallingCodes is a copy, so callers cannot mutate the package's
// data through it.
func ByAlpha2(code string) (Country, bool) {
	c, ok := byAlpha2[code]
	if !ok {
		return Country{}, false
	}
	c.CallingCodes = cloneCodes(c.CallingCodes)
	return c, true
}

// cloneCodes returns an independent copy of a calling-code slice. It preserves
// nil-ness (a nil input yields a nil output) so copies compare equal to their
// source.
func cloneCodes(codes []string) []string {
	if codes == nil {
		return nil
	}
	return append([]string(nil), codes...)
}
