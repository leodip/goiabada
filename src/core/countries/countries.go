// Package countries provides self-maintained ISO 3166-1 country reference data
// (names, alpha-2/alpha-3 codes, flag emoji, and ITU-T E.164 calling codes).
//
// The data lives in data_generated.go, which is regenerated from the datahub
// `datasets/country-codes` dataset by generate/main.go (see that file, or run
// `version-manager.sh generate countries`). This package intentionally has no
// third-party dependencies (#272).
package countries

// Country holds ISO 3166-1 reference data for a single country/territory.
//
// CallingCodes are ITU-T E.164 country calling codes as DIGITS WITHOUT the
// leading '+' (a country may have zero, one, or several). Renderers and
// persisters prepend '+' themselves — see phonecountries.All(), which lives in
// the auth server now (src/authserver/internal/phonecountries).
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
// built once at package initialization from the generated slice; Go orders
// package-level initialization by dependency, so `countries` is populated first.
var byAlpha2 = indexByAlpha2(countries)

func indexByAlpha2(list []Country) map[string]Country {
	index := make(map[string]Country, len(list))
	for _, c := range list {
		index[c.Alpha2] = c
	}
	return index
}

// All returns every country, in alpha-2 order. It returns a FRESH outer slice on every call,
// and each returned Country's CallingCodes is a copy, so callers may sort or
// otherwise mutate the result in place without affecting the package's data or
// other callers.
func All() []Country {
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
