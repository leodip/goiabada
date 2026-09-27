// Package locales is the vocabulary a user's locale is picked from: the OIDC `locale` claim, which
// OIDC Core 1.0 section 5.1 defines as a BCP 47 language tag.
//
// The table in data.go is maintained by hand; nothing generates it. Each Id is a BCP 47 tag and
// each Name its English display name. Four ids (sh, sh-BA, tl, tl-PH) are deprecated tags that
// canonicalize elsewhere; they stay because stored profiles may hold them, and a lookup matches
// the stored spelling exactly rather than canonicalizing it (#432).
package locales

import "slices"

// Locale is one entry a user may pick.
type Locale struct {
	// Id is the BCP 47 tag stored on the user and emitted as the locale claim, e.g. "pt-BR".
	Id string
	// Name is the English display name, e.g. "Portuguese (Brazil)". The picker's label puts the
	// native name in front of it (i18n.LocaleLabel).
	Name string
}

// byID indexes the table by Id. It is built once at package initialization; Go orders
// package-level initialization by dependency, so `locales` is populated first.
var byID = indexByID(locales)

func indexByID(list []Locale) map[string]Locale {
	index := make(map[string]Locale, len(list))
	for _, l := range list {
		index[l.Id] = l
	}
	return index
}

// All returns every locale in the order the picker renders them. It returns a fresh slice on
// every call, so callers may sort or otherwise mutate it without affecting the package's data or
// other callers.
func All() []Locale {
	return slices.Clone(locales)
}

// ByID looks up a locale by its Id. It returns the locale and true when found, or the zero
// Locale and false otherwise. The match is exact: case and separator are not normalized.
func ByID(id string) (Locale, bool) {
	l, ok := byID[id]
	return l, ok
}
