package render

import (
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// localeLabel renders the label shown in the locale picker for a BCP 47
// locale id (e.g. "pt-BR"), given its English name
// (locales.Locale.Name, e.g. "Portuguese (Brazil)").
//
// The result is "<native> (<english>)" so a user can recognize their
// language by either column even when the surrounding UI is in a language
// they can't read — the convention used by Wikipedia and GitHub language
// pickers. When CLDR has no endonym, or the endonym equals the English
// name (e.g. "English"), the English name is returned alone to avoid a
// redundant "English (English)".
//
// The label is viewer-independent: pt-BR always renders its native name in
// Portuguese regardless of the active UI locale, so no context is needed.
//
// It was core/i18n.LocaleLabel until #442: the admin console's locale picker is
// its one caller, and in core it put CLDR's display tables into the auth
// server's binary, which renders no locale picker.
func localeLabel(id, englishName string) string {
	native := nativeLocaleName(id)
	if native == "" || native == englishName {
		return englishName
	}
	return native + " (" + englishName + ")"
}

// nativeLocaleName returns the endonym for a locale id: the language's name
// written in that language, from CLDR (golang.org/x/text/language/display).
//
// display.Self renders a specialized endonym for some tags ("American
// English", "português europeu", "español latinoamericano", "简体中文");
// for those we take it as-is. For the common case where Self yields only
// the base-language name ("português" for pt-BR), we append the region
// endonym in the native language ("português (Brasil)") — but only when
// the region was explicit in the id, not inferred (so bare "pt" stays
// "português"). Returns "" when the id is unparseable or CLDR is silent.
func nativeLocaleName(id string) string {
	tag, err := language.Parse(id)
	if err != nil {
		return ""
	}
	name := display.Self.Name(tag)
	if name == "" {
		return ""
	}

	base, _ := tag.Base()
	if display.Self.Name(language.Make(base.String())) != name {
		// Self already folded the region/script into a specialized
		// endonym; appending a region would duplicate it.
		return name
	}

	region, conf := tag.Region()
	if conf != language.Exact {
		// Region was inferred, not written in the id — don't invent one.
		return name
	}
	if rn := display.Regions(tag).Name(region); rn != "" {
		return name + " (" + rn + ")"
	}
	return name
}
