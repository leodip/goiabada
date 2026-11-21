package emailtemplate

import (
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/i18n"
)

// expiryUnit is a minute's and an hour's name for the counts of one plural category.
type expiryUnit struct{ minute, hour string }

// expiryUnits are a minute's and an hour's names in each built-in language, one per CLDR cardinal
// category the language's whole counts reach, keyed as i18n.PluralCategory names it (#665
// decision 2), so the rule for which name a count takes is the catalogs' rule. Polish's names are in
// the accusative, the case its expiry sentences take ("Link wygaśnie za 5 minut.", "Link jest ważny
// przez 24 godziny."), as an administrator's sentence is likelier to run (#665 decision 3).
var expiryUnits = map[string]map[string]expiryUnit{
	"en":    {"one": {"minute", "hour"}, "other": {"minutes", "hours"}},
	"de":    {"one": {"Minute", "Stunde"}, "other": {"Minuten", "Stunden"}},
	"es":    {"one": {"minuto", "hora"}, "other": {"minutos", "horas"}},
	"fr":    {"one": {"minute", "heure"}, "other": {"minutes", "heures"}},
	"id":    {"other": {"menit", "jam"}},
	"it":    {"one": {"minuto", "ora"}, "other": {"minuti", "ore"}},
	"pl":    {"one": {"minutę", "godzinę"}, "few": {"minuty", "godziny"}, "many": {"minut", "godzin"}},
	"pt-BR": {"one": {"minuto", "hora"}, "other": {"minutos", "horas"}},
}

// expiryIn writes a lifetime as {{expiry}} reads it (#818 decision 4): a number with its unit in
// lang, in hours when it is a whole number of them and in minutes, rounded up, otherwise, so a
// release that changes a lifetime changes every text that names it. The unit's name is the one of
// the count's plural category in lang; a language with no names reads English's, by English's rule.
func expiryIn(lang string, lifetime time.Duration) string {
	units, ok := expiryUnits[lang]
	if !ok {
		lang, units = "en", expiryUnits["en"]
	}
	if lifetime >= time.Hour && lifetime%time.Hour == 0 {
		hours := int(lifetime / time.Hour)
		return strconv.Itoa(hours) + " " + unitOf(units, lang, hours).hour
	}
	minutes := int((lifetime + time.Minute - 1) / time.Minute)
	return strconv.Itoa(minutes) + " " + unitOf(units, lang, minutes).minute
}

// unitOf answers the names of count's plural category in lang among units, which name every
// category lang's whole counts reach.
func unitOf(units map[string]expiryUnit, lang string, count int) expiryUnit {
	return units[i18n.PluralCategory(lang, count)]
}
