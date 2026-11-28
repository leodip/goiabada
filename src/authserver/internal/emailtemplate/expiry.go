package emailtemplate

import (
	"strconv"
	"time"

	"github.com/leodip/goiabada/core/i18n"
)

// expiryUnit is a minute's and an hour's name for the counts of one plural category.
type expiryUnit struct{ minute, hour string }

// expiryNames are how one language writes {{expiry}}: join, what stands between the number and its
// unit's name, and the unit's names for each plural category, keyed as i18n.PluralCategory names it.
type expiryNames struct {
	join  string
	units map[string]expiryUnit
}

// expiryLanguages are a minute's and an hour's names in each built-in language, one per CLDR cardinal
// category the language's whole counts reach (#665 decision 2), so the rule for which name a count
// takes is the catalogs' rule, with how the language joins a number to its unit beside them (#663
// decision 4): a space in each of these languages but Simplified Chinese, Japanese's too, since every
// number takes one before Japanese (#662 decision 6). Polish's names are in the accusative, the case its expiry
// sentences take ("Link wygaśnie za 5 minut.", "Link jest ważny przez 24 godziny."), as an
// administrator's sentence is likelier to run (#665 decision 3). Russian's are in the accusative too
// ("Срок действия ссылки истечет через 21 минуту.", "Ссылка действует 24 часа."): one for 1 and 21,
// few for 2 to 4 and 22 to 24, many for 0 and 5 to 20 (#666 decision 5). Japanese has one name per
// unit, other: "30 分", "24 時間". So has Simplified Chinese, which joins the number to its unit with
// no space, as it writes a number with its measure word: "30分钟", "24小时" (#663 decision 4).
var expiryLanguages = map[string]expiryNames{
	"en":      {" ", map[string]expiryUnit{"one": {"minute", "hour"}, "other": {"minutes", "hours"}}},
	"de":      {" ", map[string]expiryUnit{"one": {"Minute", "Stunde"}, "other": {"Minuten", "Stunden"}}},
	"es":      {" ", map[string]expiryUnit{"one": {"minuto", "hora"}, "other": {"minutos", "horas"}}},
	"fr":      {" ", map[string]expiryUnit{"one": {"minute", "heure"}, "other": {"minutes", "heures"}}},
	"id":      {" ", map[string]expiryUnit{"other": {"menit", "jam"}}},
	"it":      {" ", map[string]expiryUnit{"one": {"minuto", "ora"}, "other": {"minuti", "ore"}}},
	"ja":      {" ", map[string]expiryUnit{"other": {"分", "時間"}}},
	"pl":      {" ", map[string]expiryUnit{"one": {"minutę", "godzinę"}, "few": {"minuty", "godziny"}, "many": {"minut", "godzin"}}},
	"pt-BR":   {" ", map[string]expiryUnit{"one": {"minuto", "hora"}, "other": {"minutos", "horas"}}},
	"ru":      {" ", map[string]expiryUnit{"one": {"минуту", "час"}, "few": {"минуты", "часа"}, "many": {"минут", "часов"}}},
	"zh-Hans": {"", map[string]expiryUnit{"other": {"分钟", "小时"}}},
}

// expiryIn writes a lifetime as {{expiry}} reads it (#818 decision 4): a number with its unit in
// lang, in hours when it is a whole number of them and in minutes, rounded up, otherwise, so a
// release that changes a lifetime changes every text that names it. The unit's name is the one of
// the count's plural category in lang, joined to the number as lang's entry says; a language with no
// names reads English's, by English's rule.
func expiryIn(lang string, lifetime time.Duration) string {
	names, ok := expiryLanguages[lang]
	if !ok {
		lang, names = "en", expiryLanguages["en"]
	}
	if lifetime >= time.Hour && lifetime%time.Hour == 0 {
		hours := int(lifetime / time.Hour)
		return strconv.Itoa(hours) + names.join + unitOf(names.units, lang, hours).hour
	}
	minutes := int((lifetime + time.Minute - 1) / time.Minute)
	return strconv.Itoa(minutes) + names.join + unitOf(names.units, lang, minutes).minute
}

// unitOf answers the names of count's plural category in lang among units, which name every
// category lang's whole counts reach.
func unitOf(units map[string]expiryUnit, lang string, count int) expiryUnit {
	return units[i18n.PluralCategory(lang, count)]
}
