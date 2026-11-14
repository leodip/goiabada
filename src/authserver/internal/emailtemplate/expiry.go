package emailtemplate

import (
	"strconv"
	"time"
)

// durationUnits are a minute's and an hour's names, singular then plural, in each built-in
// language.
var durationUnits = map[string]struct{ minute, minutes, hour, hours string }{
	"en":    {"minute", "minutes", "hour", "hours"},
	"de":    {"Minute", "Minuten", "Stunde", "Stunden"},
	"es":    {"minuto", "minutos", "hora", "horas"},
	"fr":    {"minute", "minutes", "heure", "heures"},
	"it":    {"minuto", "minuti", "ora", "ore"},
	"pt-BR": {"minuto", "minutos", "hora", "horas"},
}

// expiryIn writes a lifetime as {{expiry}} reads it (#818 decision 4): a number with its unit,
// singular or plural, in lang, in hours when it is a whole number of them and in minutes, rounded
// up, otherwise, so a release that changes a lifetime changes every text that names it.
func expiryIn(lang string, lifetime time.Duration) string {
	units, ok := durationUnits[lang]
	if !ok {
		units = durationUnits["en"]
	}
	if lifetime >= time.Hour && lifetime%time.Hour == 0 {
		return counted(int(lifetime/time.Hour), units.hour, units.hours)
	}
	minutes := int((lifetime + time.Minute - 1) / time.Minute)
	return counted(minutes, units.minute, units.minutes)
}

func counted(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}
