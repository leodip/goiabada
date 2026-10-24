package web

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// durationRun is the program TestUtilsJS_Durations runs under Node. For each case it loads the
// served utils.js into a fresh bare context, whose document carries only the html element's lang
// and data-catalog-lang, as both layouts write them, and evaluates the case's call there. It
// answers with Node's own default language, which the test holds to German so that a fallback to
// the runtime's default cannot pass for the fallback to English, and with what each call returned.
const durationRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const answer = { defaultLanguage: new Intl.NumberFormat().resolvedOptions().locale, answers: [] };
  request.cases.forEach(function (c) {
    const dataset = {};
    if (c.catalogLang !== null) {
      dataset.catalogLang = c.catalogLang;
    }
    const context = { document: { documentElement: { lang: c.lang, dataset: dataset } }, window: {} };
    vm.createContext(context);
    try {
      vm.runInContext(request.utils, context, { filename: "utils.js" });
      const got = vm.runInContext(c.call, context);
      answer.answers.push({ type: typeof got, value: String(got) });
    } catch (err) {
      answer.answers.push({ type: "thrown", value: String(err) });
    }
  });
  process.stdout.write(JSON.stringify(answer));
});
`

// durationCase is one call into utils.js: the page's lang and data-catalog-lang, nil for a page
// that carries none, the call, and the string it must return.
type durationCase struct {
	Lang        string  `json:"lang"`
	CatalogLang *string `json:"catalogLang"`
	Call        string  `json:"call"`
	want        string
}

// The two unit ranges the console's callers ask for: a settings field's readout, and the wait
// before another verification code.
const (
	settingsUnits = `["day", "hour", "minute", "second"]`
	waitUnits     = `["hour", "minute", "second"]`
)

func tag(s string) *string { return &s }

// formatIn is a call of the shared formatter on a page rendered from the catalog lang.
func formatIn(lang, seconds, units, want string) durationCase {
	return durationCase{Lang: lang, CatalogLang: tag(lang), Call: "formatDuration(" + seconds + ", " + units + ")", want: want}
}

// The sentences a settings form gives describeSeconds, in its data-duration-* attributes.
const (
	englishMessages = `{durationInvalid: "Enter a whole number of seconds.", durationTooLong: "That is too long.", ` +
		`durationZero: "Uses the global setting", durationGlobal: "3600"}`
	englishNoGlobal = `{durationInvalid: "Enter a whole number of seconds.", durationTooLong: "That is too long.", ` +
		`durationZero: "Uses the global setting"}`
	englishNoZero     = `{durationInvalid: "Enter a whole number of seconds.", durationTooLong: "That is too long."}`
	portugueseMessage = `{durationInvalid: "Informe um número inteiro de segundos.", durationTooLong: "Longo demais.", ` +
		`durationZero: "Usa a configuração global", durationGlobal: "5400"}`
)

// describeIn is a call of describeSeconds, as a settings field's readout makes it.
func describeIn(lang, value, messages, want string) durationCase {
	return durationCase{Lang: lang, CatalogLang: tag(lang), Call: "describeSeconds(" + value + ", " + messages + ")", want: want}
}

// durationRow is one number of seconds, written as JavaScript, and what the formatter writes for
// it in English and in pt-BR at the settings range and at the wait's.
type durationRow struct {
	seconds                                          string
	englishSettings, englishWait, ptSettings, ptWait string
}

// durationRows are the numbers of seconds #645 holds the formatter to, each string written out from
// CLDR's wording rather than computed with Intl here, which would pass by construction. The wait's
// range differs only from a day up, where it counts hours.
var durationRows = []durationRow{
	{"0", "0 seconds", "0 seconds", "0 segundo", "0 segundo"},
	{"1", "1 second", "1 second", "1 segundo", "1 segundo"},
	{"2", "2 seconds", "2 seconds", "2 segundos", "2 segundos"},
	{"59", "59 seconds", "59 seconds", "59 segundos", "59 segundos"},
	{"60", "1 minute", "1 minute", "1 minuto", "1 minuto"},
	{"61", "1 minute, 1 second", "1 minute, 1 second", "1 minuto e 1 segundo", "1 minuto e 1 segundo"},
	{"90", "1 minute, 30 seconds", "1 minute, 30 seconds", "1 minuto e 30 segundos", "1 minuto e 30 segundos"},
	{"120", "2 minutes", "2 minutes", "2 minutos", "2 minutos"},
	{"3599", "59 minutes, 59 seconds", "59 minutes, 59 seconds", "59 minutos e 59 segundos", "59 minutos e 59 segundos"},
	{"3600", "1 hour", "1 hour", "1 hora", "1 hora"},
	{"3601", "1 hour, 1 second", "1 hour, 1 second", "1 hora e 1 segundo", "1 hora e 1 segundo"},
	{"3661", "1 hour, 1 minute, 1 second", "1 hour, 1 minute, 1 second", "1 hora, 1 minuto e 1 segundo", "1 hora, 1 minuto e 1 segundo"},
	{"5400", "1 hour, 30 minutes", "1 hour, 30 minutes", "1 hora e 30 minutos", "1 hora e 30 minutos"},
	{"7200", "2 hours", "2 hours", "2 horas", "2 horas"},
	{"86399", "23 hours, 59 minutes, 59 seconds", "23 hours, 59 minutes, 59 seconds",
		"23 horas, 59 minutos e 59 segundos", "23 horas, 59 minutos e 59 segundos"},
	{"86400", "1 day", "24 hours", "1 dia", "24 horas"},
	{"86401", "1 day, 1 second", "24 hours, 1 second", "1 dia e 1 segundo", "24 horas e 1 segundo"},
	{"90061", "1 day, 1 hour, 1 minute, 1 second", "25 hours, 1 minute, 1 second",
		"1 dia, 1 hora, 1 minuto e 1 segundo", "25 horas, 1 minuto e 1 segundo"},
	{"172800", "2 days", "48 hours", "2 dias", "48 horas"},
	{"160000000", "1,851 days, 20 hours, 26 minutes, 40 seconds", "44,444 hours, 26 minutes, 40 seconds",
		"1.851 dias, 20 horas, 26 minutos e 40 segundos", "44.444 horas, 26 minutos e 40 segundos"},
	// A fraction is rounded up to a whole second, the one direction that never under-states a wait.
	{"0.4", "1 second", "1 second", "1 segundo", "1 segundo"},
	{"59.6", "1 minute", "1 minute", "1 minuto", "1 minuto"},
	{"3599.9", "1 hour", "1 hour", "1 hora", "1 hora"},
	// What is not a finite number of zero or more writes nothing, and throws nothing.
	{"-1", "", "", "", ""},
	{"-0.5", "", "", "", ""},
	{"NaN", "", "", "", ""},
	{"Infinity", "", "", "", ""},
	{"-Infinity", "", "", "", ""},
	{`"90"`, "", "", "", ""},
	{"null", "", "", "", ""},
	{"undefined", "", "", "", ""},
}

func durationCases() []durationCase {
	var cases []durationCase
	for _, r := range durationRows {
		cases = append(cases,
			formatIn("en", r.seconds, settingsUnits, r.englishSettings),
			formatIn("en", r.seconds, waitUnits, r.englishWait),
			formatIn("pt-BR", r.seconds, settingsUnits, r.ptSettings),
			formatIn("pt-BR", r.seconds, waitUnits, r.ptWait),
		)
	}
	return append(cases,
		// A settings field's readout: trimmed, digits only, zero meaning the global setting where the
		// form says so, and the cap of about five years.
		describeIn("en", `" 5400 "`, englishMessages, "1 hour, 30 minutes"),
		describeIn("en", `"abc"`, englishMessages, "Enter a whole number of seconds."),
		describeIn("en", `"1.5"`, englishMessages, "Enter a whole number of seconds."),
		describeIn("en", `"-1"`, englishMessages, "Enter a whole number of seconds."),
		describeIn("en", `""`, englishMessages, "Enter a whole number of seconds."),
		describeIn("en", `"0"`, englishMessages, "Uses the global setting (1 hour)"),
		describeIn("en", `"0"`, englishNoGlobal, "Uses the global setting"),
		describeIn("en", `"0"`, englishNoZero, "0 seconds"),
		describeIn("en", `"86400"`, englishMessages, "1 day"),
		describeIn("en", `"160000000"`, englishMessages, "1,851 days, 20 hours, 26 minutes, 40 seconds"),
		describeIn("en", `"160000001"`, englishMessages, "That is too long."),
		describeIn("pt-BR", `"5400"`, portugueseMessage, "1 hora e 30 minutos"),
		describeIn("pt-BR", `"0"`, portugueseMessage, "Usa a configuração global (1 hora e 30 minutos)"),
		describeIn("pt-BR", `"x"`, portugueseMessage, "Informe um número inteiro de segundos."),
		describeIn("pt-BR", `"160000000"`, portugueseMessage, "1.851 dias, 20 horas, 26 minutos e 40 segundos"),
		describeIn("pt-BR", `"160000001"`, portugueseMessage, "Longo demais."),

		// The duration speaks the catalog's language, an operator's added one included, with words
		// from the runtime's CLDR data, and never the language the page is marked with.
		// CLDR's French writes "1 heure" with a no-break space, as the browser shows it.
		formatIn("fr", "5400", settingsUnits, "1\u00a0heure et 30 minutes"),
		durationCase{Lang: "de-DE", CatalogLang: tag("pt-BR"), Call: "formatDuration(5400, " + settingsUnits + ")",
			want: "1 hora e 30 minutos"},
		durationCase{Lang: "pt-BR", CatalogLang: tag("en"), Call: "formatDuration(5400, " + settingsUnits + ")",
			want: "1 hour, 30 minutes"},
		durationCase{Lang: "de-DE", CatalogLang: tag("en"), Call: `describeSeconds("0", ` + englishMessages + `)`,
			want: "Uses the global setting (1 hour)"},

		// Then English, never the runtime's default language: for a catalog tag the runtime has no
		// data for, a malformed one, an empty one, and none at all.
		durationCase{Lang: "qaa", CatalogLang: tag("qaa"), Call: "formatDuration(5400, " + settingsUnits + ")",
			want: "1 hour, 30 minutes"},
		durationCase{Lang: "en", CatalogLang: tag("en_US"), Call: "formatDuration(5400, " + settingsUnits + ")",
			want: "1 hour, 30 minutes"},
		durationCase{Lang: "de-DE", CatalogLang: tag("x"), Call: "formatDuration(90061, " + waitUnits + ")",
			want: "25 hours, 1 minute, 1 second"},
		durationCase{Lang: "de-DE", CatalogLang: tag(""), Call: "formatDuration(5400, " + settingsUnits + ")",
			want: "1 hour, 30 minutes"},
		durationCase{Lang: "de-DE", CatalogLang: nil, Call: "formatDuration(5400, " + settingsUnits + ")",
			want: "1 hour, 30 minutes"},
		durationCase{Lang: "de-DE", CatalogLang: nil, Call: `describeSeconds("0", ` + englishMessages + `)`,
			want: "Uses the global setting (1 hour)"},
	)
}

// TestUtilsJS_Durations runs the served utils.js under Node and holds what the shared duration
// formatter and a settings field's readout write to the table below (#645 decisions 1 to 3):
// the catalog's language, then English; CLDR's units, plurals, list joining and digit grouping; a
// fraction rounded up to a whole second; and nothing at all for what is not a finite number of zero
// or more. Node runs with German as its own default language, LC_ALL rather than LANG because the
// dev container sets LC_ALL, which outranks LANG, so a fallback to the runtime's default would show
// as German rather than pass. Node not on PATH is fatal, as it is to core's script check.
//
// A Node upgrade whose CLDR data words a duration differently fails here, at the version bump.
func TestUtilsJS_Durations(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs utils.js under Node, which the dev container and the " +
			"test jobs install at the version src/authserver/versions.yaml pins")
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "durations.js")
	if writeErr := os.WriteFile(program, []byte(durationRun), 0o600); writeErr != nil {
		t.Fatalf("writing the program: %v", writeErr)
	}
	cases := durationCases()
	input, err := json.Marshal(map[string]any{"utils": utilsJS(t), "cases": cases})
	if err != nil {
		t.Fatalf("encoding the cases: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Env = append(os.Environ(), "LC_ALL=de_DE.UTF-8")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("running utils.js under Node: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	var answer struct {
		DefaultLanguage string `json:"defaultLanguage"`
		Answers         []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"answers"`
	}
	if decodeErr := json.Unmarshal(stdout.Bytes(), &answer); decodeErr != nil {
		t.Fatalf("reading Node's answer: %v: %s", decodeErr, stdout.String())
	}
	if !strings.HasPrefix(answer.DefaultLanguage, "de") {
		t.Fatalf("Node's default language is %q, not German, so the fallback cases would pass whatever "+
			"utils.js falls back to", answer.DefaultLanguage)
	}
	if len(answer.Answers) != len(cases) {
		t.Fatalf("Node answered %d cases of %d", len(answer.Answers), len(cases))
	}
	for i, c := range cases {
		got := answer.Answers[i]
		catalog := "none"
		if c.CatalogLang != nil {
			catalog = *c.CatalogLang
		}
		if got.Type != "string" || got.Value != c.want {
			t.Errorf("%s with lang %q, data-catalog-lang %s: got %s %q, want string %q",
				c.Call, c.Lang, catalog, got.Type, got.Value, c.want)
		}
	}
}
