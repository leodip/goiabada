package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pluralRun is the program the script's plural tests run under Node. For each case it loads the
// served utils.js into a fresh bare context, whose document carries the html element's
// data-catalog-lang, as both layouts write it, and the #js-i18n block's strings, and answers one of
// three things: the category pluralCategory gives each count, what tCount writes for each count, or
// the text of a searchable select's status after a person types each query into its field, read off
// the elements makeSearchable draws in a document just big enough to hold them. Node's own default
// language is held to Polish, so a fallback to the runtime's default cannot pass for the fallback
// to English.
const pluralRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const answer = { defaultLanguage: new Intl.PluralRules().resolvedOptions().locale, answers: [] };
  request.cases.forEach(function (c) {
    const dataset = {};
    if (c.catalogLang !== null) {
      dataset.catalogLang = c.catalogLang;
    }
    const made = [];
    const element = function () {
      const listeners = {};
      const attributes = {};
      const el = {
        hidden: false, textContent: "", className: "", id: "", style: {}, dataset: {},
        classList: { toggle: function () {} },
        setAttribute: function (name, value) { attributes[name] = String(value); },
        getAttribute: function (name) { return name in attributes ? attributes[name] : null; },
        hasAttribute: function (name) { return name in attributes; },
        removeAttribute: function (name) { delete attributes[name]; },
        appendChild: function (child) { return child; },
        append: function () {},
        after: function (node) { el.next = node; },
        addEventListener: function (type, listener) { (listeners[type] = listeners[type] || []).push(listener); },
        fire: function (type, event) { (listeners[type] || []).forEach(function (listener) { listener(event); }); },
        contains: function () { return false; },
        scrollIntoView: function () {},
        focus: function () {},
        dispatchEvent: function () {},
        getBoundingClientRect: function () { return { top: 0, bottom: 40 }; },
      };
      made.push(el);
      return el;
    };
    const document = {
      documentElement: { lang: c.catalogLang || "en", dataset: dataset },
      activeElement: null,
      createElement: element,
      querySelector: function () { return null; },
      addEventListener: function () {},
      getElementById: function (id) {
        return id === "js-i18n" ? { textContent: JSON.stringify(request.strings[c.strings] || {}) } : null;
      },
    };
    const context = { document: document, window: { innerHeight: 800, addEventListener: function () {} } };
    vm.createContext(context);
    try {
      vm.runInContext(request.utils, context, { filename: "utils.js" });
      if (c.kind === "category") {
        const category = vm.runInContext("typeof pluralCategory === 'function' ? pluralCategory : null", context);
        answer.answers.push(c.counts.map(function (count) { return category ? String(category(count)) : "no pluralCategory"; }));
      } else if (c.kind === "count") {
        const count = vm.runInContext("typeof tCount === 'function' ? tCount : null", context);
        answer.answers.push(c.counts.map(function (n) { return count ? String(count(c.key, n)) : "no tCount"; }));
      } else {
        const select = element();
        select.id = "zone";
        select.options = c.options.map(function (text, index) {
          return { value: index === 0 ? "" : "v" + index, textContent: text, selected: index === 0, dataset: {} };
        });
        vm.runInContext("makeSearchable", context)(select);
        const byRole = function (role) {
          return made.find(function (el) { return el.getAttribute("role") === role; });
        };
        const field = byRole("combobox");
        const status = byRole("status");
        document.activeElement = field;
        const statuses = c.queries.map(function (query) {
          field.value = query;
          field.fire("input", { inputType: "insertText" });
          return status.textContent;
        });
        answer.answers.push(statuses);
      }
    } catch (err) {
      answer.answers.push(["thrown: " + String(err)]);
    }
  });
  process.stdout.write(JSON.stringify(answer));
});
`

// pluralCase is one question to utils.js on a page rendered from catalogLang, nil for a page that
// carries none, whose #js-i18n block holds the strings named strings: the category of each count,
// what tCount writes for key at each count, or a searchable select's status after each query.
type pluralCase struct {
	Kind        string   `json:"kind"`
	CatalogLang *string  `json:"catalogLang"`
	Strings     string   `json:"strings"`
	Key         string   `json:"key"`
	Counts      []int    `json:"counts"`
	Options     []string `json:"options"`
	Queries     []string `json:"queries"`
	want        []string
}

// runPlural answers cases under Node with the strings each names, and holds Node's default language
// to Polish, whose categories differ from English's at 2, 5 and 22.
func runPlural(t *testing.T, strings map[string]map[string]string, cases []pluralCase) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs utils.js under Node, which the dev container and the " +
			"test jobs install at the version src/authserver/versions.yaml pins")
	}
	input, err := json.Marshal(map[string]any{"utils": utilsJS(t), "strings": strings, "cases": cases})
	require.NoError(t, err)
	cmd := exec.CommandContext(t.Context(), node, "-e", pluralRun)
	cmd.Env = append(os.Environ(), "LC_ALL=pl_PL.UTF-8")
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	require.NoErrorf(t, err, "running utils.js under Node: %s", stderr.String())
	var answer struct {
		DefaultLanguage string
		Answers         [][]string
	}
	require.NoError(t, json.Unmarshal(output, &answer))
	require.Equal(t, "pl-PL", answer.DefaultLanguage, "Node's default language, which no fallback may reach")
	require.Len(t, answer.Answers, len(cases))
	for i, c := range cases {
		lang := "no data-catalog-lang"
		if c.CatalogLang != nil {
			lang = *c.CatalogLang
		}
		assert.Equalf(t, c.want, answer.Answers[i], "%s, %s, %s%v%v", c.Kind, lang, c.Key, c.Counts, c.Queries)
	}
}

// scriptPluralCounts are the counts the issue lists for the three languages that share the chooser
// (#665, #666, #667): each category's first counts, the teens, and the return of a category past 20
// and 100.
var scriptPluralCounts = []int{0, 1, 2, 3, 4, 5, 11, 12, 14, 21, 22, 25, 100, 101, 102}

// The categories the script chooses by, from the page's catalog tag, written out from CLDR's tables
// rather than computed with Intl here. A page without a catalog tag, or with one Intl refuses or has
// no rules for, reads English's, never the browser's own default language.
func TestUtilsJS_PluralCategoryFollowsThePagesCatalogTag(t *testing.T) {
	category := func(lang *string, want ...string) pluralCase {
		return pluralCase{Kind: "category", CatalogLang: lang, Counts: scriptPluralCounts, want: want}
	}
	english := []string{"other", "one", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"}
	runPlural(t, nil, []pluralCase{
		category(tag("pl"), "many", "one", "few", "few", "few", "many", "many", "many", "many", "many", "few", "many", "many", "many", "few"),
		category(tag("ru"), "many", "one", "few", "few", "few", "many", "many", "many", "many", "one", "few", "many", "many", "one", "few"),
		category(tag("ar"), "zero", "one", "two", "few", "few", "few", "many", "many", "many", "many", "many", "many", "other", "other", "other"),
		category(tag("pl-PL"), "many", "one", "few", "few", "few", "many", "many", "many", "many", "many", "few", "many", "many", "many", "few"),
		// Zero takes the one form in French and Portuguese (Brazil).
		category(tag("fr"), "one", "one", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"),
		category(tag("pt-BR"), "one", "one", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"),
		category(tag("en"), english...),
		category(nil, english...),
		category(tag(""), english...),
		category(tag("not a tag!"), english...),
		category(tag("zxx"), english...),
	})
}

// tCount writes the form of the count's category the page's strings hold, and the other form for a
// category they hold no key for, with the count in its {{count}}; the strings hold only the forms
// the page's own catalog has, so the other form is never another language's.
func TestUtilsJS_TCountChoosesTheFormTheStringsHold(t *testing.T) {
	strings := map[string]map[string]string{
		"pl": {"pairs.one": "{{count}} para", "pairs.few": "{{count}} pary", "pairs.other": "{{count}} pary (other)"},
		"en": {"pairs.one": "{{count}} pair", "pairs.other": "{{count}} pairs"},
	}
	runPlural(t, strings, []pluralCase{
		{Kind: "count", CatalogLang: tag("pl"), Strings: "pl", Key: "pairs", Counts: []int{1, 2, 5, 22, 25},
			want: []string{"1 para", "2 pary", "5 pary (other)", "22 pary", "25 pary (other)"}},
		{Kind: "count", CatalogLang: tag("en"), Strings: "en", Key: "pairs", Counts: []int{0, 1, 2},
			want: []string{"0 pairs", "1 pair", "2 pairs"}},
		// A family the strings do not hold shows its other form's key, the visible miss t gives.
		{Kind: "count", CatalogLang: tag("en"), Strings: "en", Key: "nothing", Counts: []int{1},
			want: []string{"nothing.other"}},
	})
}

// comboboxStrings is the combobox's strings as the page hands them over in lang: the sentence for no
// match, and the forms of the match count its own catalog has, with Raw and RawCounted as the
// console's JSBootstrap reads them.
func comboboxStrings(lang string) map[string]string {
	ctx := i18n.WithLocale(context.Background(), true, lang)
	strings := i18n.RawCounted(ctx, "js.combobox.results")
	strings["js.combobox.no_matches"] = i18n.Raw(ctx, "js.combobox.no_matches")
	return strings
}

// A searchable select's status counts the matches in the page's language as the person types, by the
// count's CLDR category: no match reads the singular in French and Portuguese (Brazil), the form CLDR
// gives zero there, and the plural in the other built-in languages: in Polish, many for zero and 5,
// and few for 2 to 4 and again for 22.
func TestUtilsJS_SearchableStatusCountsTheMatches(t *testing.T) {
	options := []string{"Choose a zone", "Europe/Lisbon", "Europe/Paris", "America/Sao_Paulo"}
	// Twenty-two areas, five of them isles, which no other query matches: "area" matches 22 options
	// and "isle" 5.
	for i := 1; i <= 22; i++ {
		if i <= 5 {
			options = append(options, fmt.Sprintf("Atlantic/Isle Area %02d", i))
		} else {
			options = append(options, fmt.Sprintf("Pacific/Area %02d", i))
		}
	}
	queries := []string{"zzz", "lisb", "europe", "o", "isle", "area"}
	langs := []string{"en", "fr", "pt-BR", "es", "it", "de", "id", "pl", "ru"}
	strings := map[string]map[string]string{}
	for _, lang := range langs {
		strings[lang] = comboboxStrings(lang)
	}
	status := func(lang string, want ...string) pluralCase {
		return pluralCase{Kind: "status", CatalogLang: tag(lang), Strings: lang, Options: options, Queries: queries, want: want}
	}
	runPlural(t, strings, []pluralCase{
		status("en", "0 matches", "1 match", "2 matches", "4 matches", "5 matches", "22 matches"),
		status("fr", "0 résultat", "1 résultat", "2 résultats", "4 résultats", "5 résultats", "22 résultats"),
		status("pt-BR", "0 resultado", "1 resultado", "2 resultados", "4 resultados", "5 resultados", "22 resultados"),
		status("es", "0 resultados", "1 resultado", "2 resultados", "4 resultados", "5 resultados", "22 resultados"),
		status("it", "0 risultati", "1 risultato", "2 risultati", "4 risultati", "5 risultati", "22 risultati"),
		status("de", "0 Treffer", "1 Treffer", "2 Treffer", "4 Treffer", "5 Treffer", "22 Treffer"),
		status("id", "0 hasil", "1 hasil", "2 hasil", "4 hasil", "5 hasil", "22 hasil"),
		status("pl", "0 wyników", "1 wynik", "2 wyniki", "4 wyniki", "5 wyników", "22 wyniki"),
		status("ru", "0 совпадений", "1 совпадение", "2 совпадения", "4 совпадения", "5 совпадений", "22 совпадения"),
	})
}

// A searchable select's status in Russian takes the form of the count's category at every count
// where Russian's forms turn: many for zero, 5, 11 and 25, one for 1 and 21, and few for 2 and 22
// (#666).
func TestUtilsJS_SearchableStatusCountsTheMatchesInRussian(t *testing.T) {
	// Twenty-five zones. Each threshold's token marks the first that many of them, so the query for
	// a token matches exactly that many, and "zone" matches all 25.
	thresholds := []struct {
		token string
		count int
	}{{"qa", 1}, {"qb", 2}, {"qc", 5}, {"qd", 11}, {"qe", 21}, {"qf", 22}}
	options := []string{"Выберите"}
	for i := 1; i <= 25; i++ {
		option := fmt.Sprintf("Europe/Zone %02d", i)
		for _, threshold := range thresholds {
			if i <= threshold.count {
				option += " " + threshold.token
			}
		}
		options = append(options, option)
	}
	runPlural(t, map[string]map[string]string{"ru": comboboxStrings("ru")}, []pluralCase{{
		Kind: "status", CatalogLang: tag("ru"), Strings: "ru", Options: options,
		Queries: []string{"zzz", "qa", "qb", "qc", "qd", "qe", "qf", "zone"},
		want: []string{"0 совпадений", "1 совпадение", "2 совпадения", "5 совпадений", "11 совпадений",
			"21 совпадение", "22 совпадения", "25 совпадений"},
	}})
}
