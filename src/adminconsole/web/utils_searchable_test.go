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

// searchableRun is the program TestUtilsJS_SearchableListsMatch runs under Node. It loads the served
// utils.js into a bare context and, for each case, asks filledOption which option a browser's
// autofill of the field names, or namedOption which one the text a person leaves in the field
// names. It answers with that option's value, or null for none.
const searchableRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const context = { document: { documentElement: { lang: "en", dataset: {} } }, window: {} };
  vm.createContext(context);
  vm.runInContext(request.utils, context, { filename: "utils.js" });
  // A utils.js without the functions names no option, so every case that expects one fails.
  const none = function () { return -1; };
  const filledOption = vm.runInContext("typeof filledOption === 'function' ? filledOption : null", context) || none;
  const namedOption = vm.runInContext("typeof namedOption === 'function' ? namedOption : null", context) || none;
  const answers = request.cases.map(function (c) {
    const options = request.lists[c.list];
    const index = c.kind === "fill" ? filledOption(options, c.value, c.purpose) : namedOption(options, c.value);
    return index >= 0 ? options[index].value : null;
  });
  process.stdout.write(JSON.stringify(answers));
});
`

// searchableOption is one option of a searchable list as makeSearchable reads it: the select
// option's value and text, and its data-calling-code on the phone page.
type searchableOption struct {
	Value       string `json:"value"`
	Text        string `json:"text"`
	CallingCode string `json:"callingCode"`
}

// The lists the cases search, written as the account pages draw them: a country by its flag and
// name, a language by its tag and name, a phone country by its flag, a dash, its name and calling
// code. The UK and its three Crown Dependencies share +44, and the United States and Canada +1.
var searchableLists = map[string][]searchableOption{
	"countries": {
		{Value: "", Text: "Choose a country"},
		{Value: "CI", Text: "🇨🇮 Côte d’Ivoire"},
		{Value: "DK", Text: "🇩🇰 Denmark"},
		{Value: "DE", Text: "🇩🇪 Germany"},
		{Value: "PT", Text: "🇵🇹 Portugal"},
		{Value: "PR", Text: "🇵🇷 Puerto Rico"},
	},
	"languages": {
		{Value: "", Text: "Choose a language and region"},
		{Value: "pt-BR", Text: "pt-BR – português (Brasil) (Portuguese (Brazil))"},
		{Value: "pt-PT", Text: "pt-PT – português (Portugal) (Portuguese (Portugal))"},
	},
	"phones": {
		{Value: "", Text: "Choose a country"},
		{Value: "CAN_0", Text: "🇨🇦 - Canada (+1)", CallingCode: "+1"},
		{Value: "GGY_0", Text: "🇬🇬 - Guernsey (+44)", CallingCode: "+44"},
		{Value: "IMN_0", Text: "🇮🇲 - Isle of Man (+44)", CallingCode: "+44"},
		{Value: "JEY_0", Text: "🇯🇪 - Jersey (+44)", CallingCode: "+44"},
		{Value: "PRT_0", Text: "🇵🇹 - Portugal (+351)", CallingCode: "+351"},
		{Value: "GBR_0", Text: "🇬🇧 - UK (+44)", CallingCode: "+44"},
		{Value: "USA_0", Text: "🇺🇸 - United States (+1)", CallingCode: "+1"},
	},
}

// searchableCase is one question to utils.js: a fill of the list's field with value under the
// select's purpose, or text left in the field, and the value of the option it must name, nil for
// none.
type searchableCase struct {
	Kind    string `json:"kind"`
	List    string `json:"list"`
	Value   string `json:"value"`
	Purpose string `json:"purpose"`
	want    *string
}

func filled(list, purpose, value string, want *string) searchableCase {
	return searchableCase{Kind: "fill", List: list, Purpose: purpose, Value: value, want: want}
}

func leftAs(list, text string, want *string) searchableCase {
	return searchableCase{Kind: "name", List: list, Value: text, want: want}
}

// A browser's autofill names a country by its ISO 3166-1 alpha-2 code, which the HTML Standard's
// autofill table (4.10.19.7.1) defines for the country purpose, or in practice by its name; a
// language by its BCP 47 tag; a phone country by the "+NN" country code tel-country-code defines.
// A fill commits the option whose value equals it, case aside, and then the one its name names,
// accents, case and the leading flag aside; a calling code commits only the one country that has
// it. Text a person leaves in the field keeps the option it names by name, never by code, since a
// few typed letters are a search (#722 decisions 3, 5 and 6).
func searchableCases() []searchableCase {
	pt, ci, de, ptBR, prt := tag("PT"), tag("CI"), tag("DE"), tag("pt-BR"), tag("PRT_0")
	return []searchableCase{
		filled("countries", "country", "PT", pt),
		filled("countries", "country", "pt", pt),
		filled("countries", "country", " PT ", pt),
		filled("countries", "country", "de", de),
		filled("countries", "country", "Portugal", pt),
		filled("countries", "country", "PORTUGAL", pt),
		filled("countries", "country", "🇵🇹 Portugal", pt),
		filled("countries", "country", "Cote d’Ivoire", ci),
		filled("countries", "country", "côte d’ivoire", ci),
		filled("countries", "country", "Portugália", nil),
		filled("countries", "country", "Port", nil),
		filled("countries", "country", "", nil),
		filled("languages", "language", "pt-br", ptBR),
		filled("languages", "language", "pt-BR", ptBR),
		filled("languages", "language", "pt", nil),
		filled("phones", "tel-country-code", "+351", prt),
		filled("phones", "tel-country-code", " +351 ", prt),
		filled("phones", "tel-country-code", "+44", nil),
		filled("phones", "tel-country-code", "+1", nil),
		filled("phones", "tel-country-code", "351", nil),
		filled("phones", "tel-country-code", "+35", nil),
		filled("phones", "tel-country-code", "PRT_0", nil),
		filled("phones", "tel-country-code", "Portugal (+351)", nil),

		leftAs("countries", "Portugal", pt),
		leftAs("countries", "portugal", pt),
		leftAs("countries", " Portugal ", pt),
		leftAs("countries", "🇵🇹 Portugal", pt),
		leftAs("countries", "Côte d’Ivoire", ci),
		leftAs("countries", "cote d’ivoire", ci),
		leftAs("countries", "PT", nil),
		leftAs("countries", "de", nil),
		leftAs("countries", "Portugália", nil),
		leftAs("countries", "Port", nil),
		leftAs("languages", "pt-BR – português (Brasil) (Portuguese (Brazil))", ptBR),
		leftAs("languages", "pt-BR", nil),
		leftAs("phones", "Portugal (+351)", prt),
		leftAs("phones", "🇵🇹 - Portugal (+351)", prt),
		leftAs("phones", "+351", nil),
	}
}

// The searchable lists' matching rules, run in the served utils.js under Node. Node not on PATH is
// fatal, as it is to TestUtilsJS_Durations.
func TestUtilsJS_SearchableListsMatch(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs utils.js under Node, which the dev container and the " +
			"test jobs install at the version src/authserver/versions.yaml pins")
	}
	program := filepath.Join(t.TempDir(), "searchable.js")
	if writeErr := os.WriteFile(program, []byte(searchableRun), 0o600); writeErr != nil {
		t.Fatalf("writing the program: %v", writeErr)
	}
	cases := searchableCases()
	input, err := json.Marshal(map[string]any{"utils": utilsJS(t), "lists": searchableLists, "cases": cases})
	if err != nil {
		t.Fatalf("encoding the cases: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("running utils.js under Node: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	var answers []*string
	if decodeErr := json.Unmarshal(stdout.Bytes(), &answers); decodeErr != nil {
		t.Fatalf("reading Node's answer: %v: %s", decodeErr, stdout.String())
	}
	if len(answers) != len(cases) {
		t.Fatalf("Node answered %d cases of %d", len(answers), len(cases))
	}
	show := func(v *string) string {
		if v == nil {
			return "no option"
		}
		return "option " + *v
	}
	for i, c := range cases {
		got, want := answers[i], c.want
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			what := "text left in the field"
			if c.Kind == "fill" {
				what = "a " + c.Purpose + " fill"
			}
			t.Errorf("%s list, %s %q: got %s, want %s", c.List, what, c.Value, show(got), show(want))
		}
	}
}

// makeSearchable gives the field the select's purpose and reads each phone option's calling code
// from the attribute the account phone page writes, so a rename on either side fails here rather
// than leaving autofill to fill nothing.
func TestUtilsJS_SearchableListsReadThePurposeAndCallingCode(t *testing.T) {
	script := utilsJS(t)
	for _, read := range []string{`select.getAttribute("autocomplete")`, `dataset.callingCode`} {
		if !strings.Contains(script, read) {
			t.Errorf("utils.js does not read %s", read)
		}
	}
	page, err := templateFS.ReadFile("template/account_phone.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), `data-calling-code="{{ .CallingCode }}"`) {
		t.Error("account_phone.html writes no data-calling-code on its options")
	}
}
