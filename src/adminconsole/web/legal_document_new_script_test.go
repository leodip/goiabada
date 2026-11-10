package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shortNameRun is the program TestLegalDocumentNewJS_SuggestsTheShortName runs under Node: it loads
// the served page script into a bare context whose document has none of the page's fields, so only
// its functions are defined, and answers what suggestShortName returns for each title.
const shortNameRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const context = { document: { getElementById: function () { return null; } }, window: {} };
  vm.createContext(context);
  vm.runInContext(request.script, context, { filename: "legal-document-new.js" });
  const answers = request.titles.map(function (title) {
    return vm.runInContext("suggestShortName(" + JSON.stringify(title) + ")", context);
  });
  process.stdout.write(JSON.stringify(answers));
});
`

// The new legal document page suggests a short name from the title (#622 decision 5), one the auth
// server accepts as it is: lowercase letters, digits and hyphens, a letter or digit first and
// last, at most 64 characters. Each expected value is written out by hand.
func TestLegalDocumentNewJS_SuggestsTheShortName(t *testing.T) {
	cases := []struct{ title, want string }{
		{"Terms of use", "terms-of-use"},
		{"  Política de Privacidade  ", "politica-de-privacidade"},
		{"Cookies & tracking (2027)", "cookies-tracking-2027"},
		{"Conditions générales d'utilisation", "conditions-generales-d-utilisation"},
		{"Ürün Şartları", "urun-sartlar"},
		{"---", ""},
		{"日本語", ""},
		{strings.Repeat("a", 70), strings.Repeat("a", 64)},
		// The cut at 64 lands on a hyphen, which goes too.
		{strings.Repeat("a", 63) + " b", strings.Repeat("a", 63)},
	}

	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs a page script under Node, which the dev container and " +
			"the test jobs install at the version src/authserver/versions.yaml pins")
	}
	script, err := fs.ReadFile(StaticFS(), "pages/legal-document-new.js")
	if err != nil {
		t.Fatalf("reading the served script: %v", err)
	}
	program := filepath.Join(t.TempDir(), "short-names.js")
	if writeErr := os.WriteFile(program, []byte(shortNameRun), 0o600); writeErr != nil {
		t.Fatalf("writing the program: %v", writeErr)
	}
	titles := make([]string, len(cases))
	for i, c := range cases {
		titles[i] = c.title
	}
	input, err := json.Marshal(map[string]any{"script": string(script), "titles": titles})
	if err != nil {
		t.Fatalf("encoding the titles: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("running the script under Node: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	var answers []string
	if decodeErr := json.Unmarshal(stdout.Bytes(), &answers); decodeErr != nil {
		t.Fatalf("reading Node's answer: %v: %s", decodeErr, stdout.String())
	}
	if len(answers) != len(cases) {
		t.Fatalf("Node answered %d titles of %d", len(answers), len(cases))
	}
	for i, c := range cases {
		if answers[i] != c.want {
			t.Errorf("suggestShortName(%q) = %q, want %q", c.title, answers[i], c.want)
		}
	}
}
