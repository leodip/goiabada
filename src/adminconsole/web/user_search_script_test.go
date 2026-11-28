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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userSearchRun is the program TestUserSearchJS_DrawsTheFullNameItIsSent runs under Node: it loads
// the served page script against a stand-in of the search form, its field, the status region and
// the results table, with the console's sendAjaxRequest replaced by a recorder. It types the query,
// submits the form, hands the one request the answer it is given, and answers what each drawn row
// says under the user's email: the secondary line's text, or null when the row has none.
const userSearchRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);

  function element(props) {
    const map = {};
    const el = Object.assign({ dataset: {}, value: "", textContent: "", hidden: false, className: "", children: [],
      addEventListener: function (type, fn) { (map[type] = map[type] || []).push(fn); },
      fire: function (type, event) { (map[type] || []).forEach(function (fn) { fn(event); }); },
      appendChild: function (child) { el.children.push(child); return child; },
      append: function () { el.children.push.apply(el.children, arguments); },
      replaceChildren: function () { el.children = Array.prototype.slice.call(arguments); } }, props);
    return el;
  }

  const searchInput = element({ value: request.query });
  const searchForm = element({ dataset: { searchUrl: "/admin/groups/3/members/search", maxRows: "15",
    memberKey: "AddedToGroup", memberLabel: "Member", addUrl: "/admin/groups/3/members/add/{userId}",
    addLabel: "Add", added: "Added", subjectLabel: "Subject", prompt: "", none: "", truncated: "" } });
  searchForm.querySelector = function () { return searchInput; };
  const byId = { userSearchForm: searchForm, "row-actions-status": element({}) };
  const bySelector = { "[data-results-region]": element({}), "[data-results-rows]": element({}),
    "[data-results-note]": element({}) };

  const requests = [];
  const context = {
    Number: Number, String: String, URLSearchParams: URLSearchParams,
    setTimeout: function () { return 0; }, clearTimeout: function () {},
    document: {
      getElementById: function (id) { return byId[id] || null; },
      querySelector: function (selector) { return bySelector[selector] || null; },
      createElement: function (tag) { return element({ tagName: tag }); },
    },
    window: { addEventListener: function () {} },
    sendAjaxRequest: function (props) { requests.push(props); },
  };
  vm.createContext(context);
  vm.runInContext(request.script, context, { filename: "user-search.js" });

  searchForm.fire("submit", { preventDefault: function () {} });
  if (requests.length !== 1) { throw new Error("the search sent " + requests.length + " requests"); }
  requests[0].callback(request.answer);

  const lines = bySelector["[data-results-rows]"].children.map(function (row) {
    const who = row.children[0];
    const secondary = who.children.find(function (child) { return child.className === "cell-secondary"; });
    return secondary ? secondary.textContent : null;
  });
  process.stdout.write(JSON.stringify(lines));
});
`

func runUserSearch(t *testing.T, answer map[string]any) []any {
	t.Helper()
	node, err := exec.LookPath("node")
	require.NoError(t, err, "node is not on PATH: this test runs a page script under Node, which the dev container and "+
		"the test jobs install at the version src/authserver/versions.yaml pins")
	script, err := fs.ReadFile(StaticFS(), "pages/user-search.js")
	require.NoError(t, err, "reading the served script")
	program := filepath.Join(t.TempDir(), "user-search.js")
	require.NoError(t, os.WriteFile(program, []byte(userSearchRun), 0o600))
	input, err := json.Marshal(map[string]any{"script": string(script), "query": "a", "answer": answer})
	require.NoError(t, err)

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), "running the script under Node: %s", strings.TrimSpace(stderr.String()))
	var lines []any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &lines), "the program's answer: %s", stdout.String())
	return lines
}

// The user search draws the full name its answer sends, as core/personname wrote it on the
// console's server, and joins nothing itself (#662 decision 2): a user the answer sends no full
// name for, as a console that does not send one yet answers in the middle of an upgrade, is drawn
// with the username alone, though the answer carries the three names, and a user with neither is
// drawn with no line under the email.
func TestUserSearchJS_DrawsTheFullNameItIsSent(t *testing.T) {
	lines := runUserSearch(t, map[string]any{"Users": []map[string]any{
		{"Id": 7, "Email": "ana@example.com", "Username": "ana",
			"GivenName": "Ana", "MiddleName": "Maria", "FamilyName": "Silva", "FullName": "Ana Maria Silva"},
		{"Id": 8, "Email": "yamada@example.com", "Username": "yamada",
			"GivenName": "太郎", "MiddleName": "", "FamilyName": "山田", "FullName": "山田太郎"},
		{"Id": 9, "Email": "kim@example.com", "Username": "",
			"GivenName": "민준", "MiddleName": "", "FamilyName": "김", "FullName": "김민준"},
		{"Id": 10, "Email": "old@example.com", "Username": "old",
			"GivenName": "Ana", "MiddleName": "", "FamilyName": "Silva"},
		{"Id": 11, "Email": "nobody@example.com", "Username": "",
			"GivenName": "Ana", "MiddleName": "", "FamilyName": "Silva"},
	}})

	assert.Equal(t, []any{"Ana Maria Silva · ana", "山田太郎 · yamada", "김민준", "old", nil}, lines,
		"each row's line under the email, nil for none")
}
