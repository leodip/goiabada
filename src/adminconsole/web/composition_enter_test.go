package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compositionEnterRun is the program the composition Enter tests run under Node. For each Enter it
// loads the served utils.js into a fresh bare context, then the page script the request names when
// it names one, against stand-ins of the elements that script reads, with the console's
// sendAjaxRequest replaced by a recorder. It fills the field, presses the Enter in it as a keydown
// event and answers what the page did with it: whether the handler acted (the permissions editor
// asked the console to validate the fields, the URI list added a row, the searchable select chose
// the first match) and whether it took the Enter's default action from the browser.
const compositionEnterRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);
  const answers = request.enters.map(function (enter) {
    const made = [];
    function element(props) {
      const listeners = {};
      const attributes = {};
      const el = Object.assign({
        hidden: false, value: "", textContent: "", className: "", id: "", style: {}, dataset: {}, children: [],
        classList: { toggle: function () {} },
        setAttribute: function (name, value) { attributes[name] = String(value); },
        getAttribute: function (name) { return name in attributes ? attributes[name] : null; },
        hasAttribute: function (name) { return name in attributes; },
        removeAttribute: function (name) { delete attributes[name]; },
        appendChild: function (child) { el.children.push(child); return child; },
        append: function () { el.children.push.apply(el.children, arguments); },
        after: function () {},
        before: function () {},
        querySelector: function () { return null; },
        querySelectorAll: function () { return []; },
        addEventListener: function (type, listener) { (listeners[type] = listeners[type] || []).push(listener); },
        fire: function (type, event) { (listeners[type] || []).forEach(function (listener) { listener(event); }); },
        contains: function () { return false; },
        scrollIntoView: function () {},
        focus: function () {},
        dispatchEvent: function () {},
        getBoundingClientRect: function () { return { top: 0, bottom: 40 }; },
      }, props);
      made.push(el);
      return el;
    }
    const byId = {};
    const document = {
      documentElement: { lang: "en", dataset: {} },
      activeElement: null,
      createElement: function (tag) { return element({ tagName: tag }); },
      getElementById: function (id) { return byId[id] || null; },
      querySelector: function () { return null; },
      querySelectorAll: function () { return []; },
      addEventListener: function () {},
    };
    const requests = [];
    const context = {
      document: document, URL: URL, Event: function (type) { this.type = type; },
      setTimeout: function () { return 0; }, clearTimeout: function () {},
      window: { innerHeight: 800, addEventListener: function () {}, location: {} },
    };
    vm.createContext(context);
    vm.runInContext(request.utils, context, { filename: "utils.js" });
    context.sendAjaxRequest = function (props) { requests.push(props); };

    let field;
    let acted;
    if (request.handler === "permissions") {
      const rows = element({});
      const parts = { "[data-list-rows]": rows, "[data-list-region]": element({}),
        "[data-list-empty]": element({}), "[data-list-announce]": element({}) };
      byId.resourcePermissionsForm = element({
        dataset: { resourceId: "4", validateUrl: "/admin/resources/4/permissions/validate", duplicate: "Taken" },
        querySelector: function (selector) { return parts[selector] || null; },
      });
      ["permissionIdentifier", "permissionDescription", "addPermissionBtn", "updatePermissionBtn",
        "cancelEditBtn", "resourcePermissionsStatus", "permissionIdentifier-error",
        "permissionDescription-error"].forEach(function (id) { byId[id] = element({ id: id }); });
      vm.runInContext(request.script, context, { filename: "resource-permissions.js" });
      byId.permissionIdentifier.value = "documents:read";
      byId.permissionDescription.value = "文書を読む";
      field = byId[request.field];
      acted = function () { return requests.length > 0; };
    } else if (request.handler === "uris") {
      const rows = element({});
      rows.querySelectorAll = function () { return rows.children; };
      rows.querySelector = function () { return rows.children[0] || null; };
      const listInput = element({});
      const parts = { "[data-list-input]": listInput, "[data-list-add]": element({}), "[data-list-error]": element({}),
        "[data-list-rows]": rows, "[data-list-region]": element({}), "[data-list-empty]": element({}),
        "[data-list-announce]": element({}) };
      byId.uriListForm = element({
        dataset: { clientId: "2", added: "Added", invalid: "Not a URL", duplicate: "Listed", removeLabel: "Remove" },
        querySelector: function (selector) { return parts[selector] || null; },
      });
      byId.uriListStatus = element({});
      vm.runInContext(request.script, context, { filename: "client-uri-list.js" });
      listInput.value = "https://app.example.com/callback";
      field = listInput;
      acted = function () { return rows.children.length > 0; };
    } else {
      const select = element({ id: "zone", value: "" });
      select.options = ["Choose a time zone", "Asia/Tokyo", "Asia/Seoul"].map(function (text, index) {
        return { value: index === 0 ? "" : "v" + index, textContent: text, selected: index === 0, dataset: {} };
      });
      vm.runInContext("makeSearchable", context)(select);
      field = made.find(function (el) { return el.getAttribute("role") === "combobox"; });
      document.activeElement = field;
      field.value = "tokyo";
      field.fire("click", {});
      acted = function () { return select.value === "v1"; };
    }

    let prevented = false;
    field.fire("keydown", { key: "Enter", isComposing: enter.isComposing, keyCode: enter.keyCode,
      preventDefault: function () { prevented = true; } });
    return { acted: acted(), prevented: prevented };
  });
  process.stdout.write(JSON.stringify(answers));
});
`

// compositionEnter is one Enter pressed in a field: the keydown event's isComposing and keyCode.
type compositionEnter struct {
	IsComposing bool `json:"isComposing"`
	KeyCode     int  `json:"keyCode"`
}

// enterAnswer is what the page did with an Enter: whether its handler acted, and whether it took
// the Enter's default action from the browser.
type enterAnswer struct {
	Acted     bool `json:"acted"`
	Prevented bool `json:"prevented"`
}

// The three Enters each handler is tested with. Browsers mark the Enter that accepts an input
// method's candidate differently: Chromium and Firefox set isComposing on it, and Safari sends it
// after compositionend, isComposing false, with the keyCode 229 every browser gives a key the
// input method takes. An ordinary Enter has neither.
var (
	composingEnter = compositionEnter{IsComposing: true, KeyCode: 13}
	imeKeyEnter    = compositionEnter{IsComposing: false, KeyCode: 229}
	ordinaryEnter  = compositionEnter{IsComposing: false, KeyCode: 13}
	threeEnters    = []compositionEnter{composingEnter, imeKeyEnter, ordinaryEnter}
)

// An Enter that belongs to a composition is left to the input method; an ordinary one is the page's.
var enterAnswers = []enterAnswer{{Acted: false, Prevented: false}, {Acted: false, Prevented: false},
	{Acted: true, Prevented: true}}

// runCompositionEnters presses each Enter in field under handler, the page script at script ("" for
// utils.js alone), and answers what the page did with each.
func runCompositionEnters(t *testing.T, handler, script, field string, enters []compositionEnter) []enterAnswer {
	t.Helper()
	node, err := exec.LookPath("node")
	require.NoError(t, err, "node is not on PATH: this test runs the console's scripts under Node, which the dev "+
		"container and the test jobs install at the version src/authserver/versions.yaml pins")
	page := ""
	if script != "" {
		b, readErr := fs.ReadFile(StaticFS(), script)
		require.NoError(t, readErr, "reading the served script")
		page = string(b)
	}
	input, err := json.Marshal(map[string]any{"utils": utilsJS(t), "script": page, "handler": handler,
		"field": field, "enters": enters})
	require.NoError(t, err)
	cmd := exec.CommandContext(t.Context(), node, "-e", compositionEnterRun)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	require.NoErrorf(t, err, "running the scripts under Node: %s", stderr.String())
	var answers []enterAnswer
	require.NoError(t, json.Unmarshal(output, &answers), "the program's answer: %s", output)
	return answers
}

// The resource permissions editor adds the row on an ordinary Enter in its identifier or
// description field, and asks nothing on the Enter that accepts a conversion, which would add the
// permission half-written (#662 decision 8).
func TestResourcePermissionsJS_EnterInAConversionAddsNothing(t *testing.T) {
	for _, field := range []string{"permissionIdentifier", "permissionDescription"} {
		answers := runCompositionEnters(t, "permissions", "pages/resource-permissions.js", field, threeEnters)
		assert.Equalf(t, enterAnswers, answers, "an Enter with isComposing, one with keyCode 229 and an "+
			"ordinary one, in %s", field)
	}
}

// A client's URI list adds the entry on an ordinary Enter in its field, and not on the Enter that
// accepts a conversion (#662 decision 8).
func TestClientURIListJS_EnterInAConversionAddsNothing(t *testing.T) {
	answers := runCompositionEnters(t, "uris", "pages/client-uri-list.js", "", threeEnters)
	assert.Equal(t, enterAnswers, answers, "an Enter with isComposing, one with keyCode 229 and an ordinary one")
}

// A searchable select chooses its first match on an ordinary Enter in its open list, and chooses
// nothing on the Enter that accepts a conversion, which leaves the list open (#662 decision 8).
func TestUtilsJS_SearchableEnterInAConversionChoosesNothing(t *testing.T) {
	answers := runCompositionEnters(t, "searchable", "", "", threeEnters)
	assert.Equal(t, enterAnswers, answers, "an Enter with isComposing, one with keyCode 229 and an ordinary one")
}
