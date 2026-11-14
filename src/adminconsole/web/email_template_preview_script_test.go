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

// emailPreviewRun is the program the email template preview's tests run under Node: it loads the served
// page script against a stand-in of the editor (#818 decisions 11 and 12), the form's three fields,
// the preview's brand selector, subject, plain-text part and status, the hidden form that loads the
// frame, and Send test email, with the console's sendAjaxRequest, debounce and showNotice replaced by
// recorders. It plays the steps it is handed and answers what each look saw.
const emailPreviewRun = `"use strict";
const vm = require("vm");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", function (chunk) { input += chunk; });
process.stdin.on("end", function () {
  const request = JSON.parse(input);

  function element(props) {
    const map = {};
    const el = Object.assign({ dataset: {}, value: "", textContent: "", disabled: false, attributes: {},
      addEventListener: function (type, fn) { (map[type] = map[type] || []).push(fn); },
      fire: function (type, event) { (map[type] || []).forEach(function (fn) { fn(event); }); },
      getAttribute: function (name) { return el.attributes[name] === undefined ? null : el.attributes[name]; },
      replaceChildren: function () { el.notice = null; } }, props);
    return el;
  }
  function makeEvent(type, target, extra) {
    const event = Object.assign({ type: type, target: target, defaultPrevented: false,
      preventDefault: function () { event.defaultPrevented = true; } }, extra || {});
    return event;
  }

  const subject = element({ id: "subject", value: request.text.subject });
  const body = element({ id: "body", value: request.text.body });
  const buttonLabel = request.text.buttonLabel === undefined ? null
    : element({ id: "buttonLabel", value: request.text.buttonLabel });
  const brand = element({ id: "previewBrand", value: "" });
  const panel = element({ id: "emailTemplatePreviewPanel",
    dataset: { previewUrl: "/admin/settings/email/templates/welcome/fr/preview" } });
  const previewStatus = element({ id: "previewStatus" });
  const previewSubject = element({ id: "previewSubject" });
  const previewText = element({ id: "previewText" });
  const frameFields = { subject: element({}), buttonLabel: element({}), body: element({}), brandId: element({}) };
  const frameForm = element({ id: "previewFrameForm", elements: frameFields, submitted: [] });
  frameForm.submit = function () {
    frameForm.submitted.push({ subject: frameFields.subject.value, buttonLabel: frameFields.buttonLabel.value,
      body: frameFields.body.value, brandId: frameFields.brandId.value });
  };
  const sendForm = element({ id: "sendTestForm",
    attributes: { action: "/admin/settings/email/templates/welcome/fr/send-test" } });
  const address = element({ id: "testAddress", value: "admin@example.com" });
  const sendButton = element({ id: "btnSendTest", disabled: !!request.smtpOff });
  const sendStatus = element({ id: "sendTestStatus" });
  const byId = { subject: subject, body: body, buttonLabel: buttonLabel, previewBrand: brand,
    emailTemplatePreviewPanel: panel, previewStatus: previewStatus, previewSubject: previewSubject,
    previewText: previewText, previewFrameForm: frameForm, sendTestForm: sendForm, testAddress: address,
    btnSendTest: sendButton, sendTestStatus: sendStatus };

  // Every request the script sends, oldest first, each answered or failed by a step.
  const requests = [];
  const windowListeners = element({});
  const context = {
    JSON: JSON, Number: Number, String: String, Object: Object,
    document: { getElementById: function (id) { return byId[id] || null; } },
    window: { addEventListener: windowListeners.addEventListener },
    debounce: function (fn) { return fn; },
    sendAjaxRequest: function (props) { requests.push(props); },
    showNotice: function (region, tone, text) { region.notice = { tone: tone, text: text }; },
  };
  vm.createContext(context);
  vm.runInContext(request.script, context, { filename: "email-template-preview.js" });

  const looks = [];
  let seen = 0;
  request.steps.forEach(function (step) {
    switch (step.do) {
      case "type":
        byId[step.id].value = step.value;
        byId[step.id].fire("input", makeEvent("input", byId[step.id]));
        break;
      case "brand":
        brand.value = step.value;
        brand.fire("change", makeEvent("change", brand));
        break;
      case "answer": {
        const props = requests[step.request];
        if (typeof props.current !== "function" || props.current()) {
          props.callback(step.answer);
        }
        if (props.finished) { props.finished(); }
        break;
      }
      case "fail": {
        const props = requests[step.request];
        props.statusRegion.notice = { tone: "danger", text: step.message };
        if (props.finished) { props.finished(); }
        break;
      }
      case "send": {
        const event = makeEvent("submit", sendForm);
        sendForm.fire("submit", event);
        looks.push({ prevented: event.defaultPrevented });
        break;
      }
      case "look":
        looks.push({
          requests: requests.slice(seen).map(function (props) {
            return { url: props.url, method: props.method, body: JSON.parse(props.bodyData) };
          }),
          subject: previewSubject.textContent, text: previewText.textContent,
          emailPreviewNotice: previewStatus.notice || null, frames: frameForm.submitted.slice(),
          sendNotice: sendStatus.notice || null, sendDisabled: sendButton.disabled,
        });
        seen = requests.length;
        break;
      default:
        throw new Error("unknown step " + step.do);
    }
  });
  process.stdout.write(JSON.stringify(looks));
});
`

type emailPreviewStep struct {
	Do      string         `json:"do"`
	ID      string         `json:"id,omitempty"`
	Value   string         `json:"value,omitempty"`
	Request int            `json:"request"`
	Answer  map[string]any `json:"answer,omitempty"`
	Message string         `json:"message,omitempty"`
}

type emailPreviewRequest struct {
	URL    string         `json:"url"`
	Method string         `json:"method"`
	Body   map[string]any `json:"body"`
}

type emailPreviewNotice struct {
	Tone string `json:"tone"`
	Text string `json:"text"`
}

type emailPreviewFrame struct {
	Subject     string `json:"subject"`
	ButtonLabel string `json:"buttonLabel"`
	Body        string `json:"body"`
	BrandId     string `json:"brandId"`
}

type emailPreviewLook struct {
	Prevented     bool                  `json:"prevented"`
	Requests      []emailPreviewRequest `json:"requests"`
	Subject       string                `json:"subject"`
	Text          string                `json:"text"`
	PreviewNotice *emailPreviewNotice   `json:"emailPreviewNotice"`
	Frames        []emailPreviewFrame   `json:"frames"`
	SendNotice    *emailPreviewNotice   `json:"sendNotice"`
	SendDisabled  bool                  `json:"sendDisabled"`
}

var lookAtEmailPreview = emailPreviewStep{Do: "look"}

func typeInEmailPreviewForm(id, value string) emailPreviewStep {
	return emailPreviewStep{Do: "type", ID: id, Value: value}
}
func chooseEmailPreviewBrand(value string) emailPreviewStep {
	return emailPreviewStep{Do: "brand", Value: value}
}
func answerEmailPreviewRequest(n int, answer map[string]any) emailPreviewStep {
	return emailPreviewStep{Do: "answer", Request: n, Answer: answer}
}
func failEmailPreviewRequest(n int, message string) emailPreviewStep {
	return emailPreviewStep{Do: "fail", Request: n, Message: message}
}

func runEmailPreview(t *testing.T, text editorText, smtpOff bool, steps ...emailPreviewStep) []emailPreviewLook {
	t.Helper()
	node, err := exec.LookPath("node")
	require.NoError(t, err, "node is not on PATH: this test runs a page script under Node, which the dev container and "+
		"the test jobs install at the version src/authserver/versions.yaml pins")
	script, err := fs.ReadFile(StaticFS(), "pages/email-template-preview.js")
	require.NoError(t, err, "reading the served script")
	program := filepath.Join(t.TempDir(), "preview.js")
	require.NoError(t, os.WriteFile(program, []byte(emailPreviewRun), 0o600))
	input, err := json.Marshal(map[string]any{"script": string(script), "text": text, "smtpOff": smtpOff, "steps": steps})
	require.NoError(t, err)

	cmd := exec.CommandContext(t.Context(), node, program)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), "running the script under Node: %s", strings.TrimSpace(stderr.String()))
	var looks []emailPreviewLook
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &looks), "the program's answer: %s", stdout.String())
	return looks
}

const emailPreviewURL = "/admin/settings/email/templates/welcome/fr/preview"

// The editor asks for a preview of the text in the form as it opens, the subject and the label
// trimmed as a save sends them, and with no brand chosen, the default brand. Its answer fills the
// subject and the plain-text part, and loads the frame with the same text through the hidden form.
func TestEmailTemplatePreviewJS_PreviewsTheTextAsTheEditorOpens(t *testing.T) {
	label := " Sign in "
	looks := runEmailPreview(t, editorText{Subject: " Welcome! ", ButtonLabel: &label, Body: "Hello,\n\n{{button}}"}, false,
		lookAtEmailPreview,
		answerEmailPreviewRequest(0, map[string]any{"subject": "Welcome!", "text": "Hello,"}),
		lookAtEmailPreview,
	)

	assert.Equal(t, []emailPreviewRequest{{URL: emailPreviewURL, Method: "POST",
		Body: map[string]any{"subject": "Welcome!", "buttonLabel": "Sign in", "body": "Hello,\n\n{{button}}"}}}, looks[0].Requests)
	assert.Empty(t, looks[0].Frames, "the frame waits for the answer")
	assert.Equal(t, "Welcome!", looks[1].Subject)
	assert.Equal(t, "Hello,", looks[1].Text)
	assert.Equal(t, []emailPreviewFrame{{Subject: "Welcome!", ButtonLabel: "Sign in", Body: "Hello,\n\n{{button}}", BrandId: ""}}, looks[1].Frames)
}

// Typing asks again, and so does choosing a brand, whose id goes with the text. A text the preview
// refuses is said where the preview is, and the last good preview stays: its subject, its
// plain-text part and its frame.
func TestEmailTemplatePreviewJS_ARefusalKeepsTheLastGoodPreview(t *testing.T) {
	looks := runEmailPreview(t, editorText{Subject: "Welcome!", Body: "Hello"}, false,
		answerEmailPreviewRequest(0, map[string]any{"subject": "Welcome!", "text": "Hello"}),
		lookAtEmailPreview,
		typeInEmailPreviewForm("body", "Hello {{nom}}"),
		failEmailPreviewRequest(1, "The body uses {{nom}}, which this email does not offer."),
		lookAtEmailPreview,
		chooseEmailPreviewBrand("4"),
		typeInEmailPreviewForm("body", "Hi"),
		answerEmailPreviewRequest(3, map[string]any{"subject": "Welcome!", "text": "Hi"}),
		lookAtEmailPreview,
	)

	assert.Equal(t, []emailPreviewRequest{{URL: emailPreviewURL, Method: "POST",
		Body: map[string]any{"subject": "Welcome!", "buttonLabel": "", "body": "Hello {{nom}}"}}}, looks[1].Requests)
	assert.Equal(t, &emailPreviewNotice{Tone: "danger", Text: "The body uses {{nom}}, which this email does not offer."}, looks[1].PreviewNotice)
	assert.Equal(t, "Hello", looks[1].Text, "the last good plain-text part stays")
	assert.Len(t, looks[1].Frames, 1, "the frame is not loaded with a refused text")

	require.Len(t, looks[2].Requests, 2)
	assert.Equal(t, map[string]any{"subject": "Welcome!", "buttonLabel": "", "body": "Hello {{nom}}", "brandId": float64(4)},
		looks[2].Requests[0].Body, "choosing a brand asks again in it")
	assert.Equal(t, map[string]any{"subject": "Welcome!", "buttonLabel": "", "body": "Hi", "brandId": float64(4)}, looks[2].Requests[1].Body)
	assert.Nil(t, looks[2].PreviewNotice, "an answer empties the refusal")
	assert.Equal(t, "Hi", looks[2].Text)
	assert.Equal(t, emailPreviewFrame{Subject: "Welcome!", Body: "Hi", BrandId: "4"}, looks[2].Frames[1])
}

// An answer to a request the editor has asked again since is dropped, so a slow answer never
// overwrites a newer text's preview.
func TestEmailTemplatePreviewJS_AnOlderAnswerIsDropped(t *testing.T) {
	looks := runEmailPreview(t, editorText{Subject: "Welcome!", Body: "Hello"}, false,
		typeInEmailPreviewForm("body", "Hi"),
		answerEmailPreviewRequest(0, map[string]any{"subject": "Welcome!", "text": "Hello"}),
		lookAtEmailPreview,
	)

	assert.Empty(t, looks[0].Text)
	assert.Empty(t, looks[0].Frames)
}

// Send test email sends the text in the form, saved or not, to the address typed, in the brand
// chosen for the preview, without leaving the page; its button waits while the send runs, and the
// answer's sentence is said beside it.
func TestEmailTemplatePreviewJS_SendTestSendsTheTextInTheForm(t *testing.T) {
	looks := runEmailPreview(t, editorText{Subject: "Welcome!", Body: "Hello"}, false,
		chooseEmailPreviewBrand("4"),
		typeInEmailPreviewForm("testAddress", " jane@example.com "),
		typeInEmailPreviewForm("subject", " Bienvenue "),
		lookAtEmailPreview,
		emailPreviewStep{Do: "send"},
		lookAtEmailPreview,
		answerEmailPreviewRequest(3, map[string]any{"message": "Test email sent to jane@example.com."}),
		lookAtEmailPreview,
	)

	assert.True(t, looks[1].Prevented, "the form is sent by the script, and the page stays")
	assert.Equal(t, []emailPreviewRequest{{URL: "/admin/settings/email/templates/welcome/fr/send-test", Method: "POST",
		Body: map[string]any{"to": "jane@example.com", "subject": "Bienvenue", "buttonLabel": "", "body": "Hello", "brandId": float64(4)}}},
		looks[2].Requests)
	assert.True(t, looks[2].SendDisabled, "the button waits for the answer")
	assert.Equal(t, &emailPreviewNotice{Tone: "positive", Text: "Test email sent to jane@example.com."}, looks[3].SendNotice)
	assert.False(t, looks[3].SendDisabled)
}

// With SMTP off the button is disabled, and a submission, by Enter in the address, sends nothing.
func TestEmailTemplatePreviewJS_SMTPOffSendsNothing(t *testing.T) {
	looks := runEmailPreview(t, editorText{Subject: "Welcome!", Body: "Hello"}, true,
		lookAtEmailPreview,
		emailPreviewStep{Do: "send"},
		lookAtEmailPreview,
	)

	assert.True(t, looks[1].Prevented)
	assert.Empty(t, looks[2].Requests)
	assert.True(t, looks[2].SendDisabled)
}
