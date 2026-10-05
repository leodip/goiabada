package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/term"
)

// errReadFault is a read that fails for a reason other than the operator ending the wizard.
var errReadFault = errors.New("read fault")

// scriptedStep is one read a scripted prompter expects: the prompt it must be asked with, by its
// start, whether it is a password read, and what the read returns.
type scriptedStep struct {
	prompt string
	// hidden is a read that must not echo or be kept in the line history: a password's.
	hidden bool
	answer string
	err    error
}

// scriptedPrompter answers the reads of a test in order and fails the test on a read it was not
// scripted for, one asked with another prompt, or a password read as a line or a line as a password.
// It keeps every prompt it was asked with, which the operator reads as they read the console.
type scriptedPrompter struct {
	t       *testing.T
	steps   []scriptedStep
	prompts []string
}

func (p *scriptedPrompter) readLine(prompt string) (string, error) {
	p.t.Helper()
	return p.read(prompt, false)
}

func (p *scriptedPrompter) readPassword(prompt string) (string, error) {
	p.t.Helper()
	return p.read(prompt, true)
}

func (p *scriptedPrompter) read(prompt string, hidden bool) (string, error) {
	p.t.Helper()
	p.prompts = append(p.prompts, prompt)
	if len(p.steps) == 0 {
		p.t.Errorf("read %q with nothing scripted", prompt)
		return "", errReadFault
	}
	step := p.steps[0]
	p.steps = p.steps[1:]
	if !strings.HasPrefix(prompt, step.prompt) {
		p.t.Errorf("read %q, scripted for %q", prompt, step.prompt)
	}
	if hidden != step.hidden {
		p.t.Errorf("read %q with hidden %v, scripted with hidden %v", prompt, hidden, step.hidden)
	}
	return step.answer, step.err
}

// assertConsumed fails the test if a scripted read was never asked for.
func (p *scriptedPrompter) assertConsumed() {
	p.t.Helper()
	for _, step := range p.steps {
		p.t.Errorf("scripted read %q was never asked", step.prompt)
	}
}

func testAsker(t *testing.T, steps ...scriptedStep) (asker, *scriptedPrompter, *bytes.Buffer) {
	in := &scriptedPrompter{t: t, steps: steps}
	var buf bytes.Buffer
	return asker{in: in, out: &console{w: &buf}}, in, &buf
}

// A read that fails is the failure and never the default: a fault at "Generate configuration
// files?" took the default yes and wrote the file (#430).
func TestAsker_AReadFaultIsNeverTheDefault(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		a, in, _ := testAsker(t, scriptedStep{prompt: "Name [fallback]: ", err: errReadFault})
		got, err := a.text("Name", "fallback")
		if !errors.Is(err, errReadFault) || got != "" {
			t.Errorf("text = %q, %v; want \"\" and the read fault", got, err)
		}
		in.assertConsumed()
	})
	t.Run("choice", func(t *testing.T) {
		a, in, _ := testAsker(t, scriptedStep{prompt: "Pick [1]: ", err: errReadFault})
		got, err := a.choice("Pick", []string{"1", "2"})
		if !errors.Is(err, errReadFault) || got != "" {
			t.Errorf("choice = %q, %v; want \"\" and the read fault", got, err)
		}
		in.assertConsumed()
	})
	t.Run("yes/no", func(t *testing.T) {
		a, in, _ := testAsker(t, scriptedStep{prompt: "Go? [Y/n]: ", err: errReadFault})
		got, err := a.yesNo("Go?", true)
		if !errors.Is(err, errReadFault) || got {
			t.Errorf("yesNo = %v, %v; want false and the read fault", got, err)
		}
		in.assertConsumed()
	})
	t.Run("validated", func(t *testing.T) {
		a, in, _ := testAsker(t, scriptedStep{prompt: "Port [5432]: ", err: errReadFault})
		got, err := a.port("Port", "5432")
		if !errors.Is(err, errReadFault) || got != "" {
			t.Errorf("port = %q, %v; want \"\" and the read fault", got, err)
		}
		in.assertConsumed()
	})
	t.Run("the weak-password confirmation", func(t *testing.T) {
		a, in, _ := testAsker(t,
			scriptedStep{prompt: "Password [generated]: ", hidden: true, answer: "weak"},
			scriptedStep{prompt: "Use this password anyway? [y/N]: ", err: errReadFault},
		)
		got, err := a.judgedPassword("Password", generatePassword())
		if !errors.Is(err, errReadFault) || got != "" {
			t.Errorf("judgedPassword = %q, %v; want \"\" and the read fault", got, err)
		}
		in.assertConsumed()
	})
}

func TestAsker_AnEmptyAnswerIsTheDefault(t *testing.T) {
	a, in, _ := testAsker(t,
		scriptedStep{prompt: "Name [fallback]: ", answer: "   "},
		scriptedStep{prompt: "Pick [2]: ", answer: ""},
		scriptedStep{prompt: "Go? [Y/n]: ", answer: ""},
		scriptedStep{prompt: "Stop? [y/N]: ", answer: ""},
	)
	if got, err := a.text("Name", "fallback"); err != nil || got != "fallback" {
		t.Errorf("text = %q, %v; want the default", got, err)
	}
	if got, err := a.choice("Pick", []string{"2", "1"}); err != nil || got != "2" {
		t.Errorf("choice = %q, %v; want the default", got, err)
	}
	if got, err := a.yesNo("Go?", true); err != nil || !got {
		t.Errorf("yesNo(default yes) = %v, %v; want true", got, err)
	}
	if got, err := a.yesNo("Stop?", false); err != nil || got {
		t.Errorf("yesNo(default no) = %v, %v; want false", got, err)
	}
	in.assertConsumed()
}

func TestAsker_AnAnswerIsTrimmedAndTaken(t *testing.T) {
	a, in, _ := testAsker(t,
		scriptedStep{prompt: "Name: ", answer: "  given  "},
		scriptedStep{prompt: "Go? [y/N]: ", answer: "YES"},
		scriptedStep{prompt: "Go? [Y/n]: ", answer: "n"},
	)
	if got, err := a.text("Name", ""); err != nil || got != "given" {
		t.Errorf("text = %q, %v; want \"given\"", got, err)
	}
	if got, err := a.yesNo("Go?", false); err != nil || !got {
		t.Errorf("yesNo(YES) = %v, %v; want true", got, err)
	}
	if got, err := a.yesNo("Go?", true); err != nil || got {
		t.Errorf("yesNo(n) = %v, %v; want false", got, err)
	}
	in.assertConsumed()
}

func TestAsker_TheAbortIsReturnedAsItIs(t *testing.T) {
	a, in, _ := testAsker(t,
		scriptedStep{prompt: "Name", err: errAborted},
		scriptedStep{prompt: "Pick", err: errAborted},
		scriptedStep{prompt: "Go?", err: errAborted},
	)
	if _, err := a.text("Name", "x"); !errors.Is(err, errAborted) {
		t.Errorf("text: %v, want errAborted", err)
	}
	if _, err := a.choice("Pick", []string{"1"}); !errors.Is(err, errAborted) {
		t.Errorf("choice: %v, want errAborted", err)
	}
	if _, err := a.yesNo("Go?", true); !errors.Is(err, errAborted) {
		t.Errorf("yesNo: %v, want errAborted", err)
	}
	in.assertConsumed()
}

// An answer no generated file can carry is asked again, whatever typed prompt read it and whether
// or not it would pass that prompt's own check: a free-text password has none (#430).
func TestAsker_AnUnwritableAnswerIsAskedAgain(t *testing.T) {
	a, in, out := testAsker(t,
		scriptedStep{prompt: "Password: ", answer: "pa\xffss"},
		scriptedStep{prompt: "Password: ", answer: "pa\x00ss"},
		scriptedStep{prompt: "Password: ", answer: "pässwörd"},
		scriptedStep{prompt: "User [root]: ", answer: "\xc3"},
		scriptedStep{prompt: "User [root]: ", answer: ""},
	)
	if got, err := a.nonEmpty("Password", ""); err != nil || got != "pässwörd" {
		t.Errorf("nonEmpty = %q, %v; want \"pässwörd\"", got, err)
	}
	if got, err := a.text("User", "root"); err != nil || got != "root" {
		t.Errorf("text = %q, %v; want the default after the refusal", got, err)
	}
	in.assertConsumed()
	for _, complaint := range []string{
		"This answer cannot be written to the configuration: it is not valid UTF-8. Please try again.",
		"This answer cannot be written to the configuration: it contains a NUL character. Please try again.",
	} {
		if !strings.Contains(out.String(), complaint) {
			t.Errorf("output lacks %q:\n%s", complaint, out.String())
		}
	}
}

func TestAsker_AnInvalidAnswerIsAskedAgain(t *testing.T) {
	a, in, out := testAsker(t,
		scriptedStep{prompt: "Pick [1]: ", answer: "7"},
		scriptedStep{prompt: "Pick [1]: ", answer: "2"},
		scriptedStep{prompt: "Go? [Y/n]: ", answer: "maybe"},
		scriptedStep{prompt: "Go? [Y/n]: ", answer: "y"},
		scriptedStep{prompt: "Port [5432]: ", answer: "http"},
		scriptedStep{prompt: "Port [5432]: ", answer: "6543"},
		scriptedStep{prompt: "User: ", answer: ""},
		scriptedStep{prompt: "User: ", answer: "someone"},
	)
	if got, err := a.choice("Pick", []string{"1", "2"}); err != nil || got != "2" {
		t.Errorf("choice = %q, %v; want \"2\"", got, err)
	}
	if got, err := a.yesNo("Go?", true); err != nil || !got {
		t.Errorf("yesNo = %v, %v; want true", got, err)
	}
	if got, err := a.port("Port", "5432"); err != nil || got != "6543" {
		t.Errorf("port = %q, %v; want \"6543\"", got, err)
	}
	if got, err := a.nonEmpty("User", ""); err != nil || got != "someone" {
		t.Errorf("nonEmpty = %q, %v; want \"someone\"", got, err)
	}
	in.assertConsumed()
	for _, complaint := range []string{
		"Invalid choice. Please try again.",
		"Please enter 'y' or 'n'.",
		"Invalid port: port must be a number. Please try again.",
		"This field cannot be empty. Please try again.",
	} {
		if !strings.Contains(out.String(), complaint) {
			t.Errorf("output lacks %q:\n%s", complaint, out.String())
		}
	}
}

func TestAsker_AWeakPasswordIsKeptOnlyWhenConfirmed(t *testing.T) {
	a, in, out := testAsker(t,
		scriptedStep{prompt: "Password [generated]: ", hidden: true, answer: "changeme"},
		scriptedStep{prompt: "Use this password anyway? [y/N]: ", answer: ""},
		scriptedStep{prompt: "Password [generated]: ", hidden: true, answer: "weak"},
		scriptedStep{prompt: "Use this password anyway? [y/N]: ", answer: "y"},
		scriptedStep{prompt: "Password [generated]: ", hidden: true, answer: "Str0ng-Passw0rd!"},
	)
	if got, err := a.judgedPassword("Password", generatePassword()); err != nil || got != "weak" {
		t.Errorf("judgedPassword = %q, %v; want the confirmed \"weak\"", got, err)
	}
	if got, err := a.judgedPassword("Password", generatePassword()); err != nil || got != "Str0ng-Passw0rd!" {
		t.Errorf("judgedPassword = %q, %v; want the strong one, not asked about", got, err)
	}
	in.assertConsumed()
	if !strings.Contains(out.String(), "Weak password: ") {
		t.Errorf("output lacks the weak-password warning:\n%s", out.String())
	}
}

// memoryTerminal is a terminal as term.Terminal sees it: what the operator typed, and where the
// echo goes. readErr, when set, is what a read returns once the input is spent.
type memoryTerminal struct {
	input   *strings.Reader
	output  bytes.Buffer
	readErr error
}

func (m *memoryTerminal) Read(p []byte) (int, error) {
	n, err := m.input.Read(p)
	if errors.Is(err, io.EOF) && m.readErr != nil {
		return n, m.readErr
	}
	return n, err
}

func (m *memoryTerminal) Write(p []byte) (int, error) { return m.output.Write(p) }

// rawMode counts the times a terminal prompter entered raw mode and restored it.
type rawMode struct {
	entered, restored int
	enterErr          error
	restoreErr        error
}

func testTerminalPrompter(typed string) (*terminalPrompter, *memoryTerminal, *rawMode) {
	terminal := &memoryTerminal{input: strings.NewReader(typed)}
	raw := &rawMode{}
	p := &terminalPrompter{
		t: term.NewTerminal(terminal, ""),
		enter: func() (func() error, error) {
			if raw.enterErr != nil {
				return nil, raw.enterErr
			}
			raw.entered++
			return func() error {
				raw.restored++
				return raw.restoreErr
			}, nil
		},
		size: func() (int, int, error) { return 120, 40, nil },
	}
	return p, terminal, raw
}

func TestTerminalPrompter_ReadsALineInRawModeAndRestoresIt(t *testing.T) {
	p, terminal, raw := testTerminalPrompter("first\rsecond\r\n")
	for _, want := range []string{"first", "second"} {
		got, err := p.readLine("Name: ")
		if err != nil || got != want {
			t.Errorf("readLine = %q, %v; want %q", got, err, want)
		}
	}
	if raw.entered != 2 || raw.restored != 2 {
		t.Errorf("raw mode entered %d and restored %d times, want 2 and 2", raw.entered, raw.restored)
	}
	if !strings.Contains(terminal.output.String(), "Name: ") {
		t.Errorf("the prompt was not written: %q", terminal.output.String())
	}
}

func TestTerminalPrompter_CtrlCCtrlDAndTheEndOfInputAreTheAbort(t *testing.T) {
	for name, typed := range map[string]string{
		"Ctrl-C":                  "abc\x03",
		"Ctrl-D at an empty line": "\x04",
		"the end of the input":    "",
	} {
		t.Run(name, func(t *testing.T) {
			p, _, raw := testTerminalPrompter(typed)
			if _, err := p.readLine("Name: "); !errors.Is(err, errAborted) {
				t.Errorf("readLine: %v, want errAborted", err)
			}
			if raw.restored != raw.entered || raw.entered != 1 {
				t.Errorf("raw mode entered %d and restored %d times, want 1 and 1", raw.entered, raw.restored)
			}
		})
	}
}

func TestTerminalPrompter_AReadFaultIsNotTheAbort(t *testing.T) {
	p, terminal, raw := testTerminalPrompter("partial")
	terminal.readErr = errReadFault
	_, err := p.readLine("Name: ")
	if !errors.Is(err, errReadFault) || errors.Is(err, errAborted) {
		t.Errorf("readLine: %v, want the read fault", err)
	}
	if raw.restored != 1 {
		t.Errorf("raw mode restored %d times, want 1", raw.restored)
	}
}

func TestTerminalPrompter_RawModeFailures(t *testing.T) {
	t.Run("entering", func(t *testing.T) {
		p, _, raw := testTerminalPrompter("typed\r")
		raw.enterErr = errReadFault
		if got, err := p.readLine("Name: "); !errors.Is(err, errReadFault) || got != "" {
			t.Errorf("readLine = %q, %v; want \"\" and the failure", got, err)
		}
	})
	t.Run("restoring", func(t *testing.T) {
		p, _, raw := testTerminalPrompter("typed\r")
		raw.restoreErr = errReadFault
		if _, err := p.readLine("Name: "); !errors.Is(err, errReadFault) {
			t.Errorf("readLine: %v, want the restore failure", err)
		}
	})
}

func TestLinePrompter_ReadsLinesUntilTheEnd(t *testing.T) {
	var out bytes.Buffer
	p := &linePrompter{r: bufio.NewReader(strings.NewReader("first\nsecond\r\nlast")), w: &out}
	for _, want := range []string{"first", "second", "last"} {
		got, err := p.readLine("Name: ")
		if err != nil || got != want {
			t.Errorf("readLine = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := p.readLine("Name: "); !errors.Is(err, errAborted) {
		t.Errorf("readLine at the end: %v, want errAborted", err)
	}
	if got := strings.Count(out.String(), "Name: "); got != 4 {
		t.Errorf("the prompt was written %d times, want 4", got)
	}
}

// faultyReader returns what it holds and then errReadFault.
type faultyReader struct{ held string }

func (r *faultyReader) Read(p []byte) (int, error) {
	if r.held == "" {
		return 0, errReadFault
	}
	n := copy(p, r.held)
	r.held = r.held[n:]
	return n, nil
}

func TestLinePrompter_AReadFaultIsNotTheAbort(t *testing.T) {
	p := &linePrompter{r: bufio.NewReader(&faultyReader{held: "partial"}), w: io.Discard}
	_, err := p.readLine("Name: ")
	if !errors.Is(err, errReadFault) || errors.Is(err, errAborted) {
		t.Errorf("readLine: %v, want the read fault", err)
	}
}

// A password is read without echo and kept out of the line history, so it reaches neither the
// screen, its scrollback and recordings, nor the up arrow at a later prompt; a line read before it
// is still recalled, so the history the password is missing from is one that works (#396 decision
// 17).
func TestTerminalPrompter_APasswordIsReadWithoutEchoOrHistory(t *testing.T) {
	p, terminal, raw := testTerminalPrompter("visible\rZq7HiddenValue\r\x1b[A\r")
	if got, err := p.readLine("Name: "); err != nil || got != "visible" {
		t.Fatalf("readLine = %q, %v; want \"visible\"", got, err)
	}
	if got, err := p.readPassword("Admin password: "); err != nil || got != "Zq7HiddenValue" {
		t.Fatalf("readPassword = %q, %v; want \"Zq7HiddenValue\"", got, err)
	}
	if got, err := p.readLine("Name: "); err != nil || got != "visible" {
		t.Errorf("the up arrow recalled %q, %v; want \"visible\", the last line read with echo", got, err)
	}
	written := terminal.output.String()
	if strings.Contains(written, "Zq7HiddenValue") {
		t.Errorf("the password was echoed: %q", written)
	}
	if !strings.Contains(written, "Admin password: ") {
		t.Errorf("the password prompt was not written: %q", written)
	}
	if raw.entered != 3 || raw.restored != 3 {
		t.Errorf("raw mode entered %d and restored %d times, want 3 and 3", raw.entered, raw.restored)
	}
}

func TestTerminalPrompter_CtrlCAtAPasswordIsTheAbort(t *testing.T) {
	p, _, raw := testTerminalPrompter("abc\x03")
	if _, err := p.readPassword("Admin password: "); !errors.Is(err, errAborted) {
		t.Errorf("readPassword: %v, want errAborted", err)
	}
	if raw.entered != 1 || raw.restored != 1 {
		t.Errorf("raw mode entered %d and restored %d times, want 1 and 1", raw.entered, raw.restored)
	}
}

// Input that is not a terminal never echoed, so a password is read from it as any line is.
func TestLinePrompter_ReadsAPasswordAsALine(t *testing.T) {
	var out bytes.Buffer
	p := &linePrompter{r: bufio.NewReader(strings.NewReader("piped-Passw0rd\n")), w: &out}
	if got, err := p.readPassword("Admin password: "); err != nil || got != "piped-Passw0rd" {
		t.Errorf("readPassword = %q, %v; want \"piped-Passw0rd\"", got, err)
	}
	if out.String() != "Admin password: " {
		t.Errorf("wrote %q, want the prompt alone", out.String())
	}
}

// A generated default is offered as [generated], never as its value, and taken by an empty answer;
// a typed password is read hidden too (#396 decision 17).
func TestAsker_AGeneratedPasswordIsOfferedWithoutItsValue(t *testing.T) {
	a, in, out := testAsker(t,
		scriptedStep{prompt: "Database password [generated]: ", hidden: true, answer: ""},
		scriptedStep{prompt: "Database password [generated]: ", hidden: true, answer: " typed-Passw0rd "},
	)
	if got, err := a.generatedPassword("Database password", "Zq7GeneratedValue"); err != nil || got != "Zq7GeneratedValue" {
		t.Errorf("generatedPassword = %q, %v; want the generated value for an empty answer", got, err)
	}
	if got, err := a.generatedPassword("Database password", "Zq7GeneratedValue"); err != nil || got != "typed-Passw0rd" {
		t.Errorf("generatedPassword = %q, %v; want the typed one", got, err)
	}
	in.assertConsumed()
	if shown := strings.Join(in.prompts, "") + out.String(); strings.Contains(shown, "Zq7GeneratedValue") {
		t.Errorf("the generated value was shown: %q", shown)
	}
}

// An empty answer takes the generated password, which is shown only as [generated] and not judged:
// it holds no symbol, and a strength check would call it weak (#430). The prompt offered changeme,
// which the docs and the samples print, until the generated default replaced it.
func TestAsker_AnEmptyPasswordAnswerTakesTheGeneratedOneUnjudged(t *testing.T) {
	generated := generatePassword()
	a, in, out := testAsker(t, scriptedStep{prompt: "Password [generated]: ", hidden: true, answer: ""})
	if got, err := a.judgedPassword("Password", generated); err != nil || got != generated {
		t.Errorf("judgedPassword = %q, %v; want the generated %q", got, err, generated)
	}
	in.assertConsumed()
	if strings.Contains(out.String(), "Weak password") {
		t.Errorf("the generated password is judged:\n%s", out.String())
	}
	if strings.Contains(strings.Join(in.prompts, "\n")+out.String(), generated) {
		t.Errorf("the generated password reached the terminal")
	}
}
