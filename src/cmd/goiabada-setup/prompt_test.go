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
// start, and what the read returns.
type scriptedStep struct {
	prompt string
	answer string
	err    error
}

// scriptedPrompter answers the reads of a test in order and fails the test on a read it was not
// scripted for or one asked with another prompt.
type scriptedPrompter struct {
	t     *testing.T
	steps []scriptedStep
}

func (p *scriptedPrompter) readLine(prompt string) (string, error) {
	p.t.Helper()
	if len(p.steps) == 0 {
		p.t.Errorf("read %q with nothing scripted", prompt)
		return "", errReadFault
	}
	step := p.steps[0]
	p.steps = p.steps[1:]
	if !strings.HasPrefix(prompt, step.prompt) {
		p.t.Errorf("read %q, scripted for %q", prompt, step.prompt)
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
		got, err := a.choice("Pick", []string{"1", "2"}, "1")
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
			scriptedStep{prompt: "Password [changeme]: ", answer: ""},
			scriptedStep{prompt: "Use this password anyway? [y/N]: ", err: errReadFault},
		)
		got, err := a.password("Password", "changeme")
		if !errors.Is(err, errReadFault) || got != "" {
			t.Errorf("password = %q, %v; want \"\" and the read fault", got, err)
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
	if got, err := a.choice("Pick", []string{"1", "2"}, "2"); err != nil || got != "2" {
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
	if _, err := a.choice("Pick", []string{"1"}, "1"); !errors.Is(err, errAborted) {
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
	if got, err := a.choice("Pick", []string{"1", "2"}, "1"); err != nil || got != "2" {
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
		scriptedStep{prompt: "Password [changeme]: ", answer: ""},
		scriptedStep{prompt: "Use this password anyway? [y/N]: ", answer: ""},
		scriptedStep{prompt: "Password [changeme]: ", answer: "weak"},
		scriptedStep{prompt: "Use this password anyway? [y/N]: ", answer: "y"},
		scriptedStep{prompt: "Password [changeme]: ", answer: "Str0ng-Passw0rd!"},
	)
	if got, err := a.password("Password", "changeme"); err != nil || got != "weak" {
		t.Errorf("password = %q, %v; want the confirmed \"weak\"", got, err)
	}
	if got, err := a.password("Password", "changeme"); err != nil || got != "Str0ng-Passw0rd!" {
		t.Errorf("password = %q, %v; want the strong one, not asked about", got, err)
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
