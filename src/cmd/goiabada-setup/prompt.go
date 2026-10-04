package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/term"
)

// errAborted is the operator ending the wizard: Ctrl-C, Ctrl-D at an empty line, the end of the
// input, "Abort setup" or declining the final confirmation. main answers it with "Aborted." and
// exit 0, and nothing is written.
var errAborted = errors.New("aborted")

// prompter reads one answer. A read that fails for any reason but the operator ending the wizard
// returns that failure, never an answer: the prompts built on it would otherwise take their default,
// and a fault at "Generate configuration files?" would approve the write (#430).
type prompter interface {
	readLine(prompt string) (string, error)
}

// newPrompter reads from a terminal through x/term, which edits the line and keeps its history,
// and from anything else, a pipe or CI, line by line, since a pipe cannot be put into raw mode.
func newPrompter(stdin *os.File, stdout io.Writer) prompter {
	fd := int(stdin.Fd())
	if term.IsTerminal(fd) {
		return newTerminalPrompter(fd, struct {
			io.Reader
			io.Writer
		}{stdin, stdout})
	}
	return &linePrompter{r: bufio.NewReader(stdin), w: stdout}
}

// terminalPrompter reads through term.Terminal, which echoes, edits and keeps a history of what it
// reads. term.Terminal needs raw mode, and raw mode stops the terminal turning "\n" into "\r\n",
// which everything else the wizard prints relies on, so raw mode is entered for each read and
// restored before the read returns rather than held across the wizard (#430).
type terminalPrompter struct {
	t *term.Terminal
	// enter puts the terminal into raw mode and returns what puts it back.
	enter func() (restore func() error, err error)
	// size is the window's, read before each read so a resized window still wraps where it ends.
	size func() (width, height int, err error)
}

func newTerminalPrompter(fd int, rw io.ReadWriter) *terminalPrompter {
	return &terminalPrompter{
		t: term.NewTerminal(rw, ""),
		enter: func() (func() error, error) {
			state, err := term.MakeRaw(fd)
			if err != nil {
				return nil, err
			}
			return func() error { return term.Restore(fd, state) }, nil
		},
		size: func() (int, int, error) { return term.GetSize(fd) },
	}
}

// readLine answers errAborted for io.EOF, which term.Terminal returns for Ctrl-C, for Ctrl-D at an
// empty line and for the end of the input alike.
func (p *terminalPrompter) readLine(prompt string) (line string, err error) {
	restore, err := p.enter()
	if err != nil {
		return "", errs.Wrap(err, "unable to put the terminal into raw mode")
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil && err == nil {
			err = errs.Wrap(restoreErr, "unable to restore the terminal")
		}
	}()
	if width, height, sizeErr := p.size(); sizeErr == nil {
		_ = p.t.SetSize(width, height)
	}
	p.t.SetPrompt(prompt)
	line, err = p.t.ReadLine()
	if errors.Is(err, io.EOF) {
		return "", errAborted
	}
	if err != nil {
		return "", errs.Wrap(err, "unable to read the answer")
	}
	return line, nil
}

// linePrompter reads lines from input that is not a terminal. The end of the input is the abort,
// as it is at a terminal; a last line with no newline is still an answer.
type linePrompter struct {
	r *bufio.Reader
	w io.Writer
}

func (p *linePrompter) readLine(prompt string) (string, error) {
	_, _ = io.WriteString(p.w, prompt)
	line, err := p.r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errs.Wrap(err, "unable to read the answer")
	}
	if err != nil && line == "" {
		return "", errAborted
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

// asker is the typed prompts, over a prompter and the console their complaints are written to.
// Each returns its default only for an empty answer that was read, and a read's failure as it is.
type asker struct {
	in  prompter
	out *console
}

// text asks again for an answer no generated file could carry (checkWritable), which only input
// that is not a terminal can hold: term.Terminal drops control keys and decodes what it reads.
func (a asker) text(prompt, defaultValue string) (string, error) {
	promptStr := prompt + ": "
	if defaultValue != "" {
		promptStr = prompt + " [" + defaultValue + "]: "
	}
	for {
		input, err := a.in.readLine(promptStr)
		if err != nil {
			return "", err
		}
		if unwritable := checkWritable(input); unwritable != nil {
			a.out.printf("This answer cannot be written to the configuration: %s. Please try again.\n", unwritable)
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return defaultValue, nil
		}
		return input, nil
	}
}

// choice asks until the answer is one of validChoices, offering the first as the default.
func (a asker) choice(prompt string, validChoices []string) (string, error) {
	for {
		input, err := a.text(prompt, validChoices[0])
		if err != nil {
			return "", err
		}
		for _, valid := range validChoices {
			if input == valid {
				return input, nil
			}
		}
		a.out.println("Invalid choice. Please try again.")
	}
}

func (a asker) yesNo(prompt string, defaultYes bool) (bool, error) {
	defaultStr := "Y/n"
	if !defaultYes {
		defaultStr = "y/N"
	}
	for {
		input, err := a.in.readLine(prompt + " [" + defaultStr + "]: ")
		if err != nil {
			return false, err
		}
		switch strings.TrimSpace(strings.ToLower(input)) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		a.out.println("Please enter 'y' or 'n'.")
	}
}

// validated asks until the answer passes validate, naming what was invalid.
func (a asker) validated(prompt, defaultValue, what string, validate func(string) error) (string, error) {
	for {
		value, err := a.text(prompt, defaultValue)
		if err != nil {
			return "", err
		}
		invalid := validate(value)
		if invalid == nil {
			return value, nil
		}
		a.out.printf("Invalid %s: %s. Please try again.\n", what, invalid)
	}
}

func (a asker) email(prompt, defaultValue string) (string, error) {
	return a.validated(prompt, defaultValue, "email", validateEmail)
}

func (a asker) databaseHost(prompt, defaultValue string) (string, error) {
	return a.validated(prompt, defaultValue, "database host", validateDatabaseHost)
}

func (a asker) port(prompt, defaultValue string) (string, error) {
	return a.validated(prompt, defaultValue, "port", validatePort)
}

func (a asker) namespace(prompt, defaultValue string) (string, error) {
	return a.validated(prompt, defaultValue, "namespace", validateNamespace)
}

func (a asker) databaseName(prompt, defaultValue string) (string, error) {
	return a.validated(prompt, defaultValue, "database name", validateDatabaseName)
}

func (a asker) nonEmpty(prompt, defaultValue string) (string, error) {
	for {
		value, err := a.text(prompt, defaultValue)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
		a.out.println("This field cannot be empty. Please try again.")
	}
}

func (a asker) password(prompt, defaultValue string) (string, error) {
	for {
		value, err := a.text(prompt, defaultValue)
		if err != nil {
			return "", err
		}
		if value == "" {
			a.out.println("Password cannot be empty. Please try again.")
			continue
		}
		if issues := checkPasswordStrength(value); len(issues) > 0 {
			a.out.warning("Weak password: %s", strings.Join(issues, ", "))
			useAnyway, askErr := a.yesNo("Use this password anyway?", false)
			if askErr != nil {
				return "", askErr
			}
			if !useAnyway {
				continue
			}
		}
		return value, nil
	}
}
