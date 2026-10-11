package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/leodip/goiabada/core/adminpassword"
	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/term"
)

// errAborted is the operator ending the wizard: Ctrl-C, Ctrl-D at an empty line, the end of the
// input, "Abort setup" or declining the final confirmation. main answers it with "Aborted." and
// exit 0, and nothing is written.
var errAborted = errors.New("aborted")

// prompter reads one answer. A read that fails for any reason but the operator ending the wizard
// returns that failure, never an answer: the prompts built on it would otherwise take their default,
// and a fault at "Generate configuration files?" would approve the write (#430). readPassword reads
// a password, which a terminal neither echoes nor keeps in its line history, so it reaches neither
// the screen, its scrollback and recordings, nor the up arrow at a later prompt (#396 decision 17).
type prompter interface {
	readLine(prompt string) (string, error)
	readPassword(prompt string) (string, error)
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
// reads, but for a password, which it neither echoes nor keeps. term.Terminal needs raw mode, and
// raw mode stops the terminal turning "\n" into "\r\n", which everything else the wizard prints
// relies on, so raw mode is entered for each read and restored before the read returns rather than
// held across the wizard (#430).
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
func (p *terminalPrompter) readLine(prompt string) (string, error) {
	return p.read(prompt, p.t.ReadLine)
}

// readPassword reads through term.Terminal's password read, which echoes nothing and adds nothing
// to the history.
func (p *terminalPrompter) readPassword(prompt string) (string, error) {
	return p.read(prompt, func() (string, error) { return p.t.ReadPassword(prompt) })
}

// read runs one of term.Terminal's reads in raw mode, with prompt set for the line read, which takes
// it from the terminal; the password read takes its own.
func (p *terminalPrompter) read(prompt string, read func() (string, error)) (line string, err error) {
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
	line, err = read()
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

// readPassword reads a line: input that is not a terminal never echoed, and keeps no history.
func (p *linePrompter) readPassword(prompt string) (string, error) {
	return p.readLine(prompt)
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
	return a.ask(a.in.readLine, prompt, defaultValue, defaultValue)
}

// hidden is text read as a password, offering the default under shown, which a generated default
// is never shown as.
func (a asker) hidden(prompt, defaultValue, shown string) (string, error) {
	return a.ask(a.in.readPassword, prompt, defaultValue, shown)
}

// ask reads with read until the answer is one a generated file can carry, prompting with the
// default shown as shown, and returns the default for an empty answer.
func (a asker) ask(read func(prompt string) (string, error), prompt, defaultValue, shown string) (string, error) {
	promptStr := prompt + ": "
	if shown != "" {
		promptStr = prompt + " [" + shown + "]: "
	}
	for {
		input, err := read(promptStr)
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
	return a.choiceOffering(prompt, validChoices, validChoices[0])
}

// choiceOffering asks until the answer is one of validChoices, offering defaultChoice.
func (a asker) choiceOffering(prompt string, validChoices []string, defaultChoice string) (string, error) {
	for {
		input, err := a.text(prompt, defaultChoice)
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

// generatedPassword asks for a password read hidden, offering one generated as [generated] and never
// as itself (#396 decision 17).
func (a asker) generatedPassword(prompt, generated string) (string, error) {
	return a.hidden(prompt, generated, "generated")
}

// adminPassword asks for the first administrator's password read hidden, offering one generated as
// generatedPassword does, and judges one typed instead. One the first start refuses to seed is
// refused here with its reason and asked again, with no "use anyway": the wizard must not write a
// configuration whose first start is refused (#500). Above that floor, weak character classes are
// the operator's call. The generated one is not judged: it holds the classes SQL Server asks for and
// no symbol, and was warned about as weak (#430).
func (a asker) adminPassword(prompt, generated string) (string, error) {
	for {
		value, err := a.generatedPassword(prompt, generated)
		if err != nil {
			return "", err
		}
		if value == generated {
			return value, nil
		}
		if refused := adminpassword.Check(value); refused != nil {
			a.out.printf("Invalid admin password: %s. Please try again.\n", refused)
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
