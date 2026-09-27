package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// hostileValues is every shape that broke a generated file or changed a value on its way through
// one, each a character or sequence YAML, Compose, a shell or systemd reads as something other
// than itself. They are the 28 values the quoting was designed against and checked on through a
// real Compose container (#430).
var hostileValues = []struct{ name, value string }{
	{"double-quote", `pa"ss`}, {"dollar", `pa$HOME`}, {"dollar-brace", `pa${HOME}ss`},
	{"double-dollar", `pa$$ss`}, {"backslash", `pa\ss`}, {"backslash-n", `pa\nss`},
	{"trailing-backslash", `pass\`}, {"newline", "pa\nss"}, {"crlf", "pa\r\nss"},
	{"tab", "pa\tss"}, {"single-quote", `pa'ss`}, {"colon-space", `pa: ss`},
	{"space-hash", `pa #ss`}, {"leading-star", `*pass`}, {"leading-dash", `- pass`},
	{"backtick", "pa`id`ss"}, {"leading-space", ` pass`}, {"trailing-space", `pass `},
	{"percent", `pa%41ss`}, {"yaml-bool", `yes`}, {"yaml-null", `~`}, {"number", `0123`},
	{"unicode", `pässwörd`}, {"emoji", "pa\U0001F510ss"}, {"u2028", "pa\u2028ss"},
	{"bell", "pa\x07ss"}, {"equals", `a=b=c`}, {"braces", `{a: [b]}`},
}

// yamlScalar decodes quoted as the value of a one-key YAML document, the way a consumer reads it.
func yamlScalar(t *testing.T, quoted string) string {
	t.Helper()
	var doc struct {
		V *string `yaml:"v"`
	}
	if err := yaml.Unmarshal([]byte("v: "+quoted+"\n"), &doc); err != nil {
		t.Fatalf("yaml.v3 refuses %s: %v", quoted, err)
	}
	if doc.V == nil {
		t.Fatalf("yaml.v3 reads %s as null", quoted)
	}
	return *doc.V
}

// composeInterpolate is what Compose does to a value after YAML has read it: `$$` is a literal `$`,
// and any other `$` starts a variable reference (compose-spec, Interpolation). It reports false for
// a value holding such a reference, which Compose would have substituted.
func composeInterpolate(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) || s[i+1] != '$' {
			return "", false
		}
		b.WriteByte('$')
		i++
	}
	return b.String(), true
}

func TestYamlQuote_EveryValueReadsBackThroughYAML(t *testing.T) {
	for _, h := range hostileValues {
		t.Run(h.name, func(t *testing.T) {
			if got := yamlScalar(t, yamlQuote(h.value)); got != h.value {
				t.Errorf("%s reads back as %q, want %q", yamlQuote(h.value), got, h.value)
			}
		})
	}
}

// The characters YAML's printable set leaves out, and the line breaks a YAML 1.1 parser folds,
// are escaped rather than written; everything else is written as it is.
func TestYamlQuote_EscapesWhatYAMLCannotCarryRaw(t *testing.T) {
	cases := map[string]string{
		"plain":          `"plain"`,
		"a\\b\"c":        `"a\\b\"c"`,
		"\n\t\r":         `"\n\t\r"`,
		"\x00\x1b\x7f":   `"\x00\x1B\x7F"`,
		"\u0085\u009f":   `"\u0085\u009F"`,
		"\u2028\u2029":   `"\u2028\u2029"`,
		"\uFEFF\uFFFE":   `"\uFEFF\uFFFE"`,
		"é ü 🔐 \u00A0 '": "\"é ü 🔐 \u00A0 '\"",
	}
	for value, want := range cases {
		if got := yamlQuote(value); got != want {
			t.Errorf("yamlQuote(%q) = %s, want %s", value, got, want)
		}
		if got := yamlScalar(t, yamlQuote(value)); got != value {
			t.Errorf("%s reads back as %q, want %q", yamlQuote(value), got, value)
		}
	}
}

func TestComposeQuote_EveryValueReadsBackThroughYAMLAndInterpolation(t *testing.T) {
	for _, h := range hostileValues {
		t.Run(h.name, func(t *testing.T) {
			scalar := yamlScalar(t, composeQuote(h.value))
			got, ok := composeInterpolate(scalar)
			if !ok {
				t.Fatalf("%s leaves a single $ in %q, which Compose would substitute", composeQuote(h.value), scalar)
			}
			if got != h.value {
				t.Errorf("%s reads back as %q, want %q", composeQuote(h.value), got, h.value)
			}
		})
	}
}

// sourceWithSetA hands content to shell the way the env file's header says to, `set -a` then `.`,
// in an otherwise empty environment, and returns what a child process then receives.
func sourceWithSetA(t *testing.T, shell, content string) map[string]string {
	t.Helper()
	path, err := exec.LookPath(shell)
	if err != nil {
		t.Fatalf("%s is not installed: %v", shell, err)
	}
	file := filepath.Join(t.TempDir(), "goiabada.env")
	if writeErr := os.WriteFile(file, []byte(content), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	cmd := exec.Command(path, "-c", `set -a && . "$1" && set +a && exec env -0`, shell, file)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s could not source the file: %v\n%s", shell, err, stderr.String())
	}
	env := map[string]string{}
	for _, entry := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		name, value, _ := strings.Cut(entry, "=")
		env[name] = value
	}
	return env
}

// posixShells are the shells the env file is read by: bash, and the plain POSIX sh a systemd unit's
// ExecStart or a minimal image has, which is dash on Debian. Neither runs on Windows, where the
// file is not read by a shell either.
func posixShells(t *testing.T) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX shell on Windows; CI and the dev container run this")
	}
	return []string{"bash", "sh"}
}

func TestEnvQuote_EveryValueReadsBackThroughAShell(t *testing.T) {
	var file strings.Builder
	for i, h := range hostileValues {
		fmt.Fprintf(&file, "V%02d=%s\n", i, envQuote(h.value))
	}
	for _, shell := range posixShells(t) {
		t.Run(shell, func(t *testing.T) {
			env := sourceWithSetA(t, shell, file.String())
			for i, h := range hostileValues {
				if got := env[fmt.Sprintf("V%02d", i)]; got != h.value {
					t.Errorf("%s reads back as %q, want %q", h.name, got, h.value)
				}
			}
		})
	}
}

var systemdEnvironmentName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// systemdEnvironmentFile is an emulation, not systemd: it reads an EnvironmentFile= the way
// systemd.exec(5) describes, so the env file's shape can be checked where no systemd runs. Blank
// lines and lines starting with `#` or `;` are ignored; the key is what precedes the `=`, and an
// assignment whose key is not a valid name ([A-Za-z0-9_], env_name_is_valid in systemd's
// env-util.c) is dropped and returned in dropped; a `"`-quoted value can span lines, a `\`
// before any of "\`$ preserves that character, a `\` before a newline joins the lines, and any
// other `\` is kept with what follows it.
func systemdEnvironmentFile(content string) (env map[string]string, dropped []string, err error) {
	env = map[string]string{}
	for len(content) > 0 {
		line, rest, _ := strings.Cut(content, "\n")
		content = rest
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			return nil, nil, fmt.Errorf("no = in %q", line)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimLeft(value, " \t")
		if strings.HasPrefix(value, `"`) {
			// The value may continue on the lines after this one.
			value, content, err = systemdDoubleQuoted(value[1:] + "\n" + content)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
		} else {
			value = strings.TrimSpace(value)
		}
		if !systemdEnvironmentName.MatchString(name) {
			dropped = append(dropped, name)
			continue
		}
		env[name] = value
	}
	return env, dropped, nil
}

// systemdDoubleQuoted reads a double-quoted value from just after its opening quote and returns
// it with the text after the line its closing quote ends.
func systemdDoubleQuoted(s string) (value, rest string, err error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
			switch n := s[i]; n {
			case '"', '\\', '`', '$':
				b.WriteByte(n)
			case '\n':
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
		case c == '"':
			after, rest, _ := strings.Cut(s[i+1:], "\n")
			if strings.TrimSpace(after) != "" {
				return "", "", fmt.Errorf("text after the closing quote: %q", after)
			}
			return b.String(), rest, nil
		default:
			b.WriteByte(c)
		}
	}
	return "", "", fmt.Errorf("no closing quote")
}

func TestEnvQuote_EveryValueReadsBackThroughTheSystemdRule(t *testing.T) {
	var file strings.Builder
	for i, h := range hostileValues {
		fmt.Fprintf(&file, "V%02d=%s\n", i, envQuote(h.value))
	}
	env, dropped, err := systemdEnvironmentFile(file.String())
	if err != nil {
		t.Fatalf("the emulation cannot read the file: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped %v", dropped)
	}
	for i, h := range hostileValues {
		if got := env[fmt.Sprintf("V%02d", i)]; got != h.value {
			t.Errorf("%s reads back as %q, want %q", h.name, got, h.value)
		}
	}
}

// The emulation drops what systemd drops: without this, a reading that kept `export KEY` would let
// the env file's shape test pass against the file that lost every line.
func TestSystemdEnvironmentFile_DropsAnExportedAssignment(t *testing.T) {
	env, dropped, err := systemdEnvironmentFile("# comment\n\nexport A=\"1\"\nB=\"2\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != "export A" || len(env) != 1 || env["B"] != "2" {
		t.Errorf("read %v, dropped %q; want only B, and \"export A\" dropped", env, dropped)
	}
}

func TestCheckWritable(t *testing.T) {
	for _, h := range hostileValues {
		if err := checkWritable(h.value); err != nil {
			t.Errorf("%s is refused: %v", h.name, err)
		}
	}
	refused := map[string]string{
		"a lone continuation byte": "pa\x80ss",
		"a truncated sequence":     "pa\xc3",
		"an invalid byte":          "\xff",
		"an encoded surrogate":     "pa\xed\xa0\x80ss",
		"an overlong encoding":     "pa\xc0\xafss",
	}
	for name, value := range refused {
		if err := checkWritable(value); err == nil || err.Error() != "it is not valid UTF-8" {
			t.Errorf("%s: %v, want it refused as not UTF-8", name, err)
		}
	}
	for _, value := range []string{"\x00", "pa\x00ss", "pass\x00"} {
		if err := checkWritable(value); err == nil || err.Error() != "it contains a NUL character" {
			t.Errorf("%q: %v, want it refused for its NUL", value, err)
		}
	}
}
