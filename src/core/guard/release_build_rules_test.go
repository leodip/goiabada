package guard

// Rule 9 reads every shipped main the way its release build compiles it: the production tag set and
// every other tag free, on each of releaseTargets. Both halves of that are a premise about files the
// guard never opens, the scripts and Dockerfiles a release builds with, so this test opens them: every
// go build in them sets production, and each cross-compile script builds for exactly the platforms
// releaseTargets lists (#463). It also reads every -X target their go builds pass the linker, and
// holds each to naming a package-level string variable, because the linker ignores one that names
// nothing and the binary ships reporting "development" (#442).
//
// It is a test rather than a finding inside AssertArchitecture, so core's tier is the one that runs
// it; CI's Unit job runs that tier on every pull request. The reader is driven over fixture text in
// both directions and through a file holding no go build before the real tree is trusted to it,
// because the real tree satisfies it by construction and passing proves nothing on its own.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/internal/refgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// releaseBuild is one file a release builds with, relative to the source root: the shipped mains its
// go build commands compile, and whether it is a cross-compile script, whose build_platform calls are
// held to releaseTargets.
type releaseBuild struct {
	file      string
	mains     []string
	platforms bool
}

// releaseBuilds are the files release.yml builds every shipped binary with: the servers'
// cross-compile script and the two Dockerfiles the published images are built from, and the setup
// wizard's cross-compile script. The mains are spelled out rather than read from shippedMains, so
// that a fourth shipped main fails this test until its release build is listed here.
var releaseBuilds = []releaseBuild{
	{file: "build/build-binaries.sh", mains: []string{authserverMain, adminconsoleMain}, platforms: true},
	{file: "build/Dockerfile-authserver", mains: []string{authserverMain}},
	{file: "build/Dockerfile-adminconsole", mains: []string{adminconsoleMain}},
	{file: "cmd/goiabada-setup/build-binaries.sh", mains: []string{setupMain}, platforms: true},
}

// The reader below reads a release-build file the way the shell would run it, as far as it goes:
// quoting, expansions, comments, continued lines and the operators that end one command and begin
// the next, wherever they are spaced. Only what it reads as a command counts, so a go build or a
// build_platform call is one only where it is the command's name; and a form it cannot read, from
// an unclosed quote to a mention of go build in a string or behind echo, is reported rather than
// passed over, since reading less than the shell would is how an untagged build slips through.

// shellWord is one word of a command: its text as written, its text with the quotes removed and every
// expansion left as written, the line it begins on, whether it holds an expansion, and whether one
// stands outside quotes, where the shell would split its result into more words.
type shellWord struct {
	raw, value      string
	line            int
	expands, splits bool
}

// shellCommand is one simple command: the assignments before it, then its words, the first being its
// name. logical counts the logical lines before it, and defines marks a function definition, name().
type shellCommand struct {
	line, logical int
	assigns       []shellWord
	words         []shellWord
	defines       bool
}

// shellProblem is a form the reader cannot read, at the line it begins on.
type shellProblem struct {
	line int
	what string
}

// shellScript is a script or Dockerfile read into its commands, and its text without the comments,
// where a mention no command accounts for is looked for. When problems holds anything, the reading
// stopped there and the rest is empty.
type shellScript struct {
	commands []shellCommand
	bare     string
	problems []shellProblem
}

var (
	// assignment is a word assigning a variable, and arrayAssignment one about to assign an array.
	assignment      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)
	arrayAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=$`)

	// commandPrefixes are the reserved words a command may follow: in if go build ...; then, the
	// command is go build.
	commandPrefixes = wordSet("!", "{", "if", "then", "elif", "else", "while", "until", "do")

	doubleQuoteEscapes = strings.NewReplacer("\\\n", "", `\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`")

	// goBuildMention and buildPlatformMention find the two names wherever they are written, a JSON
	// RUN ["go", "build"] included, for the reader to compare with the commands it read.
	goBuildMention       = regexp.MustCompile(`\bgo["'\s\\,]+build\b`)
	buildPlatformMention = regexp.MustCompile(`\bbuild_platform\b`)
)

type shellReader struct {
	src      string
	i, line  int
	logical  int
	words    []shellWord
	commands []shellCommand
	problems []shellProblem
}

// readShell reads a script into its commands. A Dockerfile's RUN hands the rest of its line to the
// shell, so the one reading serves both.
func readShell(src string) shellScript {
	r := &shellReader{src: src, line: 1}
	var bare strings.Builder
	last := 0
	for r.i < len(src) {
		c := src[r.i]
		switch {
		case strings.HasPrefix(src[r.i:], "\\\n"):
			r.advance(r.i + 2)
		case c == ' ' || c == '\t' || c == '\r':
			r.i++
		case c == '\n':
			r.end(false)
			r.logical++
			r.advance(r.i + 1)
		case c == '#':
			end := strings.IndexByte(src[r.i:], '\n')
			if end < 0 {
				end = len(src) - r.i
			}
			bare.WriteString(src[last:r.i])
			last = r.i + end
			r.i += end
		case c == '(':
			r.i++
			rest := strings.TrimLeft(src[r.i:], " \t")
			defines := len(r.words) == 1 && strings.HasPrefix(rest, ")")
			if defines {
				r.i = len(src) - len(rest) + 1
			}
			r.end(defines)
		case strings.IndexByte(";&|)", c) >= 0:
			r.i++
			r.end(false)
		default:
			if !r.word() {
				return shellScript{problems: r.problems}
			}
		}
	}
	r.end(false)
	bare.WriteString(src[last:])
	return shellScript{commands: r.commands, bare: bare.String()}
}

func (r *shellReader) advance(to int) {
	r.line += strings.Count(r.src[r.i:to], "\n")
	r.i = to
}

// word reads one word, and reports false when it holds a form the reader cannot read.
func (r *shellReader) word() bool {
	w := shellWord{line: r.line}
	start := r.i
	var value strings.Builder
read:
	for r.i < len(r.src) {
		c := r.src[r.i]
		switch {
		case c == '\\' && r.i+1 < len(r.src):
			if r.src[r.i+1] != '\n' {
				value.WriteByte(r.src[r.i+1])
			}
			r.advance(r.i + 2)
			continue
		case c == '\'' || c == '"' || isExpansionStart(r.src, r.i) || c == '(' && arrayAssignment.MatchString(r.src[start:r.i]):
			end, ok := skipConstruct(r.src, r.i)
			if !ok {
				opening := r.src[r.i : r.i+1]
				if c == '$' {
					opening = r.src[r.i : r.i+2]
				}
				r.problems = append(r.problems, shellProblem{r.line, fmt.Sprintf("opens a %s that never closes", opening)})
				return false
			}
			content := r.src[r.i:end]
			switch c {
			case '\'':
				value.WriteString(content[1 : len(content)-1])
			case '"':
				value.WriteString(doubleQuoteEscapes.Replace(content[1 : len(content)-1]))
			default:
				value.WriteString(content)
			}
			w.expands = w.expands || c == '$' || c == '`' || c != '\'' && strings.ContainsAny(content, "$`")
			w.splits = w.splits || c == '$' || c == '`'
			r.advance(end)
			continue
		case c == '$':
			w.expands, w.splits = true, true
		case c == '&' && r.i > start && (r.src[r.i-1] == '>' || r.src[r.i-1] == '<'):
			// a redirection, >&2, and not an operator
		case strings.IndexByte(" \t\r\n;&|()", c) >= 0:
			break read
		}
		value.WriteByte(c)
		r.i++
	}
	w.raw, w.value = r.src[start:r.i], value.String()
	if strings.HasPrefix(w.raw, "<<") && !strings.HasPrefix(w.raw, "<<<") {
		r.problems = append(r.problems, shellProblem{w.line, "opens a heredoc, whose lines this reader cannot tell from commands"})
		return false
	}
	r.words = append(r.words, w)
	return true
}

// end closes the command being read, if there is one.
func (r *shellReader) end(defines bool) {
	words := r.words
	r.words = nil
	if len(words) > 0 && words[0].raw == "RUN" {
		words = words[1:]
	}
	for len(words) > 0 && commandPrefixes[words[0].raw] {
		words = words[1:]
	}
	if len(words) == 0 {
		return
	}
	c := shellCommand{line: words[0].line, logical: r.logical, defines: defines}
	for len(words) > 0 && assignment.MatchString(words[0].raw) {
		c.assigns = append(c.assigns, words[0])
		words = words[1:]
	}
	c.words = words
	r.commands = append(r.commands, c)
}

func isExpansionStart(src string, i int) bool {
	return src[i] == '`' || src[i] == '$' && i+1 < len(src) && (src[i+1] == '(' || src[i+1] == '{')
}

// skipConstruct returns the index just past the quoted string, expansion or array that begins at i,
// '…', "…", `…`, $(…), ${…} or (…), stepping over whatever nests inside it, and false when it never
// closes.
func skipConstruct(src string, i int) (int, bool) {
	switch src[i] {
	case '\'', '`':
		end := strings.IndexByte(src[i+1:], src[i])
		return i + end + 2, end >= 0
	case '"':
		for j := i + 1; j < len(src); {
			switch {
			case src[j] == '\\':
				j += 2
			case src[j] == '"':
				return j + 1, true
			case isExpansionStart(src, j):
				end, ok := skipConstruct(src, j)
				if !ok {
					return 0, false
				}
				j = end
			default:
				j++
			}
		}
		return 0, false
	}
	b := i
	if src[i] == '$' {
		b = i + 1
	}
	open, closer := src[b], byte(')')
	if open == '{' {
		closer = '}'
	}
	depth := 0
	for j := b; j < len(src); {
		switch c := src[j]; {
		case c == '\\':
			j += 2
		case c == '\'' || c == '"' || isExpansionStart(src, j):
			end, ok := skipConstruct(src, j)
			if !ok {
				return 0, false
			}
			j = end
		case c == open:
			depth++
			j++
		case c == closer:
			depth--
			j++
			if depth == 0 {
				return j, true
			}
		default:
			j++
		}
	}
	return 0, false
}

// unaccounted returns the line of every match of pattern in the script's text that no command
// accounts for, given the lines of the names of the commands that do.
func (s shellScript) unaccounted(pattern *regexp.Regexp, accounted []int) []int {
	left := map[int]int{}
	for _, l := range accounted {
		left[l]++
	}
	var out []int
	for _, m := range pattern.FindAllStringIndex(s.bare, -1) {
		line := 1 + strings.Count(s.bare[:m[0]], "\n")
		if left[line] > 0 {
			left[line]--
			continue
		}
		out = append(out, line)
	}
	return out
}

func isGoBuild(c shellCommand) bool {
	return len(c.words) >= 2 && c.words[0].value == "go" && c.words[1].value == "build"
}

// goBuild is one go build command found in a release-build file: the line it starts on, whether it
// sets the production tag, and why its flags cannot be read, when they cannot.
type goBuild struct {
	line       int
	production bool
	unreadable string
}

// readReleaseText reads a release-build file: its go build commands in order, the "goos/goarch"
// pairs its build_platform calls name, sorted and without repeats, and every form in it the reader
// cannot read. The function's own definition is not a call, however it is spaced.
func readReleaseText(text string) ([]goBuild, []string, []shellProblem) {
	s := readShell(text)
	if len(s.problems) > 0 {
		return nil, nil, s.problems
	}
	var builds []goBuild
	var problems []shellProblem
	var buildLines, platformLines []int
	platforms := map[string]bool{}
	for _, c := range s.commands {
		if len(c.words) == 0 {
			continue
		}
		name := c.words[0]
		switch {
		case name.expands || name.value == "go" && len(c.words) > 1 && c.words[1].expands:
			problems = append(problems, shellProblem{c.line, "runs a command named through an expansion"})
		case isGoBuild(c):
			buildLines = append(buildLines, name.line)
			production, unreadable := readBuildFlags(c.words[2:])
			builds = append(builds, goBuild{line: c.line, production: production, unreadable: unreadable})
		case name.value == "build_platform":
			platformLines = append(platformLines, name.line)
			if c.defines {
				continue
			}
			args := c.words[1:]
			if len(args) != 3 || args[0].expands || args[1].expands || args[2].expands {
				problems = append(problems, shellProblem{c.line, "calls build_platform with arguments other than three literal words"})
				continue
			}
			platforms[args[0].value+"/"+args[1].value] = true
		}
	}
	for _, l := range s.unaccounted(goBuildMention, buildLines) {
		problems = append(problems, shellProblem{l, "mentions go build where no go build command runs"})
	}
	for _, l := range s.unaccounted(buildPlatformMention, platformLines) {
		problems = append(problems, shellProblem{l, "mentions build_platform where it is neither called nor defined"})
	}
	sort.SliceStable(problems, func(i, j int) bool { return problems[i].line < problems[j].line })
	return builds, sortedKeys(platforms), problems
}

// goBuildValueFlags are the go build flags taking a value, which may be the next argument, and
// goBuildBoolFlags the ones taking none. A flag in neither cannot be read: whether it takes the next
// argument decides what that argument is.
var (
	goBuildValueFlags = wordSet("C", "o", "p", "asmflags", "buildmode", "compiler", "covermode", "coverpkg",
		"debug-actiongraph", "debug-runtime-trace", "debug-trace", "gccgoflags", "gcflags", "installsuffix",
		"ldflags", "mod", "modfile", "overlay", "pgo", "pkgdir", "tags", "toolexec")
	goBuildBoolFlags = wordSet("a", "asan", "buildvcs", "cover", "json", "linkshared", "modcacherw", "msan",
		"n", "race", "trimpath", "v", "work", "x")
)

func wordSet(words ...string) map[string]bool {
	set := map[string]bool{}
	for _, w := range words {
		set[w] = true
	}
	return set
}

// buildFlag is one flag a go build is given: its name without dashes, its value, and whether the
// word holding that value expands.
type buildFlag struct {
	name, value string
	expands     bool
}

// readGoBuildArgs reads a go build's arguments into its flags, which end at its first argument that
// is not one, and the arguments after them, or reports why they cannot be read. A word beginning
// with an expansion, quoted or not, can begin with a dash once expanded, "$FLAGS" or "${FLAGS[@]}"
// holding -tags=dev, so where a flag could be it cannot be read; as a flag's value, the next word -o
// or -ldflags consumes, it can.
func readGoBuildArgs(args []shellWord) ([]buildFlag, []shellWord, string) {
	var flags []buildFlag
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a.splits {
			return nil, nil, a.raw + " is an unquoted expansion"
		}
		if a.expands && (strings.HasPrefix(a.value, "$") || strings.HasPrefix(a.value, "`")) {
			return nil, nil, a.raw + " is an expansion that could supply a flag"
		}
		if a.value == "--" {
			return flags, args[i+1:], ""
		}
		if !strings.HasPrefix(a.value, "-") {
			return flags, args[i:], ""
		}
		name, value, hasValue := strings.Cut(strings.TrimPrefix(a.value[1:], "-"), "=")
		expands := a.expands
		switch {
		case goBuildValueFlags[name] && !hasValue:
			if i+1 == len(args) {
				return nil, nil, a.raw + " has no value"
			}
			i++
			if args[i].splits {
				return nil, nil, args[i].raw + " is an unquoted expansion"
			}
			value, expands = args[i].value, args[i].expands
		case !hasValue && !goBuildBoolFlags[name]:
			return nil, nil, a.raw + " is a flag it does not know"
		}
		flags = append(flags, buildFlag{name: name, value: value, expands: expands})
	}
	return flags, nil, ""
}

// readBuildFlags reads a go build's flags and reports whether they set the production tag, or why
// they cannot be read. The go command keeps the last -tags it is given, so the last one is the one
// read.
func readBuildFlags(args []shellWord) (bool, string) {
	flags, _, unreadable := readGoBuildArgs(args)
	if unreadable != "" {
		return false, unreadable
	}
	tags := ""
	for _, f := range flags {
		if f.name != "tags" {
			continue
		}
		if strings.ContainsAny(f.value, "$`") {
			return false, "-tags takes its value from an expansion"
		}
		tags = f.value
	}
	for _, tag := range strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || r == ' ' }) {
		if tag == "production" {
			return true, ""
		}
	}
	return false, ""
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The linker ignores an -X whose variable does not exist: go build exits 0, and the binary reports
// whatever the declaration says, "development" for the build stamp. A path a package move leaves
// behind therefore ships mislabelled releases with every tier green, so every -X target a release
// build passes is held to naming a package-level string variable the tree declares (#442).

// stampTarget is one -X target a go build in a release-build file passes the linker: the line the
// go build starts on, the target as written, importpath.name, and the go build's first package
// argument, which says which main a main. target means.
type stampTarget struct {
	line   int
	target string
	pkgArg string
}

var (
	// shellVariableReference is an -ldflags value that is one variable's expansion and nothing else,
	// "$LDFLAGS" or "${LDFLAGS}".
	shellVariableReference = regexp.MustCompile(`^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$`)

	// linkerBoolFlags are the linker flags taking no value. -X is the one flag taking a value that
	// is read; a flag in neither cannot be read, since whether it takes the next field decides what
	// that field is.
	linkerBoolFlags = wordSet("s", "w")
)

// readStampTargets reads every -X target the go build commands in a release-build file pass the
// linker, and every -ldflags it cannot read. A file, or a go build, whose flags readReleaseText
// cannot read yields nothing here, since that is already its finding. An -ldflags value that is one
// variable's expansion, as in the servers' script, is read from that variable's assignment.
func readStampTargets(text string) ([]stampTarget, []shellProblem) {
	s := readShell(text)
	if len(s.problems) > 0 {
		return nil, nil
	}
	variables := plainShellVariables(s.commands)
	var targets []stampTarget
	var problems []shellProblem
	for _, c := range s.commands {
		if !isGoBuild(c) {
			continue
		}
		flags, packages, unreadable := readGoBuildArgs(c.words[2:])
		if unreadable != "" {
			continue
		}
		pkgArg := ""
		if len(packages) > 0 {
			pkgArg = packages[0].value
		}
		for _, f := range flags {
			if f.name != "ldflags" {
				continue
			}
			value := f.value
			if m := shellVariableReference.FindStringSubmatch(value); f.expands && m != nil {
				name := m[1] + m[2]
				assigned, ok := variables[name]
				if !ok {
					problems = append(problems, shellProblem{c.line, fmt.Sprintf("-ldflags takes its value from $%s, which is not assigned exactly once by a plain assignment", name)})
					continue
				}
				value = assigned
			}
			stamps, why := readLinkerStamps(value)
			if why != "" {
				problems = append(problems, shellProblem{c.line, "passes -ldflags this reader cannot read: " + why})
				continue
			}
			for _, target := range stamps {
				targets = append(targets, stampTarget{line: c.line, target: target, pkgArg: pkgArg})
			}
		}
	}
	return targets, problems
}

// plainShellVariables returns the value of every variable a script assigns exactly once, by an
// assignment that is a command of its own, and names in no word of any command. Anything else has
// no one value the reader can stand behind: an assignment before a command sets the variable for
// that command alone, a function call included, a += appends, and a word naming it, as local,
// export, read or for do, may be setting it again.
func plainShellVariables(commands []shellCommand) map[string]string {
	type variable struct {
		value       string
		plain       bool
		assignments int
	}
	seen := map[string]*variable{}
	note := func(name string) *variable {
		if seen[name] == nil {
			seen[name] = &variable{}
		}
		return seen[name]
	}
	for _, c := range commands {
		for _, a := range c.assigns {
			name, value, _ := strings.Cut(a.value, "=")
			v := note(strings.TrimSuffix(name, "+"))
			v.assignments++
			v.value, v.plain = value, len(c.words) == 0 && !strings.HasSuffix(name, "+")
		}
		for _, w := range c.words {
			name, _, _ := strings.Cut(w.value, "=")
			note(strings.TrimSuffix(name, "+")).assignments++
		}
	}
	values := map[string]string{}
	for name, v := range seen {
		if v.assignments == 1 && v.plain {
			values[name] = v.value
		}
	}
	return values
}

// readLinkerStamps reads an -ldflags value the way the go command and the linker do, and returns
// its -X targets, or why it cannot be read. A value not beginning with a dash is pattern=flags, the
// flags applying to the packages the pattern matches. The linker reads -X's value as
// importpath.name=value, the target ending at the first equals sign and its package at the last dot
// before that.
func readLinkerStamps(value string) ([]string, string) {
	flags := strings.TrimSpace(value)
	if flags != "" && flags[0] != '-' {
		_, after, ok := strings.Cut(flags, "=")
		if !ok {
			return nil, flags + " is neither linker flags nor pattern=flags"
		}
		flags = after
	}
	fields, why := splitGoFlags(flags)
	if why != "" {
		return nil, why
	}
	var targets []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if !strings.HasPrefix(f, "-") || f == "-" || f == "--" {
			if strings.HasPrefix(f, "$") || strings.HasPrefix(f, "`") {
				return nil, f + " is an expansion that could supply a linker flag"
			}
			return nil, f + " is not a linker flag"
		}
		name, x, hasValue := strings.Cut(strings.TrimPrefix(f[1:], "-"), "=")
		switch {
		case name == "X":
			if !hasValue {
				if i+1 == len(fields) {
					return nil, f + " has no value"
				}
				i++
				x = fields[i]
			}
			target, _, ok := strings.Cut(x, "=")
			if !ok || !strings.Contains(target, ".") {
				return nil, "-X " + x + " is not importpath.name=value"
			}
			if strings.ContainsAny(target, "$`") {
				return nil, "-X " + x + " takes its path from an expansion"
			}
			targets = append(targets, target)
		case !linkerBoolFlags[name]:
			return nil, f + " is a linker flag it does not know"
		}
	}
	return targets, ""
}

// splitGoFlags splits a flag string into fields the way the go command does, which is not the way
// the shell does: fields end at spaces, a field beginning with a quote runs to the next same quote
// with nothing escaped inside, and a quote anywhere else is an ordinary character.
func splitGoFlags(s string) ([]string, string) {
	var fields []string
	for {
		s = strings.TrimLeft(s, " \t\n\r")
		if s == "" {
			return fields, ""
		}
		if q := s[0]; q == '\'' || q == '"' {
			end := strings.IndexByte(s[1:], q)
			if end < 0 {
				return nil, "it opens a " + string(q) + " that never closes"
			}
			fields = append(fields, s[1:1+end])
			s = s[2+end:]
			continue
		}
		end := strings.IndexAny(s, " \t\n\r")
		if end < 0 {
			end = len(s)
		}
		fields = append(fields, s[:end])
		s = s[end:]
	}
}

// stampVariable is what a package declares under the name an -X target gives.
type stampVariable int

const (
	stampable stampVariable = iota
	noStringVariable
	computedVariable
)

// readStampVariable reads what the package in dir, as a production build compiles it, declares
// under name: a package-level variable -X can set, declared string or with no type and a value of
// string literals, and with no value or such a value; one whose initializer is anything else, which
// the linker leaves to compute what it computes; or no package-level string variable at all.
func readStampVariable(root, dir, name string) stampVariable {
	full := filepath.Join(root, filepath.FromSlash(dir))
	entries, err := os.ReadDir(full)
	if err != nil {
		return noStringVariable
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(full, e.Name()), nil, parser.ParseComments)
		if err != nil || refgraph.ExemptByBuildConstraint(file, fset) {
			continue
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				v := spec.(*ast.ValueSpec)
				for i, n := range v.Names {
					if n.Name == name {
						return readStampSpec(v, i)
					}
				}
			}
		}
	}
	return noStringVariable
}

// readStampSpec reads the i-th variable a var spec declares.
func readStampSpec(v *ast.ValueSpec, i int) stampVariable {
	if v.Type != nil {
		if ident, ok := v.Type.(*ast.Ident); !ok || ident.Name != "string" {
			return noStringVariable
		}
	}
	switch {
	case len(v.Values) == 0:
		return stampable
	case len(v.Values) != len(v.Names):
		return computedVariable
	case isStringLiterals(v.Values[i]):
		return stampable
	}
	if lit, ok := v.Values[i].(*ast.BasicLit); ok && v.Type == nil && lit.Kind != token.STRING {
		return noStringVariable
	}
	return computedVariable
}

// isStringLiterals reports whether an expression is string literals joined by +, which the compiler
// lays down as data the linker can replace.
func isStringLiterals(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.ParenExpr:
		return isStringLiterals(e.X)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && isStringLiterals(e.X) && isStringLiterals(e.Y)
	}
	return false
}

// compiledMain returns the main a go build compiles, given the mains its file is listed as building
// and the go build's package argument: the file's one main, or else the one whose path ends with the
// argument.
func compiledMain(mains []string, pkgArg string) (string, bool) {
	if len(mains) == 1 {
		return mains[0], true
	}
	arg := path.Clean(pkgArg)
	var found []string
	for _, m := range mains {
		if m == arg || strings.HasSuffix(m, "/"+arg) {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		return "", false
	}
	return found[0], true
}

// checkReleaseStamps holds every -X target the release-build files under root pass to naming a
// package-level string variable a production build of the tree declares, a main. target resolved
// against the main its go build compiles and any other through the module paths graph holds, and
// returns what does not hold, sorted. A file from which no -X is read fails too, since a release
// built from it is not stamped, and a check that read nothing would pass on any path. A file that
// cannot be read is checkReleaseBuilds' finding.
func checkReleaseStamps(root string, builds []releaseBuild, graph *refgraph.ImportGraph) []string {
	var findings []string
	for _, b := range builds {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(b.file)))
		if err != nil {
			continue
		}
		targets, problems := readStampTargets(string(src))
		for _, p := range problems {
			findings = append(findings, fmt.Sprintf("release builds: %s:%d %s", b.file, p.line, p.what))
		}
		if len(targets) == 0 && len(problems) == 0 {
			findings = append(findings, fmt.Sprintf("release builds: %s passes no -X this reader can read, so nothing it builds is stamped", b.file))
		}
		for _, t := range targets {
			at := fmt.Sprintf("release builds: %s:%d stamps %s with -X", b.file, t.line, t.target)
			dot := strings.LastIndex(t.target, ".")
			pkg, name := t.target[:dot], t.target[dot+1:]
			var dir string
			switch {
			case pkg == "main":
				var ok bool
				if dir, ok = compiledMain(b.mains, t.pkgArg); !ok {
					findings = append(findings, fmt.Sprintf("%s, but which of %s its go build compiles cannot be told from %q", at, strings.Join(b.mains, ", "), t.pkgArg))
					continue
				}
			case graph.ModuleDir(pkg) == "":
				findings = append(findings, at+", which names no package in the four modules")
				continue
			default:
				dir = graph.RelPath(pkg)
			}
			switch readStampVariable(root, dir, name) {
			case noStringVariable:
				findings = append(findings, fmt.Sprintf("%s, which names no package-level string variable in %s", at, dir))
			case computedVariable:
				findings = append(findings, fmt.Sprintf("%s, which %s initializes with something other than string literals, so -X does not replace it", at, dir))
			}
		}
	}
	sort.Strings(findings)
	return findings
}

// checkReleaseBuilds holds the release-build files under root to the shipped mains and release
// targets rule 9 reads, and returns what does not hold, sorted.
func checkReleaseBuilds(root string, builds []releaseBuild, mains []string, targets []struct{ goos, goarch string }) []string {
	var findings []string

	shipped := map[string]bool{}
	for _, m := range mains {
		shipped[m] = true
	}
	built := map[string]bool{}
	for _, b := range builds {
		for _, m := range b.mains {
			built[m] = true
			if !shipped[m] {
				findings = append(findings, fmt.Sprintf("release builds: %s is listed as building %s, which is not a shipped main", b.file, m))
			}
		}
	}
	for _, m := range mains {
		if !built[m] {
			findings = append(findings, fmt.Sprintf("release builds: no release build is listed for the shipped main %s", m))
		}
	}

	want := map[string]bool{}
	for _, t := range targets {
		want[t.goos+"/"+t.goarch] = true
	}

	for _, b := range builds {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(b.file)))
		if err != nil {
			findings = append(findings, fmt.Sprintf("release builds: %s cannot be read: %v", b.file, err))
			continue
		}

		builds, platforms, problems := readReleaseText(string(src))
		for _, p := range problems {
			findings = append(findings, fmt.Sprintf("release builds: %s:%d %s", b.file, p.line, p.what))
		}
		if len(builds) == 0 {
			findings = append(findings, fmt.Sprintf("release builds: %s holds no go build", b.file))
		}
		for _, c := range builds {
			switch {
			case c.unreadable != "":
				findings = append(findings, fmt.Sprintf("release builds: %s:%d runs go build with flags this reader cannot read: %s", b.file, c.line, c.unreadable))
			case !c.production:
				findings = append(findings, fmt.Sprintf("release builds: %s:%d runs go build without the production tag", b.file, c.line))
			}
		}

		if !b.platforms {
			continue
		}
		got := map[string]bool{}
		for _, p := range platforms {
			got[p] = true
			if !want[p] {
				findings = append(findings, fmt.Sprintf("release builds: %s builds for %s, which releaseTargets does not list", b.file, p))
			}
		}
		for _, p := range sortedKeys(want) {
			if !got[p] {
				findings = append(findings, fmt.Sprintf("release builds: %s never builds for %s, which releaseTargets lists", b.file, p))
			}
		}
	}

	sort.Strings(findings)
	return findings
}

// ---- the reader, over fixture text ----------------------------------------------------------

func TestReleaseBuilds_GoBuildCommands(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		want     []goBuild
		problems []shellProblem
	}{
		{"a go build without the tag is reported", "GOOS=linux go build -o x ./cmd/a\n", []goBuild{{1, false, ""}}, nil},
		{"one with -tags=production passes", "GOOS=linux go build -tags=production -o x ./cmd/a\n", []goBuild{{1, true, ""}}, nil},
		{"the tag may be its own word", "go build -tags production .\n", []goBuild{{1, true, ""}}, nil},
		{"the tag may be one of a list", "go build -tags=netgo,production .\n", []goBuild{{1, true, ""}}, nil},
		{"the tag may be quoted, and the flag spelled with two dashes", `go build --tags "netgo production" .` + "\n", []goBuild{{1, true, ""}}, nil},
		{"a tag that only begins with production is not it", "go build -tags=productionish .\n", []goBuild{{1, false, ""}}, nil},
		{"the last -tags is the one the go command keeps", "go build -tags=production -tags=dev .\n", []goBuild{{1, false, ""}}, nil},
		{"a -tags after the package is not a flag", "go build . -tags=production\n", []goBuild{{1, false, ""}}, nil},
		{
			"a -tags inside another flag's quoted value is not the tag",
			`go build -ldflags "-X 'main.note=keep -tags=production inside a string'" -o out .` + "\n",
			[]goBuild{{1, false, ""}}, nil,
		},
		{"another flag's value is not read as a flag", "go build -ldflags -tags=production .\n", []goBuild{{1, false, ""}}, nil},
		{"a separator attached to a word ends the command", "go build ./cmd/a&& echo -tags=production\n", []goBuild{{1, false, ""}}, nil},
		{"a separator attached to a word before it too", "go build -o out .;echo -tags=production\n", []goBuild{{1, false, ""}}, nil},
		{"a Dockerfile's RUN is read like a script line", "FROM golang AS build\nRUN go build -buildvcs=false -tags=production -o ../../bin/a ./cmd/a\n", []goBuild{{2, true, ""}}, nil},
		{
			"a command split across backslash-continued lines is read whole",
			"    GOOS=$os go build -v \\\n        -tags=production \\\n        -o out \\\n        .\n",
			[]goBuild{{1, true, ""}}, nil,
		},
		{
			"the continued lines without the tag are reported at the line the command starts",
			"echo building\n    GOOS=$os go build -v \\\n        -o out \\\n        .\n",
			[]goBuild{{2, false, ""}}, nil,
		},
		{
			"a go build mentioned in a comment is not a command",
			"# without set -e, a failed go build exited 0\n    # catches a failing go build\ngo build -tags=production .\n",
			[]goBuild{{3, true, ""}}, nil,
		},
		{"a comment after the command is not part of it", "go build . # -tags=production\n", []goBuild{{1, false, ""}}, nil},
		{"a # inside quotes begins no comment", `echo "a # b"; go build -tags=production .` + "\n", []goBuild{{1, true, ""}}, nil},
		{
			"a separator ends one command and the next is read on its own",
			"( cd a && go build -tags=production ./x ) && go build ./y\n",
			[]goBuild{{1, true, ""}, {1, false, ""}}, nil,
		},
		{"a command behind a reserved word is read", "if go build -o x .; then echo ok; fi\n", []goBuild{{1, false, ""}}, nil},
		{"a file holding no go build yields nothing", "#!/bin/bash\n# go build\necho go-build\n", nil, nil},
		{
			"a go build behind echo is a mention, not a command",
			"FROM golang AS build\nRUN echo go build -tags=production .\n",
			nil, []shellProblem{{2, "mentions go build where no go build command runs"}},
		},
		{
			"a go build inside a string handed to another shell is not read",
			`go build -tags=production . && sh -c "go build ./cmd/b"` + "\n",
			[]goBuild{{1, true, ""}}, []shellProblem{{1, "mentions go build where no go build command runs"}},
		},
		{
			"a go build in a Dockerfile's exec form is not read",
			`RUN ["go", "build", "-tags=production", "."]` + "\n",
			nil, []shellProblem{{1, "mentions go build where no go build command runs"}},
		},
		{"an unquoted expansion among the flags cannot be read", "go build $FLAGS -tags=production .\n", []goBuild{{1, false, "$FLAGS is an unquoted expansion"}}, nil},
		{"a -tags set through an expansion cannot be read", `go build -tags="$TAGS" .` + "\n", []goBuild{{1, false, "-tags takes its value from an expansion"}}, nil},
		{"a flag the reader does not know cannot be read", "go build -frobnicate -tags=production .\n", []goBuild{{1, false, "-frobnicate is a flag it does not know"}}, nil},
		{"a quoted expansion in another flag's value is read", `go build -tags=production -ldflags "-X main.v=$V" -o "$OUT" .` + "\n", []goBuild{{1, true, ""}}, nil},
		{"a quoted expansion in a package path is read", `go build -tags=production -o out "./cmd/$NAME"` + "\n", []goBuild{{1, true, ""}}, nil},
		{
			"a quoted expansion where a flag could be cannot be read",
			`go build -tags=production "$FLAGS" -o out .` + "\n",
			[]goBuild{{1, false, `"$FLAGS" is an expansion that could supply a flag`}}, nil,
		},
		{
			"a quoted array expansion where a flag could be cannot be read",
			`go build -tags=production "${FLAGS[@]}" -o out .` + "\n",
			[]goBuild{{1, false, `"${FLAGS[@]}" is an expansion that could supply a flag`}}, nil,
		},
		{"a command named through an expansion cannot be read", "$GO build -o x .\n", nil, []shellProblem{{1, "runs a command named through an expansion"}}},
		{"a quote that never closes stops the reading", "go build -tags=production .\necho \"unclosed\n", nil, []shellProblem{{2, `opens a " that never closes`}}},
		{"a heredoc stops the reading", "cat <<EOF\ngo build -tags=production .\nEOF\n", nil, []shellProblem{{1, "opens a heredoc, whose lines this reader cannot tell from commands"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			builds, _, problems := readReleaseText(c.text)
			assert.Equal(t, c.want, builds)
			assert.Equal(t, c.problems, problems)
		})
	}
}

func TestReleaseBuilds_BuildPlatforms(t *testing.T) {
	script := `build_platform() {
    local os=$1
}
build_platform() { echo "$1"; }
build_platform () {
    local os=$1
}
# build_platform "plan9" "386" ""
build_platform "linux" "amd64" ""
build_platform darwin arm64 ""
build_platform "linux" "amd64" ""; build_platform "freebsd" "amd64" ""
build_platform "windows" "amd64" ".exe"&&build_platform "openbsd" "amd64" ""
`
	_, platforms, problems := readReleaseText(script)
	assert.Equal(t, []string{"darwin/arm64", "freebsd/amd64", "linux/amd64", "openbsd/amd64", "windows/amd64"}, platforms)
	assert.Empty(t, problems)

	t.Run("a call it cannot read is reported", func(t *testing.T) {
		_, platforms, problems := readReleaseText("build_platform \"$os\" amd64 \"\"\nbuild_platform linux\nfor p in a; do build_platform $p; done\n")
		assert.Empty(t, platforms)
		assert.Equal(t, []shellProblem{
			{1, "calls build_platform with arguments other than three literal words"},
			{2, "calls build_platform with arguments other than three literal words"},
			{3, "calls build_platform with arguments other than three literal words"},
		}, problems)
	})

	t.Run("a build_platform no call or definition accounts for is reported", func(t *testing.T) {
		_, _, problems := readReleaseText("echo build_platform linux amd64\nxargs -n2 build_platform < platforms\n")
		assert.Equal(t, []shellProblem{
			{1, "mentions build_platform where it is neither called nor defined"},
			{2, "mentions build_platform where it is neither called nor defined"},
		}, problems)
	})
}

func TestReleaseBuilds_StampTargets(t *testing.T) {
	const assignedTwice = "-ldflags takes its value from $LDFLAGS, which is not assigned exactly once by a plain assignment"
	cases := []struct {
		name     string
		text     string
		want     []stampTarget
		problems []shellProblem
	}{
		{
			"a Dockerfile's -X inside single quotes is read",
			"FROM golang AS build\nRUN go build -tags=production -ldflags=\"-w -X 'a.test/p.V=${v}'\" -o out ./cmd/a\n",
			[]stampTarget{{2, "a.test/p.V", "./cmd/a"}}, nil,
		},
		{
			"flags carried in a shell variable are read from its assignment",
			"LDFLAGS='-w -X \"a.test/p.V='${V}'\" -X \"a.test/p.D='${D}'\"'\ngo build -ldflags \"$LDFLAGS\" ./cmd/a\n",
			[]stampTarget{{2, "a.test/p.V", "./cmd/a"}, {2, "a.test/p.D", "./cmd/a"}}, nil,
		},
		{
			"the variable may be named in braces",
			"LDFLAGS='-X a.test/p.V=1'\ngo build -ldflags=\"${LDFLAGS}\" .\n",
			[]stampTarget{{2, "a.test/p.V", "."}}, nil,
		},
		{
			"unquoted targets in a double-quoted value are read",
			`go build -ldflags "-w -X main.version=${V} -X main.imageTag=${V}" .` + "\n",
			[]stampTarget{{1, "main.version", "."}, {1, "main.imageTag", "."}}, nil,
		},
		{
			"every spelling of -X the linker accepts is read",
			"go build -ldflags '-X=a.test/p.V=1 --X a.test/p.W=2 --X=a.test/p.Z=3' .\n",
			[]stampTarget{{1, "a.test/p.V", "."}, {1, "a.test/p.W", "."}, {1, "a.test/p.Z", "."}}, nil,
		},
		{
			"-ldflags spelled with two dashes is read",
			`go build --ldflags "-X a.test/p.V=1" ./cmd/a` + "\n",
			[]stampTarget{{1, "a.test/p.V", "./cmd/a"}}, nil,
		},
		{
			"flags behind a package pattern are read",
			"go build -ldflags 'all=-X a.test/p.V=1' .\n",
			[]stampTarget{{1, "a.test/p.V", "."}}, nil,
		},
		{
			"every -ldflags is read",
			"go build -ldflags '-X a.test/p.V=1' -ldflags '-X a.test/q.V=1' .\n",
			[]stampTarget{{1, "a.test/p.V", "."}, {1, "a.test/q.V", "."}}, nil,
		},
		{
			"the target ends at the first equals sign",
			`go build -ldflags "-X 'a.test/p.V=x=$V'" .` + "\n",
			[]stampTarget{{1, "a.test/p.V", "."}}, nil,
		},
		{
			"each go build is read on its own",
			"( cd a && go build -ldflags '-X a.test/p.V=1' ./cmd/a ) && go build -ldflags '-X main.v=1' ./cmd/b\n",
			[]stampTarget{{1, "a.test/p.V", "./cmd/a"}, {1, "main.v", "./cmd/b"}}, nil,
		},
		{"a go build without -ldflags stamps nothing", "go build -tags=production -o out .\n", nil, nil},
		{"an -X given to another command is not read", "echo go build -ldflags '-X a.test/p.V=1' .\n", nil, nil},
		{
			"a go build whose flags cannot be read is the other reading's finding",
			"go build $FLAGS -ldflags '-X a.test/p.V=1' .\n",
			nil, nil,
		},
		{
			"a variable assigned twice cannot be read",
			"LDFLAGS='-X a.test/p.V=1'\nLDFLAGS='-X a.test/q.V=1'\ngo build -ldflags \"$LDFLAGS\" .\n",
			nil, []shellProblem{{3, assignedTwice}},
		},
		{
			"a variable assigned and appended to cannot be read",
			"LDFLAGS='-X a.test/p.V=1'\nLDFLAGS+=' -X a.test/q.V=1'\ngo build -ldflags \"$LDFLAGS\" .\n",
			nil, []shellProblem{{3, assignedTwice}},
		},
		{
			"a variable also set by a builtin cannot be read",
			"LDFLAGS='-X a.test/p.V=1'\nf() { local LDFLAGS='-X a.test/q.V=1'; go build -ldflags \"$LDFLAGS\" .; }\n",
			nil, []shellProblem{{2, assignedTwice}},
		},
		{
			"a variable never assigned cannot be read",
			"go build -ldflags \"$LDFLAGS\" .\n",
			nil, []shellProblem{{1, assignedTwice}},
		},
		{
			"an assignment before a command sets no variable the command's own words read",
			"LDFLAGS='-X a.test/p.V=1' go build -ldflags \"$LDFLAGS\" .\n",
			nil, []shellProblem{{1, assignedTwice}},
		},
		{
			"an expansion where a linker flag could be cannot be read",
			`go build -ldflags "-w $EXTRA -X a.test/p.V=1" .` + "\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: $EXTRA is an expansion that could supply a linker flag"}},
		},
		{
			"a target whose path is an expansion cannot be read",
			`go build -ldflags "-X $PKG.V=1" .` + "\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: -X $PKG.V=1 takes its path from an expansion"}},
		},
		{
			"a target without a value cannot be read",
			"go build -ldflags '-X a.test/p.V' .\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: -X a.test/p.V is not importpath.name=value"}},
		},
		{
			"a target without a package cannot be read",
			"go build -ldflags '-X version=1' .\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: -X version=1 is not importpath.name=value"}},
		},
		{
			"an -X with nothing after it cannot be read",
			"go build -ldflags '-w -X' .\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: -X has no value"}},
		},
		{
			"a linker flag the reader does not know cannot be read",
			"go build -ldflags '-extldflags -X -X a.test/p.V=1' .\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: -extldflags is a linker flag it does not know"}},
		},
		{
			"a quote inside a field is no quote to the go command",
			`go build -ldflags '-X a.test/p.V="1 2"' .` + "\n",
			nil, []shellProblem{{1, `passes -ldflags this reader cannot read: 2" is not a linker flag`}},
		},
		{
			"a quote the go command finds unclosed cannot be read",
			`go build -ldflags "-X 'a.test/p.V=1" .` + "\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: it opens a ' that never closes"}},
		},
		{
			"a value that is neither flags nor pattern=flags cannot be read",
			"go build -ldflags 'all' .\n",
			nil, []shellProblem{{1, "passes -ldflags this reader cannot read: all is neither linker flags nor pattern=flags"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			targets, problems := readStampTargets(c.text)
			assert.Equal(t, c.want, targets)
			assert.Equal(t, c.problems, problems)
		})
	}
}

// ---- the check, over fixture trees ----------------------------------------------------------

// releaseFixtureTargets is the release-target list the fixture scripts are held to.
var releaseFixtureTargets = []struct{ goos, goarch string }{{"linux", "amd64"}, {"windows", "amd64"}}

// releaseFixtureMains is the shipped-mains list the fixture builds are held to.
var releaseFixtureMains = []string{"one/cmd/one", "two/cmd/two"}

// releaseFixtureBuilds lists a cross-compile script building both fixture mains and a Dockerfile
// building the first.
var releaseFixtureBuilds = []releaseBuild{
	{file: "build/build.sh", mains: []string{"one/cmd/one", "two/cmd/two"}, platforms: true},
	{file: "build/Dockerfile-one", mains: []string{"one/cmd/one"}},
}

const (
	cleanReleaseScript = `#!/bin/bash
# go build in a comment is not a command.
build_platform() {
    ( cd one && GOOS=$1 GOARCH=$2 go build -v \
        -tags=production \
        -o out ./cmd/one )
    ( cd two && GOOS=$1 GOARCH=$2 go build -tags=production -o out ./cmd/two )
}
build_platform "linux" "amd64" ""
build_platform "windows" "amd64" ".exe"
`
	cleanReleaseDockerfile = "FROM golang AS build\nRUN go build -tags=production -o bin/one ./cmd/one\n"
)

// writeReleaseFixture writes the given files under a temp source root, starting from the clean
// script and Dockerfile, and returns the root.
func writeReleaseFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	all := map[string]string{
		"build/build.sh":       cleanReleaseScript,
		"build/Dockerfile-one": cleanReleaseDockerfile,
	}
	for rel, src := range files {
		all[rel] = src
	}
	for rel, src := range all {
		if src == "" {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

func TestReleaseBuilds_Check(t *testing.T) {
	t.Run("release builds that set the tag and build for every target pass", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		assert.Empty(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets))
	})

	t.Run("a go build without the tag fails, naming its file and line", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/build.sh": strings.Replace(cleanReleaseScript, "go build -tags=production -o out ./cmd/two", "go build -o out ./cmd/two", 1),
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/build.sh:7 runs go build without the production tag")
	})

	t.Run("a Dockerfile losing the tag fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN go build -o bin/one ./cmd/one\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one:2 runs go build without the production tag")
	})

	t.Run("a listed file that is missing fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{"build/Dockerfile-one": ""})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one cannot be read")
	})

	t.Run("a listed file holding no go build fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\n# RUN go build -tags=production ./cmd/one\nRUN go-build ./cmd/one\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one holds no go build")
	})

	t.Run("a go build whose tag sits inside another flag's quoted value fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN go build -ldflags \"-X 'main.note=keep -tags=production inside a string'\" -o bin/one ./cmd/one\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one:2 runs go build without the production tag")
	})

	t.Run("a go build whose tag belongs to the next command fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN go build -o bin/one ./cmd/one&& echo -tags=production\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one:2 runs go build without the production tag")
	})

	t.Run("a go build whose flags cannot be read fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN go build $FLAGS -tags=production -o bin/one ./cmd/one\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one:2 runs go build with flags this reader cannot read: $FLAGS is an unquoted expansion")
	})

	t.Run("a quoted expansion that could override the tag fails", func(t *testing.T) {
		for _, flags := range []string{`"$FLAGS"`, `"${FLAGS[@]}"`} {
			root := writeReleaseFixture(t, map[string]string{
				"build/build.sh": strings.Replace(cleanReleaseScript, "go build -tags=production -o out ./cmd/two", "go build -tags=production "+flags+" -o out ./cmd/two", 1),
			})
			assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
				"release builds: build/build.sh:7 runs go build with flags this reader cannot read: "+flags+" is an expansion that could supply a flag")
		}
	})

	t.Run("a file whose only go build is echoed holds no go build", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN echo go build -tags=production .\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one holds no go build",
			"release builds: build/Dockerfile-one:2 mentions go build where no go build command runs")
	})

	t.Run("a file the reader cannot read fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN go build -tags=production -o 'bin/one ./cmd/one\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one holds no go build",
			"release builds: build/Dockerfile-one:2 opens a ' that never closes")
	})

	t.Run("a script building for a platform the release targets lack fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/build.sh": cleanReleaseScript + "build_platform \"freebsd\" \"amd64\" \"\"\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/build.sh builds for freebsd/amd64, which releaseTargets does not list")
	})

	t.Run("a second build_platform call on one line is read", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/build.sh": strings.Replace(cleanReleaseScript, `build_platform "linux" "amd64" ""`, `build_platform "linux" "amd64" ""; build_platform "freebsd" "amd64" ""`, 1),
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/build.sh builds for freebsd/amd64, which releaseTargets does not list")
	})

	t.Run("release targets naming a platform the script never builds for fail", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		targets := append(append([]struct{ goos, goarch string }{}, releaseFixtureTargets...), struct{ goos, goarch string }{"darwin", "arm64"})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, targets),
			"release builds: build/build.sh never builds for darwin/arm64, which releaseTargets lists")
	})

	t.Run("a shipped main no release build is listed for fails", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		mains := append(append([]string{}, releaseFixtureMains...), "three/cmd/three")
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, mains, releaseFixtureTargets),
			"release builds: no release build is listed for the shipped main three/cmd/three")
	})

	t.Run("a release build of a main that does not ship fails", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains[:1], releaseFixtureTargets),
			"release builds: build/build.sh is listed as building two/cmd/two, which is not a shipped main")
	})
}

// stampFixtureBuilds lists a servers-shaped script building both fixture mains with its flags in a
// shell variable, a Dockerfile building the first, and a wizard-shaped script building it too.
var stampFixtureBuilds = []releaseBuild{
	{file: "build/build.sh", mains: []string{"one/cmd/one", "two/cmd/two"}, platforms: true},
	{file: "build/Dockerfile-one", mains: []string{"one/cmd/one"}},
	{file: "build/wizard.sh", mains: []string{"one/cmd/one"}, platforms: true},
}

const (
	stampReleaseScript = `#!/bin/bash
LDFLAGS='-w -X "example.test/core/stamp.Version='${VERSION}'" -X "example.test/core/stamp.BuildDate='${BUILD_DATE}'"'
build_platform() {
    ( cd one && GOOS=$1 GOARCH=$2 go build -v -tags=production \
        -ldflags "$LDFLAGS" \
        -o out ./cmd/one )
    ( cd two && GOOS=$1 GOARCH=$2 go build -tags=production -ldflags "${LDFLAGS}" -o out ./cmd/two )
}
build_platform "linux" "amd64" ""
`
	stampDockerfile = "FROM golang AS build\nARG version\n" +
		`RUN go build -tags=production -ldflags="-w -X 'example.test/core/stamp.Version=${version}' -X 'main.imageTag=${version}'" -o bin/one ./cmd/one` + "\n"
	stampWizardScript = `#!/bin/bash
GOOS=linux go build -v -tags=production \
    -ldflags "-w -X main.version=${VERSION} -X main.imageTag=${VERSION}" \
    -o "build/one-linux" \
    .
`
	stampPackage = "package stamp\n\nvar Version = \"development\"\n\nvar BuildDate string\n"
	stampMainOne = "package main\n\nvar (\n\tversion  = \"dev\"\n\timageTag = \"latest\"\n)\n\nfunc main() {}\n"
)

// checkStampFixture writes the stamp fixture with the given files replaced, a file given as "" left
// out, and checks it.
func checkStampFixture(t *testing.T, files map[string]string) []string {
	t.Helper()

	all := map[string]string{
		"build/build.sh":       stampReleaseScript,
		"build/Dockerfile-one": stampDockerfile,
		"build/wizard.sh":      stampWizardScript,
		"core/stamp/stamp.go":  stampPackage,
		"core/other/other.go":  "package other\n",
		"one/cmd/one/main.go":  stampMainOne,
		"two/cmd/two/main.go":  "package main\n\nfunc main() {}\n",
	}
	for rel, src := range files {
		all[rel] = src
	}
	for rel, src := range all {
		if src == "" {
			delete(all, rel)
		}
	}
	root := writeTree(t, all)
	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	return checkReleaseStamps(root, stampFixtureBuilds, graph)
}

func TestReleaseBuilds_Stamps(t *testing.T) {
	t.Run("targets naming string variables pass, main. resolved against the main each go build compiles", func(t *testing.T) {
		assert.Empty(t, checkStampFixture(t, nil))
	})

	t.Run("a stale path in the servers' shell variable fails at every go build reading it", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/build.sh": strings.Replace(stampReleaseScript, "core/stamp.Version", "core/constants.Version", 1),
		})
		assertFindings(t, findings,
			"release builds: build/build.sh:4 stamps example.test/core/constants.Version with -X, which names no package-level string variable in core/constants",
			"release builds: build/build.sh:7 stamps example.test/core/constants.Version with -X, which names no package-level string variable in core/constants")
	})

	t.Run("a stale path in a Dockerfile fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/Dockerfile-one": strings.Replace(stampDockerfile, "core/stamp.Version", "core/other.Version", 1),
		})
		assertFindings(t, findings,
			"release builds: build/Dockerfile-one:3 stamps example.test/core/other.Version with -X, which names no package-level string variable in core/other")
	})

	t.Run("a variable missing from a package that exists fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/Dockerfile-one": strings.Replace(stampDockerfile, "stamp.Version", "stamp.GitCommit", 1),
		})
		assertFindings(t, findings,
			"release builds: build/Dockerfile-one:3 stamps example.test/core/stamp.GitCommit with -X, which names no package-level string variable in core/stamp")
	})

	t.Run("a package outside the four modules fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/Dockerfile-one": strings.Replace(stampDockerfile, "example.test/core/stamp.Version", "example.test/elsewhere/stamp.Version", 1),
		})
		assertFindings(t, findings,
			"release builds: build/Dockerfile-one:3 stamps example.test/elsewhere/stamp.Version with -X, which names no package in the four modules")
	})

	t.Run("main. is the main the go build compiles, not any main the file builds", func(t *testing.T) {
		script := strings.Replace(stampReleaseScript, `-ldflags "$LDFLAGS"`, `-ldflags "-X main.version=${VERSION}"`, 1)
		script = strings.Replace(script, `-ldflags "${LDFLAGS}"`, `-ldflags "-X main.version=${VERSION}"`, 1)
		findings := checkStampFixture(t, map[string]string{"build/build.sh": script})
		assertFindings(t, findings,
			"release builds: build/build.sh:7 stamps main.version with -X, which names no package-level string variable in two/cmd/two")
	})

	t.Run("a main. target the file's one main lacks fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/wizard.sh": strings.Replace(stampWizardScript, "main.imageTag", "main.tag", 1),
		})
		assertFindings(t, findings,
			"release builds: build/wizard.sh:2 stamps main.tag with -X, which names no package-level string variable in one/cmd/one")
	})

	t.Run("a main. target whose main cannot be told from the package argument fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/build.sh": strings.Replace(stampReleaseScript, `-ldflags "${LDFLAGS}" -o out ./cmd/two`, `-ldflags "-X main.version=1" -o out .`, 1),
		})
		assertFindings(t, findings,
			`release builds: build/build.sh:7 stamps main.version with -X, but which of one/cmd/one, two/cmd/two its go build compiles cannot be told from "."`)
	})

	t.Run("a variable initialized by a call fails, since -X does not replace it", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"core/stamp/stamp.go": "package stamp\n\nimport \"strings\"\n\nvar Version = strings.ToLower(\"DEV\")\n\nvar BuildDate string\n",
		})
		assertFindings(t, findings,
			"release builds: build/Dockerfile-one:3 stamps example.test/core/stamp.Version with -X, which core/stamp initializes with something other than string literals, so -X does not replace it",
			"release builds: build/build.sh:4 stamps example.test/core/stamp.Version with -X, which core/stamp initializes with something other than string literals, so -X does not replace it",
			"release builds: build/build.sh:7 stamps example.test/core/stamp.Version with -X, which core/stamp initializes with something other than string literals, so -X does not replace it")
	})

	t.Run("a constant, a function and a variable that is not a string are no string variable", func(t *testing.T) {
		for _, decl := range []string{`const Version = "development"`, "func Version() {}", "var Version = 1", "var Version []byte"} {
			findings := checkStampFixture(t, map[string]string{
				"core/stamp/stamp.go": "package stamp\n\n" + decl + "\n\nvar BuildDate string\n",
				"build/build.sh":      strings.Replace(stampReleaseScript, "core/stamp.Version", "core/stamp.BuildDate", 1),
			})
			assertFindings(t, findings,
				"release builds: build/Dockerfile-one:3 stamps example.test/core/stamp.Version with -X, which names no package-level string variable in core/stamp")
		}
	})

	t.Run("a variable a production build does not compile fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"core/stamp/stamp.go":      "package stamp\n\nvar BuildDate string\n",
			"core/stamp/dev.go":        "//go:build !production\n\npackage stamp\n\nvar Version = \"development\"\n",
			"core/stamp/stamp_test.go": "package stamp\n\nvar Version = \"development\"\n",
			"build/build.sh":           strings.Replace(stampReleaseScript, "core/stamp.Version", "core/stamp.BuildDate", 1),
		})
		assertFindings(t, findings,
			"release builds: build/Dockerfile-one:3 stamps example.test/core/stamp.Version with -X, which names no package-level string variable in core/stamp")
	})

	t.Run("a variable local to a function is no package-level variable", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"core/stamp/stamp.go": "package stamp\n\nvar BuildDate string\n\nfunc f() string {\n\tvar Version = \"development\"\n\treturn Version\n}\n",
			"build/build.sh":      strings.Replace(stampReleaseScript, "core/stamp.Version", "core/stamp.BuildDate", 1),
		})
		assertFindings(t, findings,
			"release builds: build/Dockerfile-one:3 stamps example.test/core/stamp.Version with -X, which names no package-level string variable in core/stamp")
	})

	t.Run("every declaration -X can replace passes", func(t *testing.T) {
		assert.Empty(t, checkStampFixture(t, map[string]string{
			"core/stamp/stamp.go": "package stamp\n\nvar (\n\tOther, Version string = \"o\", \"de\" + (\"velopment\")\n\tBuildDate = `development`\n)\n",
		}))
	})

	t.Run("a release build stamping nothing fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN go build -tags=production -o bin/one ./cmd/one\n",
		})
		assertFindings(t, findings,
			"release builds: build/Dockerfile-one passes no -X this reader can read, so nothing it builds is stamped")
	})

	t.Run("-ldflags the reader cannot read fails", func(t *testing.T) {
		findings := checkStampFixture(t, map[string]string{
			"build/wizard.sh": strings.Replace(stampWizardScript, "-w -X", "-w $EXTRA -X", 1),
		})
		assertFindings(t, findings,
			"release builds: build/wizard.sh:2 passes -ldflags this reader cannot read: $EXTRA is an expansion that could supply a linker flag")
	})
}

// ---- the real tree --------------------------------------------------------------------------

// TestReleaseBuilds_TheRealReleaseBuildsSetProduction holds this repository's release builds to the
// premise rule 9 rests on: every go build a release runs sets production, the release builds listed
// name exactly the guard's shippedMains, and both cross-compile scripts build for exactly its
// releaseTargets.
func TestReleaseBuilds_TheRealReleaseBuildsSetProduction(t *testing.T) {
	assert.Empty(t, checkReleaseBuilds(SourceRoot(t), releaseBuilds, shippedMains, releaseTargets))
}

// TestReleaseBuilds_TheRealStampsNameVariables holds every -X a release build passes to naming a
// package-level string variable a production build of the tree declares, so a path left behind by a
// move fails here rather than shipping a binary that reports "development".
func TestReleaseBuilds_TheRealStampsNameVariables(t *testing.T) {
	root := SourceRoot(t)
	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	assert.Empty(t, checkReleaseStamps(root, releaseBuilds, graph))
}

// ---- the wizard's Makefile ------------------------------------------------------------------

// wizardMakefile is the setup wizard's Makefile, relative to the source root. It is not a release
// build: its build target is a local dev build without the tag, as the servers' dev builds are. What
// it must not be is a second cross-compile of the wizard, drifted from the release script's tag,
// flags and version stamp, so its build-all runs that script and no go build in it picks a platform
// (#463).
const wizardMakefile = "cmd/goiabada-setup/Makefile"

// makeRecipes returns a Makefile's text with every line blanked but the recipe lines of target, or of
// every target when target is empty, each as make hands it to the shell: its leading tab removed,
// and make's @, - and + prefixes too where it begins a command. It also returns the text with every
// recipe line of any target blanked instead, and reports whether target is defined. A recipe is the
// tab-indented lines under a rule; a variable assignment is not a rule.
func makeRecipes(text, target string) (string, string, bool) {
	lines := strings.Split(text, "\n")
	out := make([]string, len(lines))
	others := slices.Clone(lines)
	rule, in, defined, continued := false, false, false, false
	for i, l := range lines {
		if strings.HasPrefix(l, "\t") {
			if rule {
				others[i] = ""
			}
			if in {
				l = strings.TrimPrefix(l, "\t")
				if !continued {
					l = strings.TrimLeft(l, "@-+")
				}
				out[i] = l
				continued = strings.HasSuffix(l, `\`)
			}
			continue
		}
		names, rest, ok := strings.Cut(l, ":")
		rule = ok && !strings.HasPrefix(rest, "=") && !strings.HasPrefix(strings.TrimSpace(l), "#")
		in = rule && (target == "" || slices.Contains(strings.Fields(names), target))
		defined = defined || in
		continued = false
	}
	return strings.Join(out, "\n"), strings.Join(others, "\n"), defined
}

// runsReleaseScript reports whether one of a recipe's commands runs the wizard's own
// build-binaries.sh, the one beside the Makefile, with --version $(VERSION) and nothing else: the
// script keeps the last --version it is given, so a later one would override the Makefile's. The
// script is named as ./build-binaries.sh, and nothing earlier on its logical line changes directory,
// so it is the wizard's script and not the servers' one at build/build-binaries.sh.
func runsReleaseScript(commands []shellCommand) bool {
	moved := map[int]bool{}
	for _, c := range commands {
		if len(c.words) == 0 {
			continue
		}
		if name := c.words[0].value; name == "cd" || name == "pushd" {
			moved[c.logical] = true
		}
		if !moved[c.logical] && !c.words[0].expands && c.words[0].value == "./build-binaries.sh" &&
			len(c.words) == 3 && c.words[1].value == "--version" && c.words[2].value == "$(VERSION)" {
			return true
		}
	}
	return false
}

// makePlatformVariable finds GOOS or GOARCH named outside a recipe: make hands a variable it exports,
// globally or for a target, to every recipe line it runs, so a go build there picks that platform
// with nothing on its own line saying so. Rather than read make's assignment, export and override
// forms, any mention outside a recipe and a comment is refused.
var makePlatformVariable = regexp.MustCompile(`\bGO(OS|ARCH)\b`)

// checkWizardMakefile holds the wizard's Makefile to delegating its cross-compile, and returns what
// does not hold. make runs each logical line of a recipe in a shell of its own, so a go build picks a
// platform when a GOOS or GOARCH is set on its logical line.
func checkWizardMakefile(text string) []string {
	var findings []string

	if recipe, _, ok := makeRecipes(text, "build-all"); !ok {
		findings = append(findings, "wizard makefile: no build-all target")
	} else if !runsReleaseScript(readShell(recipe).commands) {
		findings = append(findings, "wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)")
	}

	recipes, others, _ := makeRecipes(text, "")
	for i, l := range strings.Split(others, "\n") {
		l, _, _ = strings.Cut(l, "#")
		if makePlatformVariable.MatchString(l) {
			findings = append(findings, fmt.Sprintf("wizard makefile: line %d sets GOOS or GOARCH outside a recipe, where make can hand it to every go build", i+1))
		}
	}
	s := readShell(recipes)
	for _, p := range s.problems {
		findings = append(findings, fmt.Sprintf("wizard makefile: line %d %s", p.line, p.what))
	}
	picksPlatform := map[int]bool{}
	for _, c := range s.commands {
		for _, w := range slices.Concat(c.assigns, c.words) {
			if strings.HasPrefix(w.value, "GOOS=") || strings.HasPrefix(w.value, "GOARCH=") {
				picksPlatform[c.logical] = true
			}
		}
	}
	var buildLines []int
	for _, c := range s.commands {
		if !isGoBuild(c) {
			continue
		}
		buildLines = append(buildLines, c.words[0].line)
		if picksPlatform[c.logical] {
			findings = append(findings, fmt.Sprintf("wizard makefile: line %d cross-compiles with its own go build", c.line))
		}
	}
	for _, l := range s.unaccounted(goBuildMention, buildLines) {
		findings = append(findings, fmt.Sprintf("wizard makefile: line %d mentions go build where no go build command runs", l))
	}
	return findings
}

func TestReleaseBuilds_WizardMakefile(t *testing.T) {
	const delegating = "VERSION ?= $(or $(GOIABADA_VERSION),dev)\n" +
		"BUILD_VAR := x:y\n" +
		"all: build-all\n" +
		"\n" +
		"build:\n" +
		"\tgo build -o build/goiabada-setup .\n" +
		"\n" +
		"# GOOS=linux go build in a comment is not a command.\n" +
		"build-all:\n" +
		"\t@./build-binaries.sh --version \"$(VERSION)\"\n"

	cases := []struct {
		name string
		text string
		want []string
	}{
		{"a build-all running the release script with the version passes", delegating, nil},
		{
			"a build-all not running the release script fails",
			strings.Replace(delegating, "\t@./build-binaries.sh --version \"$(VERSION)\"\n", "\tGOOS=linux go build -o build/x .\n", 1),
			[]string{
				"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)",
				"wizard makefile: line 10 cross-compiles with its own go build",
			},
		},
		{
			"running the release script without the version fails",
			strings.Replace(delegating, ` --version "$(VERSION)"`, "", 1),
			[]string{"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)"},
		},
		{
			"running the release script with a fixed version fails",
			strings.Replace(delegating, `"$(VERSION)"`, "dev", 1),
			[]string{"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)"},
		},
		{
			"running the servers' release script fails",
			strings.Replace(delegating, "./build-binaries.sh", "../../build/build-binaries.sh", 1),
			[]string{"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)"},
		},
		{
			"running the release script from another directory fails",
			strings.Replace(delegating, "\t@./build-binaries.sh", "\t@cd ../../build && ./build-binaries.sh", 1),
			[]string{"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)"},
		},
		{
			"a later fixed version overriding it fails",
			strings.Replace(delegating, `"$(VERSION)"`, `"$(VERSION)" --version dev`, 1),
			[]string{"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)"},
		},
		{
			"the release script run by another target does not count",
			strings.Replace(delegating, "build-all:\n", "build-all:\n\techo building\n\nother:\n", 1),
			[]string{"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)"},
		},
		{
			"a build-all that only echoes the release script fails",
			strings.Replace(delegating, "\t@./build-binaries.sh", "\t@echo ./build-binaries.sh", 1),
			[]string{"wizard makefile: build-all does not run ./build-binaries.sh --version $(VERSION)"},
		},
		{
			"the release script run after a separator is read",
			strings.Replace(delegating, "\t@./build-binaries.sh", "\t@mkdir -p build&&./build-binaries.sh", 1),
			nil,
		},
		{
			"a Makefile with no build-all fails",
			strings.Replace(delegating, "build-all:", "build-every:", 1),
			[]string{"wizard makefile: no build-all target"},
		},
		{
			"a cross-compiling go build in any target fails, continued lines read whole",
			delegating + "\nbuild-linux-arm64:\n\tGOOS=linux GOARCH=arm64 \\\n\t\tgo build -o build/x .\n",
			[]string{"wizard makefile: line 13 cross-compiles with its own go build"},
		},
		{
			"a go build the reader cannot see run fails",
			delegating + "\nbuild-linux:\n\tsh -c \"GOOS=linux go build -o build/x .\"\n",
			[]string{"wizard makefile: line 13 mentions go build where no go build command runs"},
		},
		{
			"a GOOS set by another recipe line picks no platform for this one",
			delegating + "\nbuild-local:\n\texport GOOS=linux\n\tgo build -o build/x .\n",
			nil,
		},
		{
			"a platform exported from the Makefile itself fails",
			"export GOOS := linux\nexport GOARCH := arm64\n" + delegating,
			[]string{
				"wizard makefile: line 1 sets GOOS or GOARCH outside a recipe, where make can hand it to every go build",
				"wizard makefile: line 2 sets GOOS or GOARCH outside a recipe, where make can hand it to every go build",
			},
		},
		{
			"a platform exported for one target fails",
			delegating + "build: export GOOS = linux\nbuild: export GOARCH = arm64\n",
			[]string{
				"wizard makefile: line 11 sets GOOS or GOARCH outside a recipe, where make can hand it to every go build",
				"wizard makefile: line 12 sets GOOS or GOARCH outside a recipe, where make can hand it to every go build",
			},
		},
		{
			"a GOOS in a comment outside a recipe sets nothing",
			"# export GOOS := linux\n" + delegating,
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, checkWizardMakefile(c.text))
		})
	}
}

// TestReleaseBuilds_TheRealWizardMakefileDelegates holds the wizard's real Makefile to delegating its
// cross-compile to the release script.
func TestReleaseBuilds_TheRealWizardMakefileDelegates(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(SourceRoot(t), filepath.FromSlash(wizardMakefile)))
	require.NoError(t, err)
	assert.Empty(t, checkWizardMakefile(string(src)))
}
