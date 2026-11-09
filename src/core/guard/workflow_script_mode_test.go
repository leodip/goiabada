package guard

// A run: step whose command is a path, ./build.sh or src/build/build-binaries.sh, has the runner
// execute that file, which it can only when the checkout gave the file an execute bit: the mode its
// git index entry records. Committed as 100644, the script fails on the runner alone, with
// "Permission denied" and exit 126, since a test that reads such a script runs it through bash. That
// is how build validation's scan-image-binaries.sh reached main and failed every push after it
// (#820). This test reads the run: steps of every workflow and composite action as the shell runs
// them, resolves each command that is a path against its step's working-directory and the cds
// before it in the script, and holds the file it names to existing and being executable. It reads
// the mode from the tree, which on CI's fresh checkout is the committed one. The shell reader keeps
// no parentheses, so a cd on a line that opens with ( is read as a subshell's, ending with that
// line. A path behind a runner other than commandWrappers, such as sudo or xargs, and a command
// inside $(…) are not read.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// workflowSources are the files whose run: steps the runner executes, as globs relative to the
// repository root: the workflows, and the composite actions they use.
var workflowSources = []string{
	".github/workflows/*.yml", ".github/workflows/*.yaml",
	".github/actions/*/action.yml", ".github/actions/*/action.yaml",
}

// commandWrappers are the commands that run the command after them, as exec ./x.sh does. env's own
// options and assignments come before it.
var commandWrappers = wordSet("exec", "env", "time", "nohup")

// stepKey returns what follows the key on line when it is one of a step's own keys, a key at
// column, written there or after the sequence item's dash two columns before it.
func stepKey(line string, column int) (string, bool) {
	body := strings.TrimLeft(line, " ")
	depth := len(line) - len(body)
	if rest, ok := strings.CutPrefix(body, "- "); ok && depth == column-2 {
		return rest, true
	}
	return body, depth == column && body != ""
}

// stepWorkingDirectory returns the working-directory the step holding run names, and the line it is
// on, or "" and -1 when the step names none and runs at the repository root. The step is the
// mapping the run key sits in: the keys at the run key's column, from the sequence item that opens
// it to the first line indented less than the key, which the next item is.
func stepWorkingDirectory(lines []string, run workflowRun) (string, int) {
	first := run.line
	for i := run.line; i >= 0; i-- {
		body := strings.TrimLeft(lines[i], " ")
		depth := len(lines[i]) - len(body)
		if body == "" || depth >= run.column {
			first = i
			continue
		}
		if depth == run.column-2 && strings.HasPrefix(body, "- ") {
			first = i
		}
		break
	}
	last := run.line
	for i := run.line + 1; i < len(lines); i++ {
		body := strings.TrimLeft(lines[i], " ")
		if body != "" && len(lines[i])-len(body) < run.column {
			break
		}
		last = i
	}
	for i := first; i <= last; i++ {
		text, ok := stepKey(lines[i], run.column)
		if !ok {
			continue
		}
		if value, ok := strings.CutPrefix(text, "working-directory:"); ok {
			value, _, _ = strings.Cut(value, " #")
			return strings.Trim(strings.TrimSpace(value), `"'`), i
		}
	}
	return "", -1
}

// shellDirectory is the directory a script's next command runs in, relative to the repository root,
// or why this check cannot tell which.
type shellDirectory struct {
	dir, unresolved string
}

// cd is the directory after c, a cd at file line line: its literal directory joined to this one, or
// unresolved when it names none, -, an absolute directory or one that expands.
func (d shellDirectory) cd(c shellCommand, line int) shellDirectory {
	if d.unresolved != "" {
		return d
	}
	if len(c.words) != 2 || c.words[1].expands || c.words[1].value == "-" || strings.HasPrefix(c.words[1].value, "/") {
		return shellDirectory{unresolved: fmt.Sprintf("after the cd at line %d, to a directory this check cannot resolve", line)}
	}
	return shellDirectory{dir: path.Join(d.dir, c.words[1].value)}
}

// executedPath returns the path a command executes, when its name, after any commandWrappers, is a
// relative path the shell runs as a file, one holding a slash, and false when it is anything else: a
// name the shell looks up, an absolute path, or a word that expands.
func executedPath(c shellCommand) (string, bool) {
	words := c.words
	for len(words) > 0 && commandWrappers[words[0].value] {
		wrapper := words[0].value
		words = words[1:]
		for wrapper == "env" && len(words) > 0 && (strings.HasPrefix(words[0].value, "-") || assignment.MatchString(words[0].raw)) {
			words = words[1:]
		}
	}
	if c.defines || len(words) == 0 || words[0].expands {
		return "", false
	}
	name := words[0].value
	return name, strings.Contains(name, "/") && !strings.HasPrefix(name, "/")
}

// scriptModeFindings reads the run: steps of each file, named relative to root, and returns every
// command that is a path naming no file in the repository or a file without an execute bit, every
// such command whose working-directory is an expression it cannot resolve, and every form its shell
// reader cannot read, with the files it found executable, relative to root. A list of files holding
// no run: step is a finding too, since a check that read nothing would pass on any tree.
func scriptModeFindings(root string, files []string) (findings, checked []string) {
	steps := 0
	for _, file := range files {
		text, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			findings = append(findings, fmt.Sprintf("script mode: %s cannot be read: %v", file, err))
			continue
		}
		lines := workflowLines(string(text))
		for _, run := range workflowRuns(lines) {
			steps++
			var here shellDirectory
			if dir, line := stepWorkingDirectory(lines, run); strings.Contains(dir, "${{") {
				here.unresolved = fmt.Sprintf("in working-directory %s, from line %d, an expression this check cannot resolve", dir, line+1)
			} else {
				here.dir = dir
			}
			script := readShell(run.script.text)
			for _, p := range script.problems {
				findings = append(findings, fmt.Sprintf("script mode: %s:%d %s, which this reader cannot read as the shell would", file, run.script.offset+p.line, p.what))
			}
			scriptLines := strings.Split(run.script.text, "\n")
			outside, subshell := here, -1
			for _, c := range script.commands {
				if subshell >= 0 && c.logical != subshell {
					here, subshell = outside, -1
				}
				if !c.defines && len(c.words) > 0 && c.words[0].value == "cd" {
					if subshell < 0 && strings.HasPrefix(strings.TrimSpace(scriptLines[c.line-1]), "(") {
						outside, subshell = here, c.logical
					}
					here = here.cd(c, run.script.offset+c.line)
					continue
				}
				name, ok := executedPath(c)
				if !ok {
					continue
				}
				at := fmt.Sprintf("script mode: %s:%d runs %s", file, run.script.offset+c.line, name)
				if here.unresolved != "" {
					findings = append(findings, fmt.Sprintf("%s %s", at, here.unresolved))
					continue
				}
				target := filepath.Clean(filepath.Join(root, filepath.FromSlash(here.dir), filepath.FromSlash(name)))
				rel, err := filepath.Rel(root, target)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					findings = append(findings, fmt.Sprintf("%s, which is outside the repository", at))
					continue
				}
				rel = filepath.ToSlash(rel)
				info, err := os.Stat(target)
				switch {
				case err != nil:
					findings = append(findings, fmt.Sprintf("%s, but the repository has no file %s for it to run", at, rel))
				case !info.Mode().IsRegular():
					findings = append(findings, fmt.Sprintf("%s, but %s is not a file", at, rel))
				case info.Mode().Perm()&0o111 == 0:
					findings = append(findings, fmt.Sprintf("%s, but %s has mode %04o, with no execute bit, so the runner refuses it with Permission denied: "+
						"git update-index --chmod=+x %s, and chmod +x it", at, rel, info.Mode().Perm(), rel))
				default:
					if !slices.Contains(checked, rel) {
						checked = append(checked, rel)
					}
				}
			}
		}
	}
	switch {
	case len(files) == 0:
		findings = append(findings, "script mode: no workflow file was found, so this check read nothing")
	case steps == 0:
		findings = append(findings, fmt.Sprintf("script mode: %s hold no run: step, so this check read nothing", strings.Join(files, ", ")))
	}
	slices.Sort(checked)
	return findings, checked
}

// workflowFiles returns the files workflowSources names under root, relative to it.
func workflowFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, pattern := range workflowSources {
		matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		require.NoError(t, err)
		for _, m := range matches {
			rel, err := filepath.Rel(root, m)
			require.NoError(t, err)
			files = append(files, filepath.ToSlash(rel))
		}
	}
	return files
}

func TestWorkflowScripts_TheRealRunStepsRunExecutableFiles(t *testing.T) {
	repo := filepath.Dir(SourceRoot(t))
	files := workflowFiles(t, repo)
	require.Contains(t, files, buildValidationWorkflow, "the walk finds the workflows")

	findings, checked := scriptModeFindings(repo, files)
	assert.Empty(t, findings)
	assert.Contains(t, checked, "src/build/"+binaryScanCommand,
		"the walk reaches build validation's binary scan, which reached main without its execute bit")
}

// scriptModeTree writes a repository holding workflow as .github/workflows/w.yml and each script
// at its path, with its mode, and returns its root.
func scriptModeTree(t *testing.T, workflow string, scripts map[string]os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, text string, mode os.FileMode) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(text), mode))
		require.NoError(t, os.Chmod(full, mode))
	}
	write(".github/workflows/w.yml", workflow, 0o644)
	for rel, mode := range scripts {
		write(rel, "#!/bin/sh\n", mode)
	}
	return root
}

func TestWorkflowScripts_Findings(t *testing.T) {
	const workflow = "jobs:\n" + // 1
		"  build:\n" + // 2
		"    steps:\n" + // 3
		"      - name: Scan\n" + // 4
		"        working-directory: src/build\n" + // 5
		"        run: |\n" + // 6
		"          ./scan.sh \\\n" + // 7
		"            --flag\n" + // 8
		"      - run: ./src/build/scan.sh\n" + // 9
		"      - name: After its run key\n" + // 10
		"        run: tool/run.sh\n" + // 11
		"        working-directory: \"src\" # quoted\n" + // 12
		"      - name: Wrapped\n" + // 13
		"        run: |\n" + // 14
		"          if ./src/build/scan.sh; then exec env -i A=1 ./src/tool/run.sh; fi\n" + // 15
		"          bash ./src/build/scan.sh\n" + // 16
		"          go test ./...\n" + // 17
		"          \"$dir\"/scan.sh\n" + // 18
		"      - uses: ./.github/actions/x\n" + // 19
		"      - name: Moves\n" + // 20
		"        run: |\n" + // 21
		"          ( cd src/build && ./scan.sh )\n" + // 22
		"          ./src/tool/run.sh\n" + // 23
		"          cd src\n" + // 24
		"          ./tool/run.sh\n" + // 25
		"      - run: './src/build/scan.sh --name ''quoted'''\n" + // 26
		"      - run: \"./src/tool/run.sh \\\"quoted\\\"\"\n" // 27
	scripts := map[string]os.FileMode{"src/build/scan.sh": 0o755, "src/tool/run.sh": 0o755}

	t.Run("every path a step runs is an executable file", func(t *testing.T) {
		// Line 9's step names no working-directory: resolved in src/build, the step before it's,
		// ./src/build/scan.sh would name no file. Line 23 runs after the subshell's cd, line 25
		// after the cd before it, and lines 26 and 27 are read without their YAML quotes.
		findings, checked := scriptModeFindings(scriptModeTree(t, workflow, scripts), []string{".github/workflows/w.yml"})
		assert.Empty(t, findings)
		assert.Equal(t, []string{"src/build/scan.sh", "src/tool/run.sh"}, checked)
	})

	t.Run("a script without an execute bit", func(t *testing.T) {
		root := scriptModeTree(t, workflow, map[string]os.FileMode{"src/build/scan.sh": 0o644, "src/tool/run.sh": 0o755})
		findings, checked := scriptModeFindings(root, []string{".github/workflows/w.yml"})
		assertFindings(t, findings,
			"w.yml:7 runs ./scan.sh, but src/build/scan.sh has mode 0644, with no execute bit",
			"w.yml:9 runs ./src/build/scan.sh, but src/build/scan.sh has mode 0644",
			"w.yml:15 runs ./src/build/scan.sh, but src/build/scan.sh has mode 0644",
			"w.yml:22 runs ./scan.sh, but src/build/scan.sh has mode 0644",
			"w.yml:26 runs ./src/build/scan.sh, but src/build/scan.sh has mode 0644")
		assert.Contains(t, findings[0], "git update-index --chmod=+x src/build/scan.sh")
		assert.Equal(t, []string{"src/tool/run.sh"}, checked, "bash ./src/build/scan.sh reads the file, which needs no execute bit")
	})

	t.Run("a working-directory after the run key is the step's", func(t *testing.T) {
		removed := strings.Replace(workflow, "        working-directory: \"src\" # quoted\n", "", 1)
		findings, _ := scriptModeFindings(scriptModeTree(t, removed, scripts), []string{".github/workflows/w.yml"})
		assertFindings(t, findings, "w.yml:11 runs tool/run.sh, but the repository has no file tool/run.sh for it to run")
	})

	t.Run("a path naming no file, outside the repository, or under an expression", func(t *testing.T) {
		const workflow = "jobs:\n" + // 1
			"  build:\n" + // 2
			"    steps:\n" + // 3
			"      - run: ./gone.sh\n" + // 4
			"      - run: ../outside.sh\n" + // 5
			"      - working-directory: ${{ matrix.dir }}\n" + // 6
			"        run: ./scan.sh\n" + // 7
			"      - run: ./src\n" + // 8
			"      - run: cd \"$RUNNER_TEMP\" && ./tool.sh\n" // 9
		root := scriptModeTree(t, workflow, map[string]os.FileMode{"src/build/scan.sh": 0o755})
		findings, checked := scriptModeFindings(root, []string{".github/workflows/w.yml"})
		assertFindings(t, findings,
			"w.yml:4 runs ./gone.sh, but the repository has no file gone.sh",
			"w.yml:5 runs ../outside.sh, which is outside the repository",
			"w.yml:7 runs ./scan.sh in working-directory ${{ matrix.dir }}, from line 6, an expression",
			"w.yml:8 runs ./src, but src is not a file",
			"w.yml:9 runs ./tool.sh after the cd at line 9, to a directory this check cannot resolve")
		assert.Empty(t, checked)
	})

	t.Run("a script the reader cannot read", func(t *testing.T) {
		const workflow = "jobs:\n  build:\n    steps:\n      - run: |\n          echo \"never closed\n"
		findings, _ := scriptModeFindings(scriptModeTree(t, workflow, nil), []string{".github/workflows/w.yml"})
		require.NotEmpty(t, findings)
		assert.Contains(t, findings[0], "script mode: .github/workflows/w.yml:5 ")
		assert.Contains(t, findings[0], "which this reader cannot read as the shell would")
	})

	t.Run("files holding no run: step", func(t *testing.T) {
		root := scriptModeTree(t, "jobs:\n  build:\n    steps:\n      - uses: ./.github/actions/x\n", nil)
		findings, _ := scriptModeFindings(root, []string{".github/workflows/w.yml"})
		assertFindings(t, findings, "script mode: .github/workflows/w.yml hold no run: step, so this check read nothing")

		findings, _ = scriptModeFindings(root, nil)
		assertFindings(t, findings, "script mode: no workflow file was found, so this check read nothing")
	})

	t.Run("a file that cannot be read", func(t *testing.T) {
		findings, _ := scriptModeFindings(t.TempDir(), []string{".github/workflows/missing.yml"})
		assertFindings(t, findings,
			"script mode: .github/workflows/missing.yml cannot be read",
			"hold no run: step, so this check read nothing")
	})
}
