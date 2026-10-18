package guard

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// scriptCheck is the program the script check runs under Node: check.js, and the acorn release it
// parses with, which versions.yaml pins with its digest.
//
//go:embed scriptcheck/check.js scriptcheck/acorn.js
var scriptCheck embed.FS

// AssertScriptSyntax holds every static .js file under root in fsys, the vendored libraries
// included, to JavaScript every browser at the declared floor runs: Chrome and Edge 111, Safari 16.4
// and Firefox 128 (#617). acorn parses each file under Node as a classic script of ES2020 at most,
// the cap, so a syntax error, syntax newer than the cap, module syntax or one of the language's early
// errors, such as an assignment to what is not a target or a regular expression no browser compiles,
// fails here rather than in a visitor's browser. Node not on PATH is fatal.
//
// The pages load these files as they are written: there is no build step that could translate one
// down, so the cap is the language the files are written in.
func AssertScriptSyntax(t *testing.T, fsys fs.FS, root string) {
	t.Helper()

	assertScriptSyntax(t, fsys, root)
}

// assertScriptSyntax is the reporting half, failing through a Reporter so a rule test can drive it
// against a fixture FS. See Reporter in guard.go.
func assertScriptSyntax(r Reporter, fsys fs.FS, root string) {
	r.Helper()

	var scripts []scriptFile
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".js") {
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		scripts = append(scripts, scriptFile{Path: p, Source: string(src)})
		return nil
	})
	if err != nil {
		r.Fatalf("walking scripts under %s: %v", root, err)
	}
	if len(scripts) == 0 {
		r.Fatalf("walked no .js files under %s; this guard is checking nothing", root)
	}
	found, err := findScriptSyntaxProblems(scripts)
	if err != nil {
		r.Fatalf("%v", err)
	}
	for _, f := range found {
		r.Errorf("%s: %s", f.path, f.detail)
	}
}

// scriptFile is one script the check reads: its path, which a finding names, and its text.
type scriptFile struct {
	Path   string `json:"path"`
	Source string `json:"source"`
}

// findScriptSyntaxProblems parses scripts in one Node process and returns a finding for each a
// browser at the floor refuses.
//
// The context is Background because the reporting half holds none: a Reporter is Helper, Errorf
// and Fatalf, and the tier's own timeout is what bounds the run.
func findScriptSyntaxProblems(scripts []scriptFile) ([]templateFinding, error) {
	node, err := exec.LookPath("node")
	if err != nil {
		return nil, errs.New("node is not on PATH: the script check parses with acorn under Node, which the " +
			"dev container and the test jobs install at the version src/authserver/versions.yaml pins")
	}
	dir, err := os.MkdirTemp("", "scriptcheck-")
	if err != nil {
		return nil, errs.Wrap(err, "making the script check's directory")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err = writeScriptCheck(dir); err != nil {
		return nil, err
	}
	input, err := json.Marshal(scripts)
	if err != nil {
		return nil, errs.Wrap(err, "encoding the scripts for the script check")
	}

	cmd := exec.CommandContext(context.Background(), node, filepath.Join(dir, "check.js"))
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, errs.Wrapf(err, "running the script check: %s", strings.TrimSpace(stderr.String()))
	}
	var refused []struct {
		Path   string `json:"path"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &refused); err != nil {
		return nil, errs.Wrap(err, "reading the script check's answer")
	}
	found := make([]templateFinding, 0, len(refused))
	for _, f := range refused {
		found = append(found, templateFinding{path: f.Path, detail: f.Detail})
	}
	return found, nil
}

// writeScriptCheck writes the embedded check.js and acorn.js into dir, where Node loads them.
func writeScriptCheck(dir string) error {
	for _, name := range []string{"check.js", "acorn.js"} {
		content, err := scriptCheck.ReadFile("scriptcheck/" + name)
		if err != nil {
			return errs.Wrapf(err, "reading the embedded %s", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return errs.Wrapf(err, "writing %s for the script check", name)
		}
	}
	return nil
}
