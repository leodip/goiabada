package testutil

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// AssertNoAgreementPointers holds every Go comment under src/ to carrying its fact rather than
// pointing at where the fact was once written down. An issue's agreement and its probe outputs are
// files on the machine of whoever worked the issue: they are not in the repository, so a comment
// that sends its reader to a section of one, or to a probe's output file, dangles on every other
// machine and on that one too once the folder is cleaned up. The rule was written down and did not
// hold on its own: 55 such lines in 41 files had accumulated when #428 restated them, each with the
// fact it pointed at and the issue it came from.
//
// Decidable from the text, which is why it is a guard: the comment is read through go/parser, so a
// string literal holding the same words is not a finding, and the phrases are whole, so a word that
// merely contains the noun, or RFC 7516's "Key Agreement", passes. Each module's unit tier calls
// this, and the walk is the whole source tree for the reason AssertGofmted gives (#428).
func AssertNoAgreementPointers(t *testing.T) {
	t.Helper()

	assertNoAgreementPointers(t, SourceRoot(t))
}

// assertNoAgreementPointers is the reporting half. See Reporter in guard.go for why both halves
// exist.
func assertNoAgreementPointers(r Reporter, root string) {
	r.Helper()

	findings, files, err := findAgreementPointers(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	if files == 0 {
		r.Fatalf("walked no Go files under %s", root)
	}
	if len(findings) > 0 {
		r.Errorf("%d comment lines point at an agreement or a probe file instead of stating the fact "+
			"with its issue number; restate each:\n\t%s", len(findings), strings.Join(findings, "\n\t"))
	}
}

// agreementPointerPatterns are the refused shapes: the agreement named as the owner of a section or
// decision, as the subject of what it said or kept, and a probe's output or source path.
var agreementPointerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bthe agreement's\b`),
	regexp.MustCompile(`(?i)\bof the agreement\b`),
	regexp.MustCompile(`(?i)\bthe agreement (said|says|keeps|kept|requires|required|for)\b`),
	regexp.MustCompile(`\bprobe/[A-Za-z0-9_]+\.(out|go)\b`),
}

// findAgreementPointers walks every Go file under root and returns one finding per comment line
// matching a refused pattern, as `path:line: text` with the path relative to root, along with the
// number of files it parsed. A file that does not parse is the build tier's to report and is not
// counted, as in findUnformatted.
func findAgreementPointers(root string) ([]string, int, error) {
	var findings []string
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if pErr != nil {
			return nil
		}
		files++
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for _, group := range file.Comments {
			for _, c := range group.List {
				for i, line := range strings.Split(c.Text, "\n") {
					if !matchesAgreementPointer(line) {
						continue
					}
					findings = append(findings, filepath.ToSlash(rel)+":"+
						strconv.Itoa(fset.Position(c.Slash).Line+i)+": "+strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return findings, files, nil
}

func matchesAgreementPointer(line string) bool {
	for _, p := range agreementPointerPatterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}
