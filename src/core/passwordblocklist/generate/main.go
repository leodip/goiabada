// This tool generates ../data_generated.go, the blocklist of commonly used passwords, from three
// public password lists as SecLists publishes them.
//
// Usage (from src/core/passwordblocklist/generate):
//
//	go run .
//
// or via the repo helper:
//
//	./version-manager.sh generate passwordblocklist
//
// It fetches each list from the immutable raw URL of one pinned SecLists commit, refuses it unless
// its SHA-256 is the one pinned for it, keeps the entries the nist password policy could otherwise
// accept (15 characters or more, at most bcrypt's 72 bytes), lowercases them, de-duplicates them
// across the three lists, sorts them, and writes them with each source, its licence, URL and digest
// recorded in the header. Identical pins give identical output, and a run whose count drifts from
// the expected one stops for a human to review (#550 decisions 4 and 5).
//
// To move to a newer SecLists commit:
//
//  1. Look up the newest commit (git ls-remote https://github.com/danielmiessler/SecLists master).
//  2. Set pinnedCommit to it and run; the run refuses each list whose bytes changed and prints the
//     SHA-256 it received.
//  3. Set that list's sha256 to the printed digest and run again, and set expectedCount to the
//     count a run then refuses with, once the change is reviewed.
//  4. Review the diff of data_generated.go before committing it.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"go/format"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/internal/pinnedfetch"
)

const (
	// pinnedCommit is the SecLists commit the lists are fetched at. A run fetches that one commit
	// and refuses any other bytes, so the blocklist moves only when a human moves the pins.
	pinnedCommit = "a8677c0058f9c4e3cc1faa3b63b3e52db50aa4b7"

	// rawURLFmt is the immutable per-commit raw URL of a list in SecLists' Common-Credentials
	// directory (commit, then file name).
	rawURLFmt = "https://raw.githubusercontent.com/danielmiessler/SecLists/%s/Passwords/Common-Credentials/%s"

	// sizeLimit caps each download, which pinnedfetch reads through boundedread.Read, refusing an
	// overrun rather than truncating it. The largest list is about 8.8 MB.
	sizeLimit = int64(32 << 20) // 32 MiB

	userAgent = "goiabada-passwordblocklist-generator"

	// minCharacters and maxBytes are the nist policy's bounds: an entry outside them names a
	// password the policy refuses before the blocklist is consulted, so it is not kept.
	minCharacters = 15
	maxBytes      = 72

	// expectedCount is the number of entries the pinned lists give. Any drift stops generation for
	// human review.
	expectedCount = 16043
)

// source is one list: its file name under Passwords/Common-Credentials, what it is, its licence,
// and the SHA-256 its bytes must have.
type source struct {
	file    string
	name    string
	licence string
	sha256  string
}

// pin names one SecLists commit and the lists fetched at it.
//
// It is a parameter below run rather than read from the constants inside fetchPinned because no
// fixture can hash to the real digests: a test calling through the constants would never get past
// the check. run passes pinned, the one value built from the constants, so production has no other
// path.
type pin struct {
	commit  string
	sources []source
}

var pinned = pin{
	commit: pinnedCommit,
	sources: []source{
		{
			file: "100k-most-used-passwords-NCSC.txt",
			name: "The UK National Cyber Security Centre's 100,000 most used passwords, " +
				"drawn from Have I Been Pwned's Pwned Passwords",
			licence: "Crown copyright, Open Government Licence v3.0; Pwned Passwords, CC BY 4.0",
			sha256:  "c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0",
		},
		{
			file:    "Pwdb_top-1000000.txt",
			name:    "Pwdb's 1,000,000 most common passwords (ignis-sec/Pwdb-Public, 2020)",
			licence: "MIT",
			sha256:  "e9a88f67aafe65496682dc374559ee714e978bee50314767494c3e37a18c9fc8",
		},
		{
			file:    "xato-net-10-million-passwords-1000000.txt",
			name:    "The 1,000,000 most common of xato's ten million passwords (2015)",
			licence: "MIT, as part of SecLists",
			sha256:  "424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51",
		},
	},
}

// provenance is recorded verbatim in the generated file header, one per source (no wall-clock
// date, so identical sources produce identical output).
type provenance struct {
	Name      string
	Licence   string
	SourceURL string
	SHA256    string
}

func main() {
	client := &http.Client{Timeout: 120 * time.Second}
	if err := run(client.Do); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(doer pinnedfetch.Doer) error {
	bodies, provs, err := fetchPinned(doer, pinned)
	if err != nil {
		return err
	}

	entries := build(bodies)
	if validateErr := validateEntries(entries); validateErr != nil {
		return errs.Errorf("validate: %w", validateErr)
	}
	if countErr := validateCount(entries); countErr != nil {
		return errs.Errorf("validate: %w", countErr)
	}

	out, err := render(entries, pinned.commit, provs)
	if err != nil {
		return errs.Errorf("render: %w", err)
	}

	outPath, err := outputPath()
	if err != nil {
		return err
	}
	//nolint:gosec // G306: the output is a committed source file, world-readable on purpose like every file in the repository.
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return errs.Errorf("write %s: %w", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d passwords to %s\n", len(entries), outPath)
	return nil
}

// fetchPinned fetches each of p's lists at p's commit, refuses any whose SHA-256 is not the one
// pinned for it, and returns their bytes with the provenance the header records.
func fetchPinned(doer pinnedfetch.Doer, p pin) ([][]byte, []provenance, error) {
	bodies := make([][]byte, 0, len(p.sources))
	provs := make([]provenance, 0, len(p.sources))
	for _, s := range p.sources {
		url := fmt.Sprintf(rawURLFmt, p.commit, s.file)
		fmt.Fprintf(os.Stderr, "Fetching %s\n", url)
		body, err := pinnedfetch.Get(doer, url, userAgent, sizeLimit)
		if err != nil {
			return nil, nil, errs.Errorf("fetch %s: %w", s.file, err)
		}
		sum, err := pinnedfetch.CheckSHA256(body, s.sha256)
		if err != nil {
			return nil, nil, errs.Errorf("%s at commit %s: %w", s.file, p.commit, err)
		}
		bodies = append(bodies, body)
		provs = append(provs, provenance{Name: s.name, Licence: s.licence, SourceURL: url, SHA256: sum})
	}
	return bodies, provs, nil
}

// build reads each body as one password per line and returns, lowercased, de-duplicated and
// sorted, those a password the nist policy accepts can lowercase to. A line in hashcat's $HEX[]
// encoding is read as the password it encodes. A line that is not UTF-8 names no password a form
// can submit, so it is dropped rather than repaired.
func build(bodies [][]byte) []string {
	seen := map[string]bool{}
	for _, body := range bodies {
		for _, line := range bytes.Split(body, []byte("\n")) {
			password := decodeHashcatHex(strings.TrimRight(string(line), "\r"))
			if !utf8.ValidString(password) {
				continue
			}
			if entry := strings.ToLower(password); reachable(entry) {
				seen[entry] = true
			}
		}
	}
	entries := make([]string, 0, len(seen))
	for e := range seen {
		entries = append(entries, e)
	}
	slices.Sort(entries)
	return entries
}

// decodeHashcatHex returns the password line names. Hashcat writes a password it cannot write as
// is, one holding a byte outside printable ASCII or a colon, ending in whitespace, or itself reading
// as such a line, as $HEX[ followed by its bytes in hex and ], and the NCSC and Pwdb lists carry
// such lines: taken as written, each was an entry nobody types, in place of the password it
// encodes. A line hashcat would not read as one, the hex odd in length or not hex at all, is taken
// as written, as hashcat takes it.
func decodeHashcatHex(line string) string {
	inner, ok := strings.CutPrefix(line, "$HEX[")
	if !ok {
		return line
	}
	inner, ok = strings.CutSuffix(inner, "]")
	if !ok {
		return line
	}
	decoded, err := hex.DecodeString(inner)
	if err != nil {
		return line
	}
	return string(decoded)
}

// reachable reports whether a password the nist policy accepts, 15 characters or more and at most
// 72 bytes as typed, can lowercase to entry, which is what IsCommon looks the password up as. The
// bounds are weighed on the password as typed, not on entry or on the line it came from, because
// lowercasing keeps the number of characters but can change their width: the Kelvin sign (U+212A)
// takes three bytes and its lowercase k one, while U+023A takes two and its lowercase three. An
// entry over 72 bytes that a narrower password lowercases to is kept here, and validateEntries
// then stops the run for review, since the list holds entries of at most 72 bytes.
func reachable(entry string) bool {
	if utf8.RuneCountInString(entry) < minCharacters {
		return false
	}
	narrower := narrowerCases()
	width := 0
	for _, r := range entry {
		if w, ok := narrower[r]; ok {
			width += w
		} else {
			width += utf8.RuneLen(r)
		}
	}
	return width <= maxBytes
}

// narrowerCases maps each character to the fewest bytes a character lowercasing to it takes, for
// the characters where that is fewer than their own, read from the same tables strings.ToLower
// reads, so no case mapping is assumed.
var narrowerCases = sync.OnceValue(func() map[rune]int {
	narrower := map[rune]int{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		lower := unicode.ToLower(r)
		w := utf8.RuneLen(r)
		if lower == r || w < 0 || w >= utf8.RuneLen(lower) {
			continue
		}
		if known, ok := narrower[lower]; !ok || w < known {
			narrower[lower] = w
		}
	}
	return narrower
})

func withinPolicy(password string) bool {
	return utf8.RuneCountInString(password) >= minCharacters && len(password) <= maxBytes
}

// validateEntries checks what the package promises of its list: every entry UTF-8, lowercase,
// within the policy's bounds, free of the newline entries are delimited by, unique and sorted.
func validateEntries(entries []string) error {
	previous := ""
	for i, e := range entries {
		switch {
		case !utf8.ValidString(e):
			return errs.Errorf("entry %d %q is not UTF-8", i, e)
		case strings.ToLower(e) != e:
			return errs.Errorf("entry %d %q is not lowercase", i, e)
		case !withinPolicy(e):
			return errs.Errorf("entry %d %q is outside %d characters to %d bytes", i, e, minCharacters, maxBytes)
		case strings.Contains(e, "\n"):
			return errs.Errorf("entry %d %q holds a newline", i, e)
		case i > 0 && previous >= e:
			return errs.Errorf("entry %d %q is not after %q", i, e, previous)
		}
		previous = e
	}
	return nil
}

// validateCount guards against an entry lost or gained silently.
func validateCount(entries []string) error {
	if len(entries) != expectedCount {
		return errs.Errorf("unexpected count %d (want %d); the pinned lists may have changed — "+
			"review the change, then update expectedCount", len(entries), expectedCount)
	}
	return nil
}

// render builds the generated Go source and formats it with go/format. The list is one string
// constant, every entry on a line of its own and followed by a newline, opened by one too, so the
// package matches a whole entry as "\n" + entry + "\n" and the binary carries the bytes alone.
func render(entries []string, commit string, provs []provenance) ([]byte, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, `// Code generated by "go run ." in ./generate; DO NOT EDIT.
//
// The passwords of 15 characters or more and at most 72 bytes in three public lists, lowercased,
// de-duplicated and sorted, fetched from SecLists (MIT) at commit %s:
`, commit)
	for _, p := range provs {
		fmt.Fprintf(&sb, "//\n//   %s\n//     Licence: %s\n//     Source:  %s\n//     SHA-256: %s\n",
			p.Name, p.Licence, p.SourceURL, p.SHA256)
	}
	sb.WriteString(`//
// To regenerate this file, run from src/core/passwordblocklist/generate:
//   go run .
// or from src/authserver:
//   ./version-manager.sh generate passwordblocklist

package passwordblocklist

// list holds every entry between newlines.
const list = "\n"`)
	for _, e := range entries {
		fmt.Fprintf(&sb, " +\n\t%q", e+"\n")
	}
	sb.WriteString("\n")

	formatted, err := format.Source([]byte(sb.String()))
	if err != nil {
		return nil, errs.Errorf("format generated source: %w", err)
	}
	return formatted, nil
}

// outputPath resolves ../data_generated.go relative to this source file.
func outputPath() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errs.Errorf("could not determine current file path")
	}
	return filepath.Join(filepath.Dir(currentFile), "..", "data_generated.go"), nil
}
