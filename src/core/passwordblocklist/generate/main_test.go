package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// fakeDoer serves canned bodies keyed by request URL, so tests never touch the network.
type fakeDoer struct {
	responses map[string]string
}

func (f fakeDoer) do(req *http.Request) (*http.Response, error) {
	body, ok := f.responses[req.URL.String()]
	status := http.StatusOK
	if !ok {
		status = http.StatusNotFound
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func digest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// fixtures are what the fake serves for each of a fixture pin's three sources.
var fixtures = []string{
	"PasswordPassword\r\nshort\r\n",
	"passwordpassword\ncorrect horse battery staple\n",
	"averylongpasswordindeed\n",
}

const fixtureCommit = "0123456789abcdef0123456789abcdef01234567"

// fixturePin is a pin whose digests are the fixtures' own, so fetchPinned gets past the check.
func fixturePin() pin {
	p := pin{commit: fixtureCommit}
	for i, body := range fixtures {
		p.sources = append(p.sources, source{
			file:    fmt.Sprintf("list-%d.txt", i),
			name:    fmt.Sprintf("Fixture list %d", i),
			licence: fmt.Sprintf("Licence %d", i),
			sha256:  digest(body),
		})
	}
	return p
}

func fixtureDoer(p pin) fakeDoer {
	d := fakeDoer{responses: map[string]string{}}
	for i, s := range p.sources {
		d.responses[fmt.Sprintf(rawURLFmt, p.commit, s.file)] = fixtures[i]
	}
	return d
}

func TestFetchPinned(t *testing.T) {
	t.Run("each source fetched at the pin's commit, checked and recorded", func(t *testing.T) {
		p := fixturePin()

		bodies, provs, err := fetchPinned(fixtureDoer(p).do, p)
		if err != nil {
			t.Fatalf("fetchPinned: %v", err)
		}
		if len(bodies) != len(fixtures) || len(provs) != len(fixtures) {
			t.Fatalf("got %d bodies and %d provenances, want %d of each", len(bodies), len(provs), len(fixtures))
		}
		for i, s := range p.sources {
			if string(bodies[i]) != fixtures[i] {
				t.Errorf("body %d = %q, want %q", i, bodies[i], fixtures[i])
			}
			want := provenance{
				Name:      s.name,
				Licence:   s.licence,
				SourceURL: "https://raw.githubusercontent.com/danielmiessler/SecLists/" + fixtureCommit + "/Passwords/Common-Credentials/" + s.file,
				SHA256:    s.sha256,
			}
			if provs[i] != want {
				t.Errorf("provenance %d = %+v, want %+v", i, provs[i], want)
			}
		}
	})

	t.Run("another digest: refused, naming the source, the pinned and the received hash", func(t *testing.T) {
		p := fixturePin()
		received := p.sources[1].sha256
		p.sources[1].sha256 = strings.Repeat("0", 64)

		bodies, _, err := fetchPinned(fixtureDoer(p).do, p)
		if err == nil {
			t.Fatal("fetchPinned accepted a list whose digest is not the pinned one")
		}
		if bodies != nil {
			t.Errorf("bodies = %q, want nil", bodies)
		}
		for _, want := range []string{p.sources[1].file, p.sources[1].sha256, received} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q", err, want)
			}
		}
	})

	t.Run("a source the server does not answer: refused", func(t *testing.T) {
		p := fixturePin()
		d := fixtureDoer(p)
		delete(d.responses, fmt.Sprintf(rawURLFmt, p.commit, p.sources[2].file))

		if _, _, err := fetchPinned(d.do, p); err == nil {
			t.Fatal("fetchPinned accepted a missing source")
		}
	})

	// The production pin, which run passes. No fixture can hash to its digests, so this is the
	// case that ties run to the constants: it fails if the check is skipped.
	t.Run("the production pin refuses any list but its own", func(t *testing.T) {
		d := fakeDoer{responses: map[string]string{}}
		for _, s := range pinned.sources {
			d.responses[fmt.Sprintf(rawURLFmt, pinnedCommit, s.file)] = fixtures[0]
		}

		_, _, err := fetchPinned(d.do, pinned)
		if err == nil {
			t.Fatal("fetchPinned(pinned) accepted a fixture")
		}
		for _, want := range []string{pinned.sources[0].sha256, digest(fixtures[0])} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q", err, want)
			}
		}
	})
}

// The pins are the three sources the agreement names, at one SecLists commit (#550 decision 5).
func TestPinned_NamesTheThreeSources(t *testing.T) {
	var files []string
	for _, s := range pinned.sources {
		files = append(files, s.file)
		if s.name == "" || s.licence == "" {
			t.Errorf("%s names no source or no licence", s.file)
		}
		if len(s.sha256) != 64 {
			t.Errorf("%s pins %q, not a SHA-256", s.file, s.sha256)
		}
	}
	want := []string{"100k-most-used-passwords-NCSC.txt", "Pwdb_top-1000000.txt", "xato-net-10-million-passwords-1000000.txt"}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("pinned files = %v, want %v", files, want)
	}
}

// build keeps what the nist policy could otherwise accept, 15 characters or more and at most 72
// bytes, lowercased, de-duplicated across the sources and sorted (#550 decisions 4 and 5).
func TestBuild(t *testing.T) {
	cases := []struct {
		name   string
		bodies []string
		want   []string
	}{
		{
			name:   "lowercased, de-duplicated across sources and sorted",
			bodies: []string{"ZzzzzzzzzzzzzzzZ\nPasswordPassword\n", "passwordpassword\nPASSWORDPASSWORD\n"},
			want:   []string{"passwordpassword", "zzzzzzzzzzzzzzzz"},
		},
		{
			name:   "15 characters kept, 14 dropped",
			bodies: []string{strings.Repeat("a", 15) + "\n" + strings.Repeat("b", 14) + "\n"},
			want:   []string{strings.Repeat("a", 15)},
		},
		{
			name:   "characters counted, not bytes: 15 two-byte characters kept, 14 dropped",
			bodies: []string{strings.Repeat("é", 15) + "\n" + strings.Repeat("è", 14) + "\n"},
			want:   []string{strings.Repeat("é", 15)},
		},
		{
			name:   "72 bytes kept, 73 dropped",
			bodies: []string{strings.Repeat("a", 72) + "\n" + strings.Repeat("b", 73) + "\n"},
			want:   []string{strings.Repeat("a", 72)},
		},
		{
			name:   "36 two-byte characters kept, 37 dropped",
			bodies: []string{strings.Repeat("é", 36) + "\n" + strings.Repeat("è", 37) + "\n"},
			want:   []string{strings.Repeat("é", 36)},
		},
		{
			name:   "line endings stripped, spaces inside and around kept",
			bodies: []string{"correct horse battery\r\n  leading spaces too\r\n"},
			want:   []string{"  leading spaces too", "correct horse battery"},
		},
		{
			name:   "a last line with no newline kept",
			bodies: []string{"averylongpasswordindeed"},
			want:   []string{"averylongpasswordindeed"},
		},
		{
			name:   "invalid UTF-8 dropped",
			bodies: []string{"abcdefghijklmn\xff\nabcdefghijklmnop\n"},
			want:   []string{"abcdefghijklmnop"},
		},
		{
			name:   "nothing long enough: nothing",
			bodies: []string{"short\n\n\n"},
			want:   []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bodies := make([][]byte, len(c.bodies))
			for i, b := range c.bodies {
				bodies[i] = []byte(b)
			}
			got := build(bodies)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("build = %q, want %q", got, c.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	if err := validateEntries([]string{"aaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbb"}); err != nil {
		t.Errorf("valid entries refused: %v", err)
	}
	for name, entries := range map[string][]string{
		"uppercase":   {"Aaaaaaaaaaaaaaa"},
		"duplicate":   {"aaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaa"},
		"unsorted":    {"bbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaa"},
		"14 chars":    {"aaaaaaaaaaaaaa"},
		"73 bytes":    {strings.Repeat("a", 73)},
		"a newline":   {"aaaaaaa\naaaaaaa"},
		"not utf-8":   {"aaaaaaaaaaaaaa\xff"},
		"empty entry": {""},
	} {
		if err := validateEntries(entries); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
	if err := validateCount(make([]string, expectedCount-1)); err == nil {
		t.Error("a count one short of the expected: want error")
	}
	if err := validateCount(make([]string, expectedCount)); err != nil {
		t.Errorf("the expected count refused: %v", err)
	}
}

// TestRender checks that the header names each source, its licence, URL and digest, and through
// the type-check helper that the rendered list compiles against passwordblocklist.go.
func TestRender(t *testing.T) {
	p := fixturePin()
	_, provs, err := fetchPinned(fixtureDoer(p).do, p)
	if err != nil {
		t.Fatalf("fetchPinned: %v", err)
	}
	entries := []string{"averylongpasswordindeed", "pass\"word\\with`quotes", "passwordpassword"}

	out, err := render(entries, p.commit, provs)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(out)
	wants := []string{"// Code generated", "DO NOT EDIT", "package passwordblocklist", fixtureCommit, "const list = "}
	for _, prov := range provs {
		wants = append(wants, prov.Name, prov.Licence, prov.SourceURL, prov.SHA256)
	}
	for _, want := range wants {
		if !strings.Contains(s, want) {
			t.Errorf("render output missing %q", want)
		}
	}
	for _, e := range entries {
		if !strings.Contains(s, fmt.Sprintf("%q", e+"\n")) {
			t.Errorf("render output does not hold %q as one quoted line", e)
		}
	}

	guard.AssertGeneratedSourceTypeChecks(t, "..", "data_generated.go", out)
}
