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
)

// fakeDoer serves canned responses keyed by request URL, so tests never touch
// the network.
type fakeDoer struct {
	responses map[string]fakeResp
	err       error
}

type fakeResp struct {
	status int
	body   string
}

func (f fakeDoer) do(req *http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	r, ok := f.responses[req.URL.String()]
	if !ok {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	}
	return &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Header:     make(http.Header),
	}, nil
}

func TestNormalizeDial(t *testing.T) {
	valid := map[string][]string{
		"297":               {"297"},
		"1-876":             {"1876"},
		"39-06":             {"3906"},
		"381 p":             {"381"}, // trailing note letter
		"290 n":             {"290"}, // trailing note letter
		"599":               {"599"},
		"1,2":               {"1", "2"},
		"1787,1939":         {"1787", "1939"},
		"1-809,1-829,1-849": {"1809", "1829", "1849"}, // DO multi-code
		"":                  nil,
		"   ":               nil,
	}
	for in, want := range valid {
		got, err := normalizeDial(in)
		if err != nil {
			t.Errorf("normalizeDial(%q) unexpected error: %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("normalizeDial(%q) = %v, want %v", in, got, want)
		}
	}

	// Malformed values must ERROR, not be silently repaired.
	invalid := []string{
		"12x34",   // embedded letter
		"1/234",   // stray punctuation
		"1.234",   // stray punctuation
		"+1",      // leading '+'
		"1-",      // dangling hyphen
		"1--2",    // empty hyphen group
		"-",       // no digits
		"abc",     // letters only
		"1,,2",    // empty token
		"12 34",   // space-separated digits (note must be letters)
		"381 p q", // ambiguous double note is not supported
	}
	for _, in := range invalid {
		if got, err := normalizeDial(in); err == nil {
			t.Errorf("normalizeDial(%q) = (%v, nil), want error", in, got)
		}
	}
}

func TestEmojiFromAlpha2(t *testing.T) {
	cases := map[string]string{
		"BR":  "🇧🇷",
		"US":  "🇺🇸",
		"XK":  "🇽🇰",
		"us":  "", // lowercase invalid
		"B1":  "", // non-letter
		"B":   "", // wrong length
		"BRA": "",
	}
	for in, want := range cases {
		if got := emojiFromAlpha2(in); got != want {
			t.Errorf("emojiFromAlpha2(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadCapped(t *testing.T) {
	// Within limit.
	b, err := readCapped(strings.NewReader("abcdef"), 10)
	if err != nil || string(b) != "abcdef" {
		t.Errorf("readCapped within limit = (%q, %v)", b, err)
	}
	// Exactly at limit is allowed.
	if _, err := readCapped(strings.NewReader("abc"), 3); err != nil {
		t.Errorf("readCapped at limit errored: %v", err)
	}
	// Over limit fails.
	if _, err := readCapped(strings.NewReader("abcdef"), 3); err == nil {
		t.Error("readCapped over limit: want error, got nil")
	}
}

func TestIsHex40(t *testing.T) {
	good := "caa72d1e0e5af8876c170bb36a9e4d64a01bba88"
	if !isHex40(good) {
		t.Errorf("isHex40(%q) = false", good)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", 40), good + "0", good[:39]} {
		if isHex40(bad) {
			t.Errorf("isHex40(%q) = true, want false", bad)
		}
	}
}

func TestResolveSHA(t *testing.T) {
	good := "caa72d1e0e5af8876c170bb36a9e4d64a01bba88"

	t.Run("success", func(t *testing.T) {
		d := fakeDoer{responses: map[string]fakeResp{apiCommitsURL: {200, `{"sha":"` + good + `","commit":{}}`}}}
		sha, err := resolveSHA(d.do)
		if err != nil || sha != good {
			t.Errorf("resolveSHA = (%q, %v), want (%q, nil)", sha, err, good)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		d := fakeDoer{responses: map[string]fakeResp{apiCommitsURL: {500, ``}}}
		if _, err := resolveSHA(d.do); err == nil {
			t.Error("want error on non-200")
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		d := fakeDoer{responses: map[string]fakeResp{apiCommitsURL: {200, `not json`}}}
		if _, err := resolveSHA(d.do); err == nil {
			t.Error("want error on malformed JSON")
		}
	})
	t.Run("invalid SHA", func(t *testing.T) {
		d := fakeDoer{responses: map[string]fakeResp{apiCommitsURL: {200, `{"sha":"nope"}`}}}
		if _, err := resolveSHA(d.do); err == nil {
			t.Error("want error on invalid SHA")
		}
	})
}

func TestFetchCSV(t *testing.T) {
	url := "https://example.test/data.csv"
	t.Run("success", func(t *testing.T) {
		d := fakeDoer{responses: map[string]fakeResp{url: {200, "col\nval\n"}}}
		b, err := fetchCSV(d.do, url)
		if err != nil || string(b) != "col\nval\n" {
			t.Errorf("fetchCSV = (%q, %v)", b, err)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		d := fakeDoer{responses: map[string]fakeResp{url: {403, ""}}}
		if _, err := fetchCSV(d.do, url); err == nil {
			t.Error("want error on non-200")
		}
	})
}

// minimal valid header covering the required columns (others omitted).
const testHeader = "ISO3166-1-Alpha-2,ISO3166-1-Alpha-3,Dial,CLDR display name,official_name_en"

func TestParseCSV(t *testing.T) {
	t.Run("basic + normalization + name fallback", func(t *testing.T) {
		csv := testHeader + "\n" +
			"BR,BRA,55,Brazil,Federative Republic of Brazil\n" +
			"JM,JAM,1-876,Jamaica,Jamaica\n" +
			"ZZ,ZZZ,999,,Fallback Land\n" // empty CLDR -> fallback to official_name_en
		list, err := parseCSV([]byte(csv))
		if err != nil {
			t.Fatalf("parseCSV err: %v", err)
		}
		if len(list) != 3 {
			t.Fatalf("len = %d, want 3", len(list))
		}
		if list[1].Alpha2 != "JM" || !reflect.DeepEqual(list[1].CallingCodes, []string{"1876"}) {
			t.Errorf("JM = %+v", list[1])
		}
		if list[0].Emoji != "🇧🇷" {
			t.Errorf("BR emoji = %q", list[0].Emoji)
		}
		if list[2].Name != "Fallback Land" {
			t.Errorf("name fallback failed: %q", list[2].Name)
		}
	})
	t.Run("missing required header", func(t *testing.T) {
		csv := "Foo,Bar\n1,2\n"
		if _, err := parseCSV([]byte(csv)); err == nil {
			t.Error("want error on missing required column")
		}
	})
	t.Run("BOM tolerated", func(t *testing.T) {
		csv := "\xef\xbb\xbf" + testHeader + "\nBR,BRA,55,Brazil,Brazil\n"
		list, err := parseCSV([]byte(csv))
		if err != nil || len(list) != 1 || list[0].Alpha2 != "BR" {
			t.Errorf("BOM handling failed: list=%v err=%v", list, err)
		}
	})
	t.Run("malformed dial errors (not silently repaired)", func(t *testing.T) {
		csv := testHeader + "\nZZ,ZZZ,12x34,Bad,Bad\n"
		if _, err := parseCSV([]byte(csv)); err == nil {
			t.Error("want error for malformed dial 12x34")
		}
	})
}

func TestApplySupplements(t *testing.T) {
	t.Run("adds XK when absent, fills empty UM", func(t *testing.T) {
		in := []country{
			{Alpha2: "UM", Alpha3: "UMI", Name: "US Outlying", CallingCodes: nil},
			{Alpha2: "BR", Alpha3: "BRA", Name: "Brazil", CallingCodes: []string{"55"}},
		}
		out := applySupplements(in)
		xk, ok := findGen(out, "XK")
		if !ok || xk.Alpha3 != "XKX" || !reflect.DeepEqual(xk.CallingCodes, []string{"383"}) || xk.Emoji != "🇽🇰" {
			t.Errorf("XK supplement wrong: %+v ok=%v", xk, ok)
		}
		um, _ := findGen(out, "UM")
		if !reflect.DeepEqual(um.CallingCodes, []string{"1"}) {
			t.Errorf("UM fill wrong: %+v", um)
		}
	})
	t.Run("does not override non-empty UM", func(t *testing.T) {
		in := []country{{Alpha2: "UM", Alpha3: "UMI", Name: "x", CallingCodes: []string{"507"}}}
		out := applySupplements(in)
		um, _ := findGen(out, "UM")
		if !reflect.DeepEqual(um.CallingCodes, []string{"507"}) {
			t.Errorf("UM should not be overridden: %+v", um)
		}
	})
	t.Run("does not duplicate existing XK", func(t *testing.T) {
		in := []country{{Alpha2: "XK", Alpha3: "XKX", Name: "Kosovo", CallingCodes: []string{"383"}}}
		out := applySupplements(in)
		n := 0
		for _, c := range out {
			if c.Alpha2 == "XK" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("XK count = %d, want 1", n)
		}
	})
}

func TestValidateRows(t *testing.T) {
	valid := []country{
		{Name: "Brazil", Alpha2: "BR", Alpha3: "BRA", Emoji: "🇧🇷", CallingCodes: []string{"55"}},
		{Name: "United States", Alpha2: "US", Alpha3: "USA", Emoji: "🇺🇸", CallingCodes: []string{"1"}},
	}
	if err := validateRows(valid); err != nil {
		t.Errorf("valid rows errored: %v", err)
	}
	// Exactly 5 codes is the allowed maximum.
	if err := validateRows([]country{{Name: "x", Alpha2: "DO", Alpha3: "DOM", CallingCodes: []string{"1", "2", "3", "4", "5"}}}); err != nil {
		t.Errorf("5 codes should be valid: %v", err)
	}

	bad := map[string][]country{
		"dup alpha-2":     {valid[0], {Name: "x", Alpha2: "BR", Alpha3: "XXX", CallingCodes: []string{"1"}}},
		"dup alpha-3":     {valid[0], {Name: "x", Alpha2: "ZZ", Alpha3: "BRA", CallingCodes: []string{"1"}}},
		"lowercase a2":    {{Name: "x", Alpha2: "br", Alpha3: "BRA", CallingCodes: []string{"1"}}},
		"short a3":        {{Name: "x", Alpha2: "BR", Alpha3: "BR", CallingCodes: []string{"1"}}},
		"empty name":      {{Name: "", Alpha2: "BR", Alpha3: "BRA", CallingCodes: []string{"1"}}},
		"empty codes":     {{Name: "x", Alpha2: "BR", Alpha3: "BRA", CallingCodes: nil}},
		"non-digit code":  {{Name: "x", Alpha2: "BR", Alpha3: "BRA", CallingCodes: []string{"5a"}}},
		"too many codes":  {{Name: "x", Alpha2: "BR", Alpha3: "BRA", CallingCodes: []string{"1", "2", "3", "4", "5", "6"}}},
		"dup code in one": {{Name: "x", Alpha2: "BR", Alpha3: "BRA", CallingCodes: []string{"1", "1"}}},
	}
	for name, rows := range bad {
		if err := validateRows(rows); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestCheckSupplementPreconditions(t *testing.T) {
	umEmpty := country{Alpha2: "UM", Alpha3: "UMI", Name: "US Outlying", CallingCodes: nil}
	br := country{Alpha2: "BR", Alpha3: "BRA", Name: "Brazil", CallingCodes: []string{"55"}}

	if err := checkSupplementPreconditions([]country{umEmpty, br}); err != nil {
		t.Errorf("clean preconditions errored: %v", err)
	}
	bad := map[string][]country{
		"XK present upstream": {umEmpty, {Alpha2: "XK", Alpha3: "XKX", Name: "Kosovo", CallingCodes: []string{"383"}}},
		"UM missing":          {br},
		"UM already has dial": {{Alpha2: "UM", Alpha3: "UMI", Name: "x", CallingCodes: []string{"1"}}, br},
	}
	for name, list := range bad {
		if err := checkSupplementPreconditions(list); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestValidateUpstreamCount(t *testing.T) {
	// A too-small list fails the count check before preconditions.
	if err := validateUpstream([]country{{Alpha2: "UM", Alpha3: "UMI", Name: "x"}}); err == nil {
		t.Error("wrong upstream count: want error")
	}
}

func TestValidateCount(t *testing.T) {
	if err := validateCount([]country{}); err == nil {
		t.Error("want error for wrong count")
	}
}

func TestRender(t *testing.T) {
	list := []country{
		{Name: "Brazil", Alpha2: "BR", Alpha3: "BRA", Emoji: "🇧🇷", CallingCodes: []string{"55"}},
	}
	prov := provenance{
		CommitSHA: "caa72d1e0e5af8876c170bb36a9e4d64a01bba88",
		SourceURL: "https://example.test/x.csv",
		CSVSHA256: "deadbeef",
	}
	out, err := render(list, prov)
	if err != nil {
		t.Fatalf("render err: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		"// Code generated", "DO NOT EDIT", "package countries",
		prov.CommitSHA, prov.CSVSHA256, prov.SourceURL,
		"var countries = []Country{", `Alpha2: "BR"`, `CallingCodes: []string{"55"}`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("render output missing %q", want)
		}
	}
}

// TestFetchPinnedAndHeader exercises the complete provenance chain against a
// fake serving both endpoints: resolve SHA → build the immutable per-commit URL
// from that SHA → fetch the CSV → compute its SHA-256 → carry all three EXACT
// values into the rendered header. It never writes a file or touches the network.
func TestFetchPinnedAndHeader(t *testing.T) {
	sha := "caa72d1e0e5af8876c170bb36a9e4d64a01bba88"
	rawURL := fmt.Sprintf(rawURLFmt, sha) // must equal the URL fetchPinned builds
	csv := testHeader + "\nBR,BRA,55,Brazil,Brazil\n"
	d := fakeDoer{responses: map[string]fakeResp{
		apiCommitsURL: {200, `{"sha":"` + sha + `"}`},
		rawURL:        {200, csv}, // if fetchPinned built a wrong URL, this 404s
	}}

	csvBytes, prov, err := fetchPinned(d.do)
	if err != nil {
		t.Fatalf("fetchPinned: %v", err)
	}
	if prov.CommitSHA != sha {
		t.Errorf("CommitSHA = %q, want %q", prov.CommitSHA, sha)
	}
	if prov.SourceURL != rawURL {
		t.Errorf("SourceURL = %q, want %q", prov.SourceURL, rawURL)
	}
	sum := sha256.Sum256([]byte(csv))
	wantHash := hex.EncodeToString(sum[:])
	if prov.CSVSHA256 != wantHash {
		t.Errorf("CSVSHA256 = %q, want %q (exact computed hash)", prov.CSVSHA256, wantHash)
	}
	if string(csvBytes) != csv {
		t.Errorf("csvBytes = %q, want %q", csvBytes, csv)
	}

	// The rendered header must carry the exact resolved SHA, URL, and hash.
	list, err := parseCSV(csvBytes)
	if err != nil {
		t.Fatalf("parseCSV: %v", err)
	}
	out, err := render(list, prov)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(out)
	for _, want := range []string{sha, rawURL, wantHash} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered header missing %q", want)
		}
	}
}

func findGen(list []country, a2 string) (country, bool) {
	for _, c := range list {
		if c.Alpha2 == a2 {
			return c, true
		}
	}
	return country{}, false
}
