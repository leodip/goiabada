package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/internal/pinnedfetch"
)

// fakeDoer serves canned responses keyed by request URL, so tests never touch
// the network. Any other URL gets a 404.
type fakeDoer map[string]fakeResp

type fakeResp struct {
	status int
	body   []byte
}

func (f fakeDoer) do(req *http.Request) (*http.Response, error) {
	r, ok := f[req.URL.String()]
	if !ok {
		r = fakeResp{status: http.StatusNotFound}
	}
	return &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(bytes.NewReader(r.body)),
		Header:     make(http.Header),
	}, nil
}

// fixtureRelease is the release every fixture tarball is served as and names in
// its version entry.
const fixtureRelease = "2026z"

// The fixture tables. ZZ's name holds a quote and a backslash and the
// Europe/Zurich comment a non-ASCII letter, which is what the escaping has to
// carry through; the zone lines are out of order, so the output's order is the
// generator's sort.
const (
	fixtureISO3166 = "# ISO 3166 alpha-2 country codes\n" +
		"#\n" +
		"#code\tname of country, territory, area, or subdivision\n" +
		"BR\tBrazil\n" +
		"CH\tSwitzerland\n" +
		"DE\tGermany\n" +
		"LI\tLiechtenstein\n" +
		"SE\tSweden\n" +
		"ZZ\tQuote \"Land\" \\ Back\n"

	fixtureZone1970 = "# tzdb timezone descriptions\n" +
		"#\n" +
		"SE,ZZ\t+5920+01803\tEurope/Stockholm\n" +
		"DE\t+5230+01322\tEurope/Berlin\tmost of Germany\n" +
		"CH,DE,LI\t+4723+00832\tEurope/Zurich\tBüsingen\n" +
		"BR\t-2332-04637\tAmerica/Sao_Paulo\tBrazil (southeast)\n"
)

// fixtureRows is what the fixture tables parse to, in the generator's order.
// Germany is the one country with two rows, so it alone keeps its comments.
var fixtureRows = []zone{
	{CountryCode: "BR", Zone: "America/Sao_Paulo", CountryName: "Brazil", Comments: ""},
	{CountryCode: "DE", Zone: "Europe/Berlin", CountryName: "Germany", Comments: "most of Germany"},
	{CountryCode: "DE", Zone: "Europe/Zurich", CountryName: "Germany", Comments: "Büsingen"},
	{CountryCode: "LI", Zone: "Europe/Zurich", CountryName: "Liechtenstein", Comments: ""},
	{CountryCode: "ZZ", Zone: "Europe/Stockholm", CountryName: `Quote "Land" \ Back`, Comments: ""},
	{CountryCode: "SE", Zone: "Europe/Stockholm", CountryName: "Sweden", Comments: ""},
	{CountryCode: "CH", Zone: "Europe/Zurich", CountryName: "Switzerland", Comments: ""},
}

// entry is one member of a fixture tarball. A zero typeflag is a regular file.
type entry struct {
	name     string
	body     string
	typeflag byte
}

func fixtureEntries() []entry {
	return []entry{
		{name: "version", body: fixtureRelease + "\n"},
		{name: "africa", body: "# a zone source the generator does not read\n"},
		{name: "iso3166.tab", body: fixtureISO3166},
		{name: "zone1970.tab", body: fixtureZone1970},
	}
}

// replacing returns the fixture entries with name's body replaced.
func replacing(name, body string) []entry {
	entries := fixtureEntries()
	for i := range entries {
		if entries[i].name == name {
			entries[i].body = body
		}
	}
	return entries
}

// without returns the fixture entries with name left out.
func without(name string) []entry {
	var entries []entry
	for _, e := range fixtureEntries() {
		if e.name != name {
			entries = append(entries, e)
		}
	}
	return entries
}

// buildTarball writes entries into a gzipped tar archive in memory.
func buildTarball(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0644, Typeflag: e.typeflag}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.body))
		} else {
			hdr.Linkname = "elsewhere"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("tar body %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// serve answers the fixture release's URL with body and returns the pin whose
// digest is body's own, so generate gets past the check.
func serve(body []byte) (pinnedfetch.Doer, pin) {
	d := fakeDoer{fmt.Sprintf(releaseURLFmt, fixtureRelease): {status: http.StatusOK, body: body}}
	return d.do, pin{release: fixtureRelease, sha256: sha256Hex(body)}
}

// requireRefusal fails unless err is non-nil and names every one of want, so a
// fixture refused at an earlier boundary than the case means fails the case.
func requireRefusal(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("generate accepted the fixture")
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not name %q", err, w)
		}
	}
}

// readBack parses rendered source and returns its table's rows, each field
// through strconv.Unquote, so what a consumer of the file sees is compared.
func readBack(t *testing.T, src []byte) []zone {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "data_generated.go", src, 0)
	if err != nil {
		t.Fatalf("parse rendered source: %v", err)
	}
	var rows []zone
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Names[0].Name != "zones" {
				continue
			}
			for _, elt := range vs.Values[0].(*ast.CompositeLit).Elts {
				fields := map[string]string{}
				for _, kv := range elt.(*ast.CompositeLit).Elts {
					kv := kv.(*ast.KeyValueExpr)
					s, err := strconv.Unquote(kv.Value.(*ast.BasicLit).Value)
					if err != nil {
						t.Fatalf("unquote %s: %v", kv.Value.(*ast.BasicLit).Value, err)
					}
					fields[kv.Key.(*ast.Ident).Name] = s
				}
				rows = append(rows, zone{
					CountryCode: fields["CountryCode"],
					Zone:        fields["Zone"],
					CountryName: fields["CountryName"],
					Comments:    fields["Comments"],
				})
			}
		}
	}
	return rows
}

func TestGenerate(t *testing.T) {
	t.Run("the fixture renders its rows sorted, type-checks, and records its provenance", func(t *testing.T) {
		tarball := buildTarball(t, fixtureEntries())
		d, p := serve(tarball)

		out, err := generate(d, p)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		for _, want := range []string{
			"// Code generated", "DO NOT EDIT", "package timezones", "var zones = []Zone{",
			"tzdata release:  " + fixtureRelease,
			"Source:          " + fmt.Sprintf(releaseURLFmt, fixtureRelease),
			"Tarball SHA-256: " + p.sha256,
		} {
			if !strings.Contains(string(out), want) {
				t.Errorf("rendered output missing %q", want)
			}
		}
		if got := readBack(t, out); !reflect.DeepEqual(got, fixtureRows) {
			t.Errorf("rows read back:\n%v\nwant:\n%v", got, fixtureRows)
		}
		guard.AssertGeneratedSourceTypeChecks(t, "..", "data_generated.go", out)
	})

	// The old template escaped quotes and backslashes and then %q escaped them
	// again, so a name holding either would have read back with its escapes
	// doubled. No committed row held one, which is why nothing saw it (#432).
	t.Run("a quote, a backslash and a non-ASCII letter read back unchanged", func(t *testing.T) {
		d, p := serve(buildTarball(t, fixtureEntries()))

		out, err := generate(d, p)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		rows := readBack(t, out)
		var names, comments []string
		for _, r := range rows {
			names = append(names, r.CountryName)
			comments = append(comments, r.Comments)
		}
		if !contains(names, `Quote "Land" \ Back`) {
			t.Errorf("no row reads back the name %q: %q", `Quote "Land" \ Back`, names)
		}
		if !contains(comments, "Büsingen") {
			t.Errorf("no row reads back the comment %q: %q", "Büsingen", comments)
		}
	})
}

// TestKeepMultiZoneComments: zone1970.tab's column 4 is useful only for a
// country with several zones, so a country with one row loses its comment and
// a country with more keeps every one (#432).
func TestKeepMultiZoneComments(t *testing.T) {
	cases := []struct {
		name string
		in   []zone
		want []zone
	}{
		{
			// IANA's own example: the Europe/Zurich comment describes Büsingen,
			// which is in Germany, so it survives for DE alone.
			name: "a row shared by CH, DE and LI keeps its comment for DE, which has another zone",
			in: []zone{
				{CountryCode: "CH", Zone: "Europe/Zurich", Comments: "Büsingen"},
				{CountryCode: "DE", Zone: "Europe/Zurich", Comments: "Büsingen"},
				{CountryCode: "LI", Zone: "Europe/Zurich", Comments: "Büsingen"},
				{CountryCode: "DE", Zone: "Europe/Berlin", Comments: "most of Germany"},
			},
			want: []zone{
				{CountryCode: "CH", Zone: "Europe/Zurich", Comments: ""},
				{CountryCode: "DE", Zone: "Europe/Zurich", Comments: "Büsingen"},
				{CountryCode: "LI", Zone: "Europe/Zurich", Comments: ""},
				{CountryCode: "DE", Zone: "Europe/Berlin", Comments: "most of Germany"},
			},
		},
		{
			name: "a single-country, single-zone row with a comment is emptied",
			in:   []zone{{CountryCode: "BR", Zone: "America/Sao_Paulo", Comments: "Brazil (southeast)"}},
			want: []zone{{CountryCode: "BR", Zone: "America/Sao_Paulo", Comments: ""}},
		},
		{
			name: "a country with two zones keeps both comments",
			in: []zone{
				{CountryCode: "PT", Zone: "Europe/Lisbon", Comments: "Portugal (mainland)"},
				{CountryCode: "PT", Zone: "Atlantic/Madeira", Comments: "Madeira Islands"},
			},
			want: []zone{
				{CountryCode: "PT", Zone: "Europe/Lisbon", Comments: "Portugal (mainland)"},
				{CountryCode: "PT", Zone: "Atlantic/Madeira", Comments: "Madeira Islands"},
			},
		},
		{
			name: "a row without a comment stays without one",
			in: []zone{
				{CountryCode: "PT", Zone: "Europe/Lisbon"},
				{CountryCode: "PT", Zone: "Atlantic/Madeira", Comments: "Madeira Islands"},
				{CountryCode: "SE", Zone: "Europe/Stockholm"},
			},
			want: []zone{
				{CountryCode: "PT", Zone: "Europe/Lisbon"},
				{CountryCode: "PT", Zone: "Atlantic/Madeira", Comments: "Madeira Islands"},
				{CountryCode: "SE", Zone: "Europe/Stockholm"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keepMultiZoneComments(c.in)
			if !reflect.DeepEqual(c.in, c.want) {
				t.Errorf("got:\n%v\nwant:\n%v", c.in, c.want)
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// lineAfter is the 1-based number of a line appended to table.
func lineAfter(table string) int {
	return strings.Count(table, "\n") + 1
}

// TestGenerate_RefusesTheArchive: every case is a tarball that hashes to its own
// pin, so what refuses it is the check the case names.
func TestGenerate_RefusesTheArchive(t *testing.T) {
	cases := []struct {
		name    string
		entries []entry
		want    []string
	}{
		{"a version entry naming another release", replacing("version", "2026y\n"),
			[]string{`version entry names release "2026y"`, `the pin is "` + fixtureRelease + `"`}},
		{"no version entry", without("version"), []string{"the tarball holds no version"}},
		{"no iso3166.tab", without("iso3166.tab"), []string{"the tarball holds no iso3166.tab"}},
		{"no zone1970.tab", without("zone1970.tab"), []string{"the tarball holds no zone1970.tab"}},
		{"a zone1970.tab that is not a regular file",
			append(without("zone1970.tab"), entry{name: "zone1970.tab", typeflag: tar.TypeSymlink}),
			[]string{"the tarball holds no zone1970.tab"}},
		{"an entry present twice", append(fixtureEntries(), entry{name: "version", body: fixtureRelease + "\n"}),
			[]string{"the tarball holds version twice"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := generate(serve(buildTarball(t, c.entries)))
			requireRefusal(t, err, c.want...)
		})
	}

	t.Run("bytes that are not gzip", func(t *testing.T) {
		_, err := generate(serve([]byte("not a gzip stream")))
		requireRefusal(t, err, "gunzip the tarball")
	})
}

// TestGenerate_RefusesTheTables: each case appends one line to one table of an
// otherwise valid fixture, and the refusal must name the file, the line and the
// cause.
func TestGenerate_RefusesTheTables(t *testing.T) {
	zoneLine := lineAfter(fixtureZone1970)
	isoLine := lineAfter(fixtureISO3166)
	cases := []struct {
		name  string
		entry string
		line  string
		want  []string
	}{
		{"a zone row with fewer than three columns", "zone1970.tab", "BR\t-2332-04637",
			[]string{fmt.Sprintf("zone1970.tab line %d has 2 columns, want at least 3", zoneLine), `"BR\t-2332-04637"`}},
		{"a country code iso3166.tab does not name", "zone1970.tab", "XX\t+0000+00000\tEtc/Nowhere",
			[]string{fmt.Sprintf("zone1970.tab line %d: country code XX is not in iso3166.tab", zoneLine)}},
		{"a lower-case country code", "zone1970.tab", "br\t-0308-06001\tAmerica/Manaus",
			[]string{fmt.Sprintf(`zone1970.tab line %d: country code "br" is not two upper-case letters`, zoneLine)}},
		{"an empty zone name", "zone1970.tab", "BR\t-0308-06001\t\tAmazonas",
			[]string{fmt.Sprintf("zone1970.tab line %d has an empty zone name", zoneLine)}},
		{"a (country, zone) pair listed twice", "zone1970.tab", "BR\t-2332-04637\tAmerica/Sao_Paulo",
			[]string{fmt.Sprintf("zone1970.tab line %d: BR America/Sao_Paulo is listed twice", zoneLine)}},
		{"an iso3166.tab line without a tab", "iso3166.tab", "XK Kosovo",
			[]string{fmt.Sprintf(`iso3166.tab line %d has no tab: "XK Kosovo"`, isoLine)}},
		{"an iso3166.tab lower-case code", "iso3166.tab", "xk\tKosovo",
			[]string{fmt.Sprintf(`iso3166.tab line %d: country code "xk" is not two upper-case letters`, isoLine)}},
		{"an iso3166.tab empty name", "iso3166.tab", "XK\t",
			[]string{fmt.Sprintf("iso3166.tab line %d: country XK has an empty name", isoLine)}},
		{"an iso3166.tab code listed twice", "iso3166.tab", "BR\tBrasil",
			[]string{fmt.Sprintf("iso3166.tab line %d: country BR is listed twice", isoLine)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			table := fixtureZone1970
			if c.entry == "iso3166.tab" {
				table = fixtureISO3166
			}
			_, err := generate(serve(buildTarball(t, replacing(c.entry, table+c.line+"\n"))))
			requireRefusal(t, err, c.want...)
		})
	}
}

// TestGenerate_RefusesTheDownload covers what happens before the archive is
// read: the digest, the status, and both ceilings.
func TestGenerate_RefusesTheDownload(t *testing.T) {
	t.Run("another digest: refused, naming the pinned and the received hash", func(t *testing.T) {
		tarball := buildTarball(t, fixtureEntries())
		d, p := serve(tarball)
		p.sha256 = strings.Repeat("0", 64)

		_, err := generate(d, p)
		requireRefusal(t, err, "SHA-256 mismatch", p.sha256, sha256Hex(tarball))
	})

	t.Run("a status other than 200", func(t *testing.T) {
		d := fakeDoer{fmt.Sprintf(releaseURLFmt, fixtureRelease): {status: http.StatusInternalServerError}}

		_, err := generate(d.do, pin{release: fixtureRelease, sha256: sha256Hex(nil)})
		requireRefusal(t, err, "unexpected status 500")
	})

	t.Run("a tarball over its ceiling", func(t *testing.T) {
		_, err := generate(serve(bytes.Repeat([]byte{0}, int(tarballSizeLimit)+1)))
		requireRefusal(t, err, "fetch tarball")
		if !errors.Is(err, boundedread.ErrResponseTooLarge) {
			t.Errorf("error %q is not boundedread.ErrResponseTooLarge", err)
		}
	})

	// A tarball well under its own ceiling that expands past the decompressed
	// one: gzip compresses a run of zeros about a thousandfold.
	t.Run("a tarball that decompresses over its ceiling", func(t *testing.T) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(make([]byte, decompressedSizeLimit+1)); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if int64(buf.Len()) > tarballSizeLimit {
			t.Fatalf("the fixture is %d bytes, over the tarball ceiling it is meant to pass", buf.Len())
		}

		_, err := generate(serve(buf.Bytes()))
		requireRefusal(t, err, "decompress the tarball")
		if !errors.Is(err, boundedread.ErrResponseTooLarge) {
			t.Errorf("error %q is not boundedread.ErrResponseTooLarge", err)
		}
	})

	// The production pin, which run passes. No fixture can hash to its digest,
	// so this is the case that ties run to the constants: it fails if the check
	// is skipped or the pin stops being the one the header claims.
	t.Run("the production pin refuses any tarball but its own", func(t *testing.T) {
		tarball := buildTarball(t, fixtureEntries())
		d := fakeDoer{fmt.Sprintf(releaseURLFmt, pinnedRelease): {status: http.StatusOK, body: tarball}}

		_, err := generate(d.do, pinned)
		requireRefusal(t, err, "tzdata "+pinnedRelease, pinnedTarballSHA256, sha256Hex(tarball))
	})
}
