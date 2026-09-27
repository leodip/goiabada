// This tool generates ../data_generated.go from IANA tzdata.
//
// Usage (from src/core/timezones/generate):
//
//	go run .
//
// or via the repo helper:
//
//	./version-manager.sh generate timezones
//
// It fetches the tarball of one pinned tzdata release, refuses it unless its
// SHA-256 is the pinned one and its own version entry names that release, reads
// zone1970.tab and iso3166.tab from it in memory, and regenerates the committed
// table. The header records the release, URL and hash and no date, so identical
// pins give identical output. A malformed row or a country code iso3166.tab
// does not name fails the run rather than being skipped, so a human reviews it.
//
// To move to a newer release:
//
//  1. Look up the latest release (https://data.iana.org/time-zones/tzdb/version).
//  2. Set pinnedRelease to it and run; the run refuses the tarball and prints
//     the SHA-256 it received.
//  3. Set pinnedTarballSHA256 to that hash and run again.
//  4. Review the diff of data_generated.go before committing it.
//
// The first fetch of a release is trusted on first use: IANA publishes a PGP
// signature beside each tarball and no digest file, and this tool does not
// verify the signature.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/internal/pinnedfetch"
)

const (
	// pinnedRelease is the tzdata release the table is generated from, and
	// pinnedTarballSHA256 the SHA-256 of its tarball. A run fetches that one
	// release and refuses any other bytes, so the table moves only when a human
	// moves these two (see the steps above). The latest release used to be
	// scraped from IANA's page at run time, which made two runs of one tree
	// disagree and broke once when the page changed (#432).
	pinnedRelease       = "2026c"
	pinnedTarballSHA256 = "e4a178a4477f3d0ea77cc31828ff72aa38feff8d61aa13e7e99e142e9d902be4"

	// releaseURLFmt is a release's tarball URL (%s = release name).
	releaseURLFmt = "https://data.iana.org/time-zones/releases/tzdata%s.tar.gz"

	// tarballSizeLimit caps the download and decompressedSizeLimit the
	// decompressed archive, each read through boundedread.Read, which refuses an
	// overrun rather than truncating it. A release's tarball is under 500 KB and
	// expands to under 2 MB.
	tarballSizeLimit      = int64(8 << 20)  // 8 MiB
	decompressedSizeLimit = int64(16 << 20) // 16 MiB

	userAgent = "goiabada-timezones-generator"
)

// The three archive entries the run reads. Each must be present, once, as a
// regular file.
const (
	versionEntry  = "version"
	iso3166Entry  = "iso3166.tab"
	zone1970Entry = "zone1970.tab"
)

var tarEntries = []string{versionEntry, iso3166Entry, zone1970Entry}

// zone mirrors timezones.Zone for generation (kept local so the generator does
// not import the package it writes into).
type zone struct {
	CountryCode string
	Zone        string
	CountryName string
	Comments    string
}

// provenance is recorded verbatim in the generated file header (no wall-clock
// date, so identical source produces identical output).
type provenance struct {
	Release       string
	SourceURL     string
	TarballSHA256 string
}

// pin names one tzdata release and the SHA-256 its tarball must have.
//
// It is a parameter below run rather than read from the constants inside
// generate because no fixture tarball can hash to the real digest: a test
// calling through the constants would never get past the check to the parser.
// run passes pinned, the one value built from the constants, so production has
// no other path (#432).
type pin struct {
	release string
	sha256  string
}

var pinned = pin{release: pinnedRelease, sha256: pinnedTarballSHA256}

func main() {
	client := &http.Client{Timeout: 60 * time.Second}
	if err := run(client.Do); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(doer pinnedfetch.Doer) error {
	out, err := generate(doer, pinned)
	if err != nil {
		return err
	}

	outPath, err := outputPath()
	if err != nil {
		return err
	}
	//nolint:gosec // G306: the output is a committed source file, world-readable on purpose like every file in the repository.
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return errs.Errorf("write %s: %w", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s\n", outPath)
	return nil
}

// generate does everything from the fetch to render and writes nothing: it
// fetches p's tarball, refuses it unless its SHA-256 and its version entry are
// p's, parses both tables, sorts the rows and renders the file.
func generate(doer pinnedfetch.Doer, p pin) ([]byte, error) {
	url := fmt.Sprintf(releaseURLFmt, p.release)
	fmt.Fprintf(os.Stderr, "Fetching %s\n", url)
	tarball, err := pinnedfetch.Get(doer, url, userAgent, tarballSizeLimit)
	if err != nil {
		return nil, errs.Errorf("fetch tarball: %w", err)
	}
	sum, err := pinnedfetch.CheckSHA256(tarball, p.sha256)
	if err != nil {
		return nil, errs.Errorf("tzdata %s: %w", p.release, err)
	}

	entries, err := readEntries(tarball)
	if err != nil {
		return nil, errs.Errorf("tzdata %s: %w", p.release, err)
	}
	if got := strings.TrimSuffix(string(entries[versionEntry]), "\n"); got != p.release {
		return nil, errs.Errorf("the tarball's %s entry names release %q, but the pin is %q", versionEntry, got, p.release)
	}

	countries, err := parseISO3166(entries[iso3166Entry])
	if err != nil {
		return nil, err
	}
	zones, err := parseZone1970(entries[zone1970Entry], countries)
	if err != nil {
		return nil, err
	}
	keepMultiZoneComments(zones)
	sortZones(zones)
	fmt.Fprintf(os.Stderr, "Parsed %d rows\n", len(zones))

	return render(zones, provenance{Release: p.release, SourceURL: url, TarballSHA256: sum})
}

// readEntries decompresses the tarball in memory and returns the contents of
// the entries the run reads, refusing one that is missing or appears twice.
// Nothing touches the filesystem, so no entry name is ever joined into a path.
func readEntries(tarball []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, errs.Wrap(err, "gunzip the tarball")
	}
	raw, err := boundedread.Read(gz, decompressedSizeLimit)
	if err != nil {
		return nil, errs.Wrap(err, "decompress the tarball")
	}

	wanted := map[string]bool{}
	for _, name := range tarEntries {
		wanted[name] = true
	}
	entries := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errs.Wrap(err, "read the tar archive")
		}
		if hdr.Typeflag != tar.TypeReg || !wanted[hdr.Name] {
			continue
		}
		if _, seen := entries[hdr.Name]; seen {
			return nil, errs.Errorf("the tarball holds %s twice", hdr.Name)
		}
		// The archive is already in memory under decompressedSizeLimit, so this
		// read is bounded by it.
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, errs.Wrapf(err, "read %s", hdr.Name)
		}
		entries[hdr.Name] = body
	}
	for _, name := range tarEntries {
		if _, ok := entries[name]; !ok {
			return nil, errs.Errorf("the tarball holds no %s", name)
		}
	}
	return entries, nil
}

// dataLines calls fn with the 1-based number and text of every line that is
// neither blank nor a '#' comment.
func dataLines(data []byte, fn func(n int, line string) error) error {
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if err := fn(i+1, line); err != nil {
			return err
		}
	}
	return nil
}

// parseISO3166 reads iso3166.tab into a map from alpha-2 code to tzdata's
// English country name. Each data line is a code, a tab, and the name.
func parseISO3166(data []byte) (map[string]string, error) {
	countries := map[string]string{}
	err := dataLines(data, func(n int, line string) error {
		code, name, ok := strings.Cut(line, "\t")
		if !ok {
			return errs.Errorf("%s line %d has no tab: %q", iso3166Entry, n, line)
		}
		if !isUpperAlpha2(code) {
			return errs.Errorf("%s line %d: country code %q is not two upper-case letters", iso3166Entry, n, code)
		}
		if name == "" {
			return errs.Errorf("%s line %d: country %s has an empty name", iso3166Entry, n, code)
		}
		if _, dup := countries[code]; dup {
			return errs.Errorf("%s line %d: country %s is listed twice", iso3166Entry, n, code)
		}
		countries[code] = name
		return nil
	})
	if err != nil {
		return nil, err
	}
	return countries, nil
}

// parseZone1970 reads zone1970.tab into one row per (country, zone): a line's
// first column is a comma-separated list of country codes, its third the zone
// ID and its optional fourth a comment, given here to every country on the line
// (keepMultiZoneComments then empties it where it does not apply). Every
// country code must name a country in iso3166.tab, whose name the row takes.
func parseZone1970(data []byte, countries map[string]string) ([]zone, error) {
	var zones []zone
	seen := map[[2]string]bool{}
	err := dataLines(data, func(n int, line string) error {
		cols := strings.Split(line, "\t")
		if len(cols) < 3 {
			return errs.Errorf("%s line %d has %d columns, want at least 3: %q", zone1970Entry, n, len(cols), line)
		}
		zoneID := cols[2]
		if zoneID == "" {
			return errs.Errorf("%s line %d has an empty zone name: %q", zone1970Entry, n, line)
		}
		comments := ""
		if len(cols) > 3 {
			comments = cols[3]
		}
		for _, code := range strings.Split(cols[0], ",") {
			if !isUpperAlpha2(code) {
				return errs.Errorf("%s line %d: country code %q is not two upper-case letters", zone1970Entry, n, code)
			}
			name, ok := countries[code]
			if !ok {
				return errs.Errorf("%s line %d: country code %s is not in %s", zone1970Entry, n, code, iso3166Entry)
			}
			key := [2]string{code, zoneID}
			if seen[key] {
				return errs.Errorf("%s line %d: %s %s is listed twice", zone1970Entry, n, code, zoneID)
			}
			seen[key] = true
			zones = append(zones, zone{CountryCode: code, Zone: zoneID, CountryName: name, Comments: comments})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return zones, nil
}

// keepMultiZoneComments empties the comment of every row whose country has no
// other row. zone1970.tab's header says column 4 is "present if and only if
// countries have multiple timezones, and useful only for those countries",
// giving Europe/Zurich's CH,DE,LI row as the example: its comment describes
// Büsingen in Germany, not Switzerland or Liechtenstein. Copying it to every
// country on the line labelled 63 single-zone countries with another country's
// region at 2026c, e.g. Sweden's Europe/Berlin as "most of Germany" (#432).
func keepMultiZoneComments(zones []zone) {
	rows := map[string]int{}
	for _, z := range zones {
		rows[z.CountryCode]++
	}
	for i := range zones {
		if rows[zones[i].CountryCode] > 1 {
			continue
		}
		zones[i].Comments = ""
	}
}

// sortZones orders the rows by country name and then zone ID, the order the
// picker renders. The country code breaks a tie, which two countries sharing a
// name would need, so the order never depends on the input's.
func sortZones(zones []zone) {
	sort.Slice(zones, func(i, j int) bool {
		a, b := zones[i], zones[j]
		if a.CountryName != b.CountryName {
			return a.CountryName < b.CountryName
		}
		if a.Zone != b.Zone {
			return a.Zone < b.Zone
		}
		return a.CountryCode < b.CountryCode
	})
}

func isUpperAlpha2(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

// render builds the generated Go source and formats it with go/format. Every
// field goes through %q alone: the old template escaped quotes and backslashes
// before %q escaped them again (#432).
func render(zones []zone, prov provenance) ([]byte, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, `// Code generated by "go run ." in ./generate; DO NOT EDIT.
//
// Source:          %s
// tzdata release:  %s
// Tarball SHA-256: %s
//
// To regenerate this file, run from src/core/timezones/generate:
//   go run .
// or from src/authserver:
//   ./version-manager.sh generate timezones

package timezones

// zones is the generated table, sorted by country name and then zone ID.
var zones = []Zone{
`, prov.SourceURL, prov.Release, prov.TarballSHA256)

	for _, z := range zones {
		fmt.Fprintf(&sb, "\t{CountryCode: %q, Zone: %q, CountryName: %q, Comments: %q},\n",
			z.CountryCode, z.Zone, z.CountryName, z.Comments)
	}
	sb.WriteString("}\n")

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
