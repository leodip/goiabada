// This tool generates ../data_generated.go from the datahub
// `datasets/country-codes` dataset.
//
// Usage (from src/core/countries/generate):
//
//	go run .
//
// or via the repo helper:
//
//	./version-manager.sh generate countries
//
// It resolves the current upstream `main` commit, fetches the CSV from the
// immutable per-commit raw URL (so a moving branch cannot make output
// non-deterministic), records the commit SHA + CSV SHA-256 as provenance, and
// regenerates the committed data slice. It fails (rather than silently
// skipping) on any malformed or drifted source data so a human reviews changes.
package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// apiCommitsURL resolves the current tip commit of the upstream default
	// branch. We pin to the returned SHA and never fetch a moving ref again.
	apiCommitsURL = "https://api.github.com/repos/datasets/country-codes/commits/main"
	// rawURLFmt is the immutable per-commit raw CSV URL (%s = commit SHA).
	rawURLFmt = "https://raw.githubusercontent.com/datasets/country-codes/%s/data/country-codes.csv"

	// Size caps: read limit+1 and fail if exceeded (io.LimitReader alone
	// truncates silently). The CSV is ~130 KiB; the commit JSON is small.
	csvSizeLimit = int64(8 << 20) // 8 MiB
	apiSizeLimit = int64(4 << 20) // 4 MiB

	userAgent = "goiabada-countries-generator"

	// expectedUpstreamCount is the number of rows the upstream CSV is expected
	// to have BEFORE supplements. Any change (e.g. an upstream-added XK, or a
	// removed/added country) stops generation for human review.
	expectedUpstreamCount = 249
	// expectedGeneratedCount guards against silent country loss/addition:
	// 249 upstream rows + the XK supplement. Any drift stops generation.
	expectedGeneratedCount = expectedUpstreamCount + 1

	// maxCallingCodes bounds a country's calling codes. It mirrors the runtime
	// cap in phonecountries.Get (src/core/phonecountries/phone_countries.go),
	// which panics above 5 — so the generator must reject it first.
	maxCallingCodes = 5
)

// requiredColumns are located by header name; a missing one is fatal.
var requiredColumns = []string{
	"ISO3166-1-Alpha-2",
	"ISO3166-1-Alpha-3",
	"Dial",
	"CLDR display name",
	"official_name_en",
}

// country mirrors countries.Country for generation (kept local so the generator
// does not import the package it writes into).
type country struct {
	Name         string
	Alpha2       string
	Alpha3       string
	Emoji        string
	CallingCodes []string
}

// provenance is recorded verbatim in the generated file header (no wall-clock
// date, so identical source produces identical output).
type provenance struct {
	CommitSHA string
	SourceURL string
	CSVSHA256 string
}

// httpDoer is the injectable HTTP seam so tests never touch the network.
type httpDoer func(req *http.Request) (*http.Response, error)

func main() {
	client := &http.Client{Timeout: 60 * time.Second}
	if err := run(client.Do); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(doer httpDoer) error {
	csvBytes, prov, err := fetchPinned(doer)
	if err != nil {
		return err
	}

	list, err := parseCSV(csvBytes)
	if err != nil {
		return fmt.Errorf("parse CSV: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Parsed %d upstream rows\n", len(list))

	if err := validateUpstream(list); err != nil {
		return fmt.Errorf("validate upstream: %w", err)
	}

	list = applySupplements(list)

	if err := validate(list); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	sort.Slice(list, func(i, j int) bool { return list[i].Alpha2 < list[j].Alpha2 })

	out, err := render(list, prov)
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}

	outPath, err := outputPath()
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d countries to %s\n", len(list), outPath)
	return nil
}

// fetchPinned resolves the upstream tip commit, fetches the CSV from the
// immutable per-commit URL built from that SHA, and computes the provenance
// (commit SHA, immutable source URL, CSV SHA-256). Extracted from run so the
// full SHA → URL → hash chain is testable without touching the filesystem.
func fetchPinned(doer httpDoer) ([]byte, provenance, error) {
	fmt.Fprintln(os.Stderr, "Resolving upstream commit SHA...")
	sha, err := resolveSHA(doer)
	if err != nil {
		return nil, provenance{}, fmt.Errorf("resolve SHA: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Pinned commit: %s\n", sha)

	url := fmt.Sprintf(rawURLFmt, sha)
	fmt.Fprintf(os.Stderr, "Fetching %s\n", url)
	csvBytes, err := fetchCSV(doer, url)
	if err != nil {
		return nil, provenance{}, fmt.Errorf("fetch CSV: %w", err)
	}
	sum := sha256.Sum256(csvBytes)
	prov := provenance{CommitSHA: sha, SourceURL: url, CSVSHA256: hex.EncodeToString(sum[:])}
	return csvBytes, prov, nil
}

// resolveSHA fetches the tip commit of the upstream default branch.
func resolveSHA(doer httpDoer) (string, error) {
	body, err := doGet(doer, apiCommitsURL, apiSizeLimit)
	if err != nil {
		return "", err
	}
	var payload struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode commit JSON: %w", err)
	}
	if !isHex40(payload.SHA) {
		return "", fmt.Errorf("unexpected commit SHA %q", payload.SHA)
	}
	return payload.SHA, nil
}

// fetchCSV downloads the pinned CSV.
func fetchCSV(doer httpDoer, url string) ([]byte, error) {
	return doGet(doer, url, csvSizeLimit)
}

// doGet issues a GET with a User-Agent, checks for HTTP 200, and reads the body
// under a hard size cap (limit+1 read → fail if exceeded).
func doGet(doer httpDoer, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := doer(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %d", url, resp.StatusCode)
	}
	return readCapped(resp.Body, limit)
}

// readCapped reads at most limit bytes, failing if the source has more.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	return b, nil
}

// parseCSV parses the raw CSV into countries, locating columns by header name
// and normalizing the name, dial codes, and emoji. It does NOT apply
// supplements or run cross-row validation (those come after).
func parseCSV(data []byte) ([]country, error) {
	data = stripBOM(data)
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1 // tolerate ragged rows; we index by name

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}
	for _, col := range requiredColumns {
		if _, ok := idx[col]; !ok {
			return nil, fmt.Errorf("required column %q missing from header", col)
		}
	}
	get := func(rec []string, col string) string {
		i := idx[col]
		if i < 0 || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}

	var list []country
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read record: %w", err)
		}
		a2 := get(rec, "ISO3166-1-Alpha-2")
		a3 := get(rec, "ISO3166-1-Alpha-3")
		name := get(rec, "CLDR display name")
		if name == "" {
			name = get(rec, "official_name_en")
		}
		codes, err := normalizeDial(get(rec, "Dial"))
		if err != nil {
			return nil, fmt.Errorf("row %q: %w", a2, err)
		}
		list = append(list, country{
			Name:         name,
			Alpha2:       a2,
			Alpha3:       a3,
			Emoji:        emojiFromAlpha2(a2),
			CallingCodes: codes,
		})
	}
	return list, nil
}

// validateUpstream checks the parsed, PRE-supplement dataset matches the state
// the supplement policy assumes, so any upstream drift fails before writing:
// the row count, XK being absent (so the supplement is still needed), and UM
// being present with an empty dial (so the supplement fills it rather than
// masking a new upstream value).
func validateUpstream(list []country) error {
	if len(list) != expectedUpstreamCount {
		return fmt.Errorf("unexpected upstream row count %d (want %d); "+
			"upstream data may have changed — review supplements before regenerating", len(list), expectedUpstreamCount)
	}
	return checkSupplementPreconditions(list)
}

// checkSupplementPreconditions enforces the XK/UM policy assumptions on the
// pre-supplement data (split out so it is unit-testable with small fixtures).
func checkSupplementPreconditions(list []country) error {
	var um *country
	for i := range list {
		if list[i].Alpha2 == "XK" {
			return fmt.Errorf("upstream now provides XK; the XK supplement is now redundant — review generator supplements")
		}
		if list[i].Alpha2 == "UM" {
			um = &list[i]
		}
	}
	if um == nil {
		return fmt.Errorf("upstream no longer contains UM; review generator supplements")
	}
	if len(um.CallingCodes) != 0 {
		return fmt.Errorf("upstream now provides a UM dial %v; the UM supplement assumes it is empty — review generator supplements", um.CallingCodes)
	}
	return nil
}

// applySupplements adds/repairs entries the upstream dataset omits, matching the
// coverage of the library this package replaces:
//   - XK/XKX/+383 (Kosovo): absent upstream, added.
//   - UM (US Minor Outlying Islands): upstream Dial is empty; fill with "1".
//
// validateUpstream has already asserted the preconditions (XK absent, UM present
// & empty), so these are the only supplements applied. The is-absent / is-empty
// guards here are defensive belt-and-braces. Supplements run BEFORE validation
// so UM's just-filled dial does not trip the empty-calling-code check.
func applySupplements(list []country) []country {
	hasXK := false
	for i := range list {
		if list[i].Alpha2 == "XK" {
			hasXK = true
		}
		if list[i].Alpha2 == "UM" && len(list[i].CallingCodes) == 0 {
			list[i].CallingCodes = []string{"1"}
		}
	}
	if !hasXK {
		list = append(list, country{
			Name:         "Kosovo",
			Alpha2:       "XK",
			Alpha3:       "XKX",
			Emoji:        emojiFromAlpha2("XK"),
			CallingCodes: []string{"383"},
		})
	}
	return list
}

// validate enforces the invariants that protect the generated data. Any failure
// stops generation for human review.
func validate(list []country) error {
	if err := validateCount(list); err != nil {
		return err
	}
	return validateRows(list)
}

// validateCount guards against silent country loss/addition.
func validateCount(list []country) error {
	if len(list) != expectedGeneratedCount {
		return fmt.Errorf("unexpected country count %d (want %d = 249 upstream + XK); "+
			"upstream data may have changed — review before regenerating", len(list), expectedGeneratedCount)
	}
	return nil
}

// validateRows checks per-row and cross-row invariants (format, uniqueness,
// non-empty name/codes). It is independent of the total count so it can be
// exercised with small fixtures.
func validateRows(list []country) error {
	seenA2 := map[string]bool{}
	seenA3 := map[string]bool{}
	for _, c := range list {
		if !isUpperAlpha(c.Alpha2, 2) {
			return fmt.Errorf("invalid alpha-2 %q (name %q): want 2 upper-case letters", c.Alpha2, c.Name)
		}
		if !isUpperAlpha(c.Alpha3, 3) {
			return fmt.Errorf("invalid alpha-3 %q (alpha-2 %q): want 3 upper-case letters", c.Alpha3, c.Alpha2)
		}
		if seenA2[c.Alpha2] {
			return fmt.Errorf("duplicate alpha-2 %q", c.Alpha2)
		}
		if seenA3[c.Alpha3] {
			return fmt.Errorf("duplicate alpha-3 %q", c.Alpha3)
		}
		seenA2[c.Alpha2] = true
		seenA3[c.Alpha3] = true
		if c.Name == "" {
			return fmt.Errorf("empty name for %q", c.Alpha2)
		}
		if len(c.CallingCodes) == 0 {
			return fmt.Errorf("empty calling-code list for %q", c.Alpha2)
		}
		if len(c.CallingCodes) > maxCallingCodes {
			return fmt.Errorf("%q has %d calling codes (max %d); phonecountries.Get would panic at runtime",
				c.Alpha2, len(c.CallingCodes), maxCallingCodes)
		}
		seenCode := map[string]bool{}
		for _, code := range c.CallingCodes {
			if !isDigits(code) {
				return fmt.Errorf("invalid calling code %q for %q", code, c.Alpha2)
			}
			if seenCode[code] {
				return fmt.Errorf("duplicate calling code %q for %q", code, c.Alpha2)
			}
			seenCode[code] = true
		}
	}
	return nil
}

// dialTokenRe matches one supported Dial token: one or more digit groups
// separated by single hyphens, with an optional trailing whitespace+letters
// note. It accepts exactly the syntax observed in the upstream data
// ("297", "1-876", "39-06", "290 n", "381 p") and nothing else. Capture group 1
// is the digits-and-hyphens code; the note (group 0 tail) is discarded.
var dialTokenRe = regexp.MustCompile(`^([0-9]+(?:-[0-9]+)*)(?:\s+[A-Za-z]+)?$`)

// normalizeDial parses a datahub Dial cell into E.164 calling codes as digits
// only, without '+'. It splits on ',', and for each token strips hyphen
// separators and an optional trailing note (e.g. "1-876"→"1876", "39-06"→"3906",
// "381 p"→"381"). An empty/whitespace field yields no codes (nil, nil) — the
// supplement and empty-list validations handle that.
//
// Per the fail-on-malformed contract it returns an error (rather than silently
// repairing) on any unsupported token: embedded letters ("12x34"), stray
// punctuation ("1/234"), dangling hyphens ("1-"), or empty tokens ("1,,2").
func normalizeDial(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	var out []string
	for _, tok := range strings.Split(trimmed, ",") {
		t := strings.TrimSpace(tok)
		m := dialTokenRe.FindStringSubmatch(t)
		if m == nil {
			return nil, fmt.Errorf("unsupported dial token %q (in %q)", tok, raw)
		}
		out = append(out, strings.ReplaceAll(m[1], "-", ""))
	}
	return out, nil
}

// emojiFromAlpha2 derives a flag emoji from an alpha-2 code using Unicode
// regional-indicator symbols. Returns "" for a non-A..Z, non-length-2 input.
func emojiFromAlpha2(a2 string) string {
	if len(a2) != 2 {
		return ""
	}
	const base = 0x1F1E6 // REGIONAL INDICATOR SYMBOL LETTER A
	runes := make([]rune, 0, 2)
	for i := 0; i < 2; i++ {
		c := a2[i]
		if c < 'A' || c > 'Z' {
			return ""
		}
		runes = append(runes, rune(base+int(c-'A')))
	}
	return string(runes)
}

func isUpperAlpha(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func stripBOM(b []byte) []byte {
	const bom = "\xef\xbb\xbf"
	if strings.HasPrefix(string(b), bom) {
		return b[len(bom):]
	}
	return b
}

// render builds the generated Go source and formats it with go/format.
func render(list []country, prov provenance) ([]byte, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, `// Code generated by "go run ." in ./generate; DO NOT EDIT.
//
// Source:         %s
// Upstream commit: %s
// CSV SHA-256:     %s
//
// To regenerate this file, run from src/core/countries/generate:
//   go run .
// or from src/authserver:
//   ./version-manager.sh generate countries

package countries

// countries is the generated dataset, sorted by alpha-2. CallingCodes are
// digits without '+'.
var countries = []Country{
`, prov.SourceURL, prov.CommitSHA, prov.CSVSHA256)

	for _, c := range list {
		fmt.Fprintf(&sb, "\t{Name: %q, Alpha2: %q, Alpha3: %q, Emoji: %q, CallingCodes: %s},\n",
			c.Name, c.Alpha2, c.Alpha3, c.Emoji, renderCodes(c.CallingCodes))
	}
	sb.WriteString("}\n")

	formatted, err := format.Source([]byte(sb.String()))
	if err != nil {
		return nil, fmt.Errorf("format generated source: %w", err)
	}
	return formatted, nil
}

func renderCodes(codes []string) string {
	quoted := make([]string, len(codes))
	for i, c := range codes {
		quoted[i] = fmt.Sprintf("%q", c)
	}
	return "[]string{" + strings.Join(quoted, ", ") + "}"
}

// outputPath resolves ../data_generated.go relative to this source file.
func outputPath() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("could not determine current file path")
	}
	return filepath.Join(filepath.Dir(currentFile), "..", "data_generated.go"), nil
}
