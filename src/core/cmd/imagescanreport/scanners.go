package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// scanner is one of the three tools whose output the report reads, in the order the report names them.
type scanner int

const (
	trivy scanner = iota
	grype
	govulncheck
)

func (s scanner) String() string {
	return [...]string{"Trivy", "Grype", "govulncheck"}[s]
}

// record is one scanner's report of one advisory in one package of one image.
type record struct {
	scanner   scanner
	image     string
	ids       []string // the scanner's identifier for the advisory first, then its aliases
	pkg       string
	installed string
	fixed     []string
	goPackage bool
	reachable bool     // govulncheck's alone: the vulnerable symbol is called
	symbols   []string // the symbols govulncheck found called
}

// The identifiers, package names and versions the report writes come from the scanners' databases
// and go into a public issue, so each is held to what those values look like: no space, no Markdown,
// no @ that would mention someone. A value outside it fails the scan rather than reaching the issue.
var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	valuePattern      = regexp.MustCompile(`^[A-Za-z0-9(][A-Za-z0-9._:/+~()-]*$`)
	symbolPattern     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./()*-]*$`)
)

// readScan reads one image's scan directory: the name the report calls the image by, and every
// record its three scanners wrote.
func readScan(dir string) (string, []record, error) {
	content, err := readFile(dir, "image")
	if err != nil {
		return "", nil, err
	}
	image := strings.TrimSpace(string(content))
	if image == "" || strings.ContainsAny(image, "\n`@") {
		return "", nil, errs.Errorf("%s: the image file names no image, or one the report cannot write", dir)
	}
	var records []record
	for _, read := range []struct {
		file  string
		parse func([]byte, string) ([]record, error)
	}{
		{"trivy.json", parseTrivy},
		{"grype.json", parseGrype},
		{"govulncheck.json", parseGovulncheck},
	} {
		content, err := readFile(dir, read.file)
		if err != nil {
			return "", nil, err
		}
		parsed, err := read.parse(content, image)
		if err != nil {
			return "", nil, errs.Wrapf(err, "%s", filepath.Join(dir, read.file))
		}
		for _, r := range parsed {
			if err := r.check(); err != nil {
				return "", nil, errs.Wrapf(err, "%s", filepath.Join(dir, read.file))
			}
		}
		records = append(records, parsed...)
	}
	return image, records, nil
}

func readFile(dir, name string) ([]byte, error) {
	path := filepath.Join(dir, name)
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.Wrapf(err, "reading %s", path)
	}
	return content, nil
}

func (r record) check() error {
	if len(r.ids) == 0 || r.pkg == "" {
		return errs.New("a finding names no advisory or no package")
	}
	for _, id := range r.ids {
		if !identifierPattern.MatchString(id) {
			return errs.Errorf("the advisory identifier %q is not one the report can write", id)
		}
	}
	values := append([]string{r.pkg, r.installed}, r.fixed...)
	for _, v := range values {
		if v != "" && !valuePattern.MatchString(v) {
			return errs.Errorf("the package name or version %q is not one the report can write", v)
		}
	}
	for _, s := range r.symbols {
		if !symbolPattern.MatchString(s) {
			return errs.Errorf("the symbol %q is not one the report can write", s)
		}
	}
	return nil
}

// trivyReport is the part of Trivy's JSON report, schema version 2, the report reads.
type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Results       []struct {
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			VendorIDs        []string `json:"VendorIDs"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivy(content []byte, image string) ([]record, error) {
	var report trivyReport
	if err := json.Unmarshal(content, &report); err != nil {
		return nil, errs.Wrap(err, "reading Trivy's report")
	}
	if report.SchemaVersion != 2 || report.ArtifactName == "" {
		return nil, errs.Errorf("not a Trivy report of schema version 2 (schema version %d, artifact %q)", report.SchemaVersion, report.ArtifactName)
	}
	var records []record
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			var fixed []string
			for f := range strings.SplitSeq(v.FixedVersion, ",") {
				if f = strings.TrimSpace(f); f != "" {
					fixed = append(fixed, f)
				}
			}
			records = append(records, record{
				scanner:   trivy,
				image:     image,
				ids:       append([]string{v.VulnerabilityID}, v.VendorIDs...),
				pkg:       v.PkgName,
				installed: v.InstalledVersion,
				fixed:     fixed,
				goPackage: result.Class == "lang-pkgs" && result.Type == "gobinary",
			})
		}
	}
	return records, nil
}

// grypeReport is the part of Grype's JSON report the report reads.
type grypeReport struct {
	Descriptor struct {
		Name string `json:"name"`
	} `json:"descriptor"`
	Matches []struct {
		Vulnerability struct {
			ID  string `json:"id"`
			Fix struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
}

func parseGrype(content []byte, image string) ([]record, error) {
	var report grypeReport
	if err := json.Unmarshal(content, &report); err != nil {
		return nil, errs.Wrap(err, "reading Grype's report")
	}
	// Grype writes "matches": [] for an image with nothing in it, so a report without the list is
	// not one Grype finished.
	if report.Descriptor.Name != "grype" || report.Matches == nil {
		return nil, errs.Errorf("not a Grype report (descriptor %q)", report.Descriptor.Name)
	}
	var records []record
	for _, m := range report.Matches {
		ids := []string{m.Vulnerability.ID}
		for _, related := range m.RelatedVulnerabilities {
			ids = append(ids, related.ID)
		}
		records = append(records, record{
			scanner:   grype,
			image:     image,
			ids:       ids,
			pkg:       m.Artifact.Name,
			installed: m.Artifact.Version,
			fixed:     m.Vulnerability.Fix.Versions,
			goPackage: m.Artifact.Type == "go-module",
		})
	}
	return records, nil
}

// govulncheckMessage is one message of govulncheck's JSON stream, protocol version 1, as far as the
// report reads it.
type govulncheckMessage struct {
	Config *struct {
		ProtocolVersion string `json:"protocol_version"`
		ScannerName     string `json:"scanner_name"`
	} `json:"config"`
	OSV *struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
	} `json:"osv"`
	Finding *struct {
		OSV          string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace        []struct {
			Module   string `json:"module"`
			Version  string `json:"version"`
			Package  string `json:"package"`
			Function string `json:"function"`
			Receiver string `json:"receiver"`
		} `json:"trace"`
	} `json:"finding"`
}

func parseGovulncheck(content []byte, image string) ([]record, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	configured := false
	aliases := map[string][]string{}
	var records []record
	for {
		var message govulncheckMessage
		err := decoder.Decode(&message)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errs.Wrap(err, "reading govulncheck's stream")
		}
		switch {
		case message.Config != nil:
			if message.Config.ScannerName != "govulncheck" || !strings.HasPrefix(message.Config.ProtocolVersion, "v1.") {
				return nil, errs.Errorf("not a govulncheck stream of protocol version 1 (scanner %q, protocol %q)", message.Config.ScannerName, message.Config.ProtocolVersion)
			}
			configured = true
		case message.OSV != nil:
			aliases[message.OSV.ID] = message.OSV.Aliases
		case message.Finding != nil:
			f := message.Finding
			if len(f.Trace) == 0 {
				return nil, errs.Errorf("govulncheck's finding of %s has no trace", f.OSV)
			}
			// The first frame is the vulnerable symbol, and it names a function only when the
			// binary calls it; a finding at the module or package level is one nothing reaches.
			frame := f.Trace[0]
			r := record{
				scanner:   govulncheck,
				image:     image,
				ids:       []string{f.OSV},
				pkg:       frame.Module,
				installed: frame.Version,
				goPackage: true,
			}
			if f.FixedVersion != "" {
				r.fixed = []string{f.FixedVersion}
			}
			if frame.Function != "" {
				r.reachable = true
				r.symbols = []string{symbol(frame.Package, frame.Receiver, frame.Function)}
			}
			records = append(records, r)
		}
	}
	if !configured {
		return nil, errs.New("not a govulncheck stream: it has no config message")
	}
	// The OSV records come before the findings that name them, but a finding is matched only once the
	// whole stream is read, so a stream in another order still merges by its aliases.
	for i, r := range records {
		known, ok := aliases[r.ids[0]]
		if !ok {
			return nil, errs.Errorf("govulncheck reports %s with no OSV record for it", r.ids[0])
		}
		records[i].ids = append(records[i].ids, known...)
	}
	return records, nil
}

// symbol writes a vulnerable symbol as Go writes a method expression: crypto/x509.Certificate.Verify,
// or net/http.(*Client).Do for a pointer receiver.
func symbol(pkg, receiver, function string) string {
	name := function
	if receiver != "" {
		if strings.HasPrefix(receiver, "*") {
			receiver = "(" + receiver + ")"
		}
		name = receiver + "." + function
	}
	return pkg + "." + name
}
