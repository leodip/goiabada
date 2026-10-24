package main

// The weekly image scan's report, driven over the scanners' own output (#520). testdata/published-1.7.2
// is what the pinned Trivy 0.76.0, Grype 0.120.1 and govulncheck 1.9.0 wrote on 2026-10-24 for the
// linux/amd64 images that authserver-latest and adminconsole-latest named that day, 1.7.2, pulled from
// Docker Hub by digest (authserver sha256:223b04e1…, adminconsole sha256:8727b34c…), and
// testdata/branch the same for the two images built from this branch. Each govulncheck stream is cut
// to the advisories its findings name; the 250 other OSV records it carries are the whole database
// entry for every module in the binary, which nothing here reads.
//
// What those runs found, read from the scanners' tables rather than from this program: in each 1.7.2
// image, musl and musl-utils 1.2.6-r2 carry CVE-2026-107891, fixed in 1.2.6-r3, from Trivy and Grype;
// the standard library 1.27.2 carries CVE-2026-111943, which Grype and govulncheck call GO-2026-6809,
// fixed in 1.27.3, with x509.Certificate.Verify called; Grype alone reports busybox's CVE-2025-60876,
// with no fix; and Trivy and govulncheck report golang.org/x/crypto's GO-2026-5932, with no fix and
// no call to it. The images built from this branch carry only the last two.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var published172 = []string{
	"testdata/published-1.7.2/authserver-amd64",
	"testdata/published-1.7.2/adminconsole-amd64",
}

var branchImages = []string{
	"testdata/branch/authserver-amd64",
	"testdata/branch/adminconsole-amd64",
}

// report runs the command over dirs and returns its exit code, the report and the log.
func report(t *testing.T, dirs ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(dirs, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

const published172Report = `The weekly scan of the published images found 2 advisories someone can act on: each has a fixed version, or is in Go code that govulncheck reports reachable. The scan's other findings are in its run's log. The Image scan workflow rewrites this list when it changes, and closes this issue once it is empty.

### [CVE-2026-107891](https://nvd.nist.gov/vuln/detail/CVE-2026-107891)

- **Images:** adminconsole-latest linux/amd64, authserver-latest linux/amd64
- **Packages:** ` + "`musl`" + ` 1.2.6-r2, fixed in 1.2.6-r3; ` + "`musl-utils`" + ` 1.2.6-r2, fixed in 1.2.6-r3
- **Reported by:** Trivy, Grype

### [CVE-2026-111943](https://nvd.nist.gov/vuln/detail/CVE-2026-111943) · [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)

- **Images:** adminconsole-latest linux/amd64, authserver-latest linux/amd64
- **Packages:** ` + "`stdlib`" + ` 1.27.2, fixed in 1.26.10, 1.27.3
- **Reported by:** Trivy, Grype, govulncheck
- **Reachable:** yes, govulncheck finds ` + "`crypto/x509.Certificate.Verify`" + ` called in every image listed
`

func TestReport_ThePublished172ImagesListMuslAndTheX509Advisory(t *testing.T) {
	code, out, _ := report(t, published172...)
	require.Equal(t, 0, code)
	assert.Equal(t, published172Report, out)
}

func TestReport_MuslFromBothScannersIsOneEntryNamingBothImages(t *testing.T) {
	_, out, _ := report(t, published172...)
	assert.Equal(t, 1, strings.Count(out, "CVE-2026-107891]"), "CVE-2026-107891 is not one entry:\n%s", out)
	assert.Contains(t, out, "### [CVE-2026-107891](https://nvd.nist.gov/vuln/detail/CVE-2026-107891)\n\n- **Images:** adminconsole-latest linux/amd64, authserver-latest linux/amd64\n")
	assert.Contains(t, out, "- **Reported by:** Trivy, Grype\n")
}

// Trivy names the standard library's advisory CVE-2026-111943, with GO-2026-6809 among its vendor
// identifiers; Grype names it GO-2026-6809, related to the CVE; govulncheck GO-2026-6809, aliased to it.
func TestReport_TheCVEAndTheGoIdentifierOfOneAdvisoryAreOneEntryMarkedReachable(t *testing.T) {
	_, out, _ := report(t, published172...)
	assert.Equal(t, 1, strings.Count(out, "GO-2026-6809]"), "GO-2026-6809 is not one entry:\n%s", out)
	assert.Equal(t, 1, strings.Count(out, "CVE-2026-111943]"), "CVE-2026-111943 is not one entry:\n%s", out)
	assert.Contains(t, out, "### [CVE-2026-111943](https://nvd.nist.gov/vuln/detail/CVE-2026-111943) · [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)\n")
	assert.Contains(t, out, "- **Reachable:** yes, govulncheck finds `crypto/x509.Certificate.Verify` called in every image listed\n")
}

// Linked through one scanner only: with Trivy's vendor identifiers and Grype's related advisories
// emptied, govulncheck's alias is what still makes CVE-2026-111943 and GO-2026-6809 one advisory.
func TestReport_OneScannersAliasIsEnoughToMergeTwoIdentifiers(t *testing.T) {
	dirs := editedScans(t, published172, func(scanner string, doc map[string]any) {
		switch scanner {
		case "trivy":
			eachTrivyVulnerability(doc, func(v map[string]any) { v["VendorIDs"] = nil })
		case "grype":
			eachGrypeMatch(doc, func(m map[string]any) { m["relatedVulnerabilities"] = []any{} })
		}
	})
	_, out, _ := report(t, dirs...)
	assert.Contains(t, out, "### [CVE-2026-111943](https://nvd.nist.gov/vuln/detail/CVE-2026-111943) · [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)\n")
	assert.Equal(t, 1, strings.Count(out, "GO-2026-6809]"), "GO-2026-6809 is not one entry:\n%s", out)
}

func TestReport_FindingsWithNoFixThatNothingReachesGoToTheLog(t *testing.T) {
	_, out, log := report(t, published172...)
	for _, id := range []string{"CVE-2025-60876", "GO-2026-5932", "busybox", "golang.org/x/crypto", "ssl_client"} {
		assert.NotContains(t, out, id)
	}
	assert.Contains(t, log, "CVE-2025-60876 in busybox 1.37.0-r31, busybox-binsh 1.37.0-r31, ssl_client 1.37.0-r31 (adminconsole-latest linux/amd64, authserver-latest linux/amd64), reported by Grype: no fixed version\n")
	assert.Contains(t, log, "GO-2026-5932 in golang.org/x/crypto 0.58.0 (adminconsole-latest linux/amd64, authserver-latest linux/amd64), reported by Trivy, govulncheck: no fixed version, and govulncheck finds no call to it\n")
}

func TestReport_NothingActionableGivesAnEmptyReport(t *testing.T) {
	code, out, log := report(t, branchImages...)
	require.Equal(t, 0, code, log)
	assert.Empty(t, out)
	assert.Contains(t, log, "CVE-2025-60876 in busybox 1.37.0-r31, busybox-binsh 1.37.0-r31 (goiabada-adminconsole:ci linux/amd64, goiabada-authserver:ci linux/amd64), reported by Grype: no fixed version\n")
	assert.Contains(t, log, "GO-2026-5932 in golang.org/x/crypto 0.58.0")
}

// The workflow compares the report with the issue's body to decide whether anything changed, so the
// same scans give the same bytes, in whatever order the directories are named.
func TestReport_TheSameScansGiveByteIdenticalOutput(t *testing.T) {
	_, first, firstLog := report(t, published172...)
	_, again, againLog := report(t, published172...)
	_, reversed, reversedLog := report(t, published172[1], published172[0])
	assert.Equal(t, first, again)
	assert.Equal(t, first, reversed)
	assert.Equal(t, firstLog, againLog)
	assert.Equal(t, firstLog, reversedLog)
}

// A Go finding govulncheck reports reachable is listed with no fix to move to.
func TestReport_AReachableGoFindingWithNoFixIsListed(t *testing.T) {
	dirs := editedScans(t, published172, func(scanner string, doc map[string]any) {
		switch scanner {
		case "trivy":
			eachTrivyVulnerability(doc, func(v map[string]any) {
				if v["VulnerabilityID"] == "CVE-2026-111943" {
					v["FixedVersion"] = ""
					v["Status"] = "affected"
				}
			})
		case "grype":
			eachGrypeMatch(doc, func(m map[string]any) {
				if vuln := m["vulnerability"].(map[string]any); vuln["id"] == "GO-2026-6809" {
					vuln["fix"] = map[string]any{"versions": []any{}, "state": "not-fixed"}
				}
			})
		case "govulncheck":
			if finding, ok := doc["finding"].(map[string]any); ok && finding["osv"] == "GO-2026-6809" {
				delete(finding, "fixed_version")
			}
		}
	})
	_, out, _ := report(t, dirs...)
	assert.Contains(t, out, "found 2 advisories")
	assert.Contains(t, out, "- **Packages:** `stdlib` 1.27.2, no fixed version\n")
	assert.Contains(t, out, "- **Reachable:** yes, govulncheck finds `crypto/x509.Certificate.Verify` called in every image listed\n")
}

// A Go finding with a fix is listed whether or not anything reaches it, and says it is not reached.
func TestReport_AGoFindingWithAFixIsListedUnreached(t *testing.T) {
	dirs := editedScans(t, published172, func(scanner string, doc map[string]any) {
		if finding, ok := doc["finding"].(map[string]any); ok && scanner == "govulncheck" && finding["osv"] == "GO-2026-5932" {
			finding["fixed_version"] = "v0.59.0"
		}
	})
	_, out, log := report(t, dirs...)
	assert.Contains(t, out, "found 3 advisories")
	assert.Contains(t, out, "### [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)\n\n- **Images:** adminconsole-latest linux/amd64, authserver-latest linux/amd64\n- **Packages:** `golang.org/x/crypto` 0.58.0, fixed in 0.59.0\n- **Reported by:** Trivy, govulncheck\n- **Reachable:** no, govulncheck finds no call to it\n")
	assert.NotContains(t, log, "GO-2026-5932")
}

// Reached in one image and not in the other: the entry says which.
func TestReport_ReachabilityIsSaidPerImage(t *testing.T) {
	dirs := editedScans(t, published172[1:], func(scanner string, doc map[string]any) {
		if finding, ok := doc["finding"].(map[string]any); ok && scanner == "govulncheck" && finding["osv"] == "GO-2026-6809" {
			for _, frame := range finding["trace"].([]any) {
				delete(frame.(map[string]any), "function")
				delete(frame.(map[string]any), "receiver")
			}
		}
	})
	_, out, _ := report(t, published172[0], dirs[0])
	assert.Contains(t, out, "- **Reachable:** yes in authserver-latest linux/amd64 (`crypto/x509.Certificate.Verify`); govulncheck finds no call to it in adminconsole-latest linux/amd64\n")
}

// A scan that cannot be read fails the run and writes no report, never one that reads as all clear.
func TestReport_AScanThatCannotBeReadFailsTheRun(t *testing.T) {
	cases := map[string]func(dir string){
		"a missing Trivy file": func(dir string) { require.NoError(t, os.Remove(filepath.Join(dir, "trivy.json"))) },
		"a missing Grype file": func(dir string) { require.NoError(t, os.Remove(filepath.Join(dir, "grype.json"))) },
		"a missing govulncheck file": func(dir string) {
			require.NoError(t, os.Remove(filepath.Join(dir, "govulncheck.json")))
		},
		"a missing image name":          func(dir string) { require.NoError(t, os.Remove(filepath.Join(dir, "image"))) },
		"an empty image name":           func(dir string) { writeFile(t, dir, "image", "\n") },
		"a Trivy file that is not JSON": func(dir string) { writeFile(t, dir, "trivy.json", "FATAL image scan error") },
		"an empty Trivy file":           func(dir string) { writeFile(t, dir, "trivy.json", "") },
		"a Trivy file of another schema": func(dir string) {
			writeFile(t, dir, "trivy.json", `{"SchemaVersion":3,"ArtifactName":"image.tar","Results":[]}`)
		},
		"a JSON object that is no Trivy report":  func(dir string) { writeFile(t, dir, "trivy.json", `{}`) },
		"a JSON object that is no Grype report":  func(dir string) { writeFile(t, dir, "grype.json", `{"matches":[]}`) },
		"a Grype report with no list of matches": func(dir string) { writeFile(t, dir, "grype.json", `{"descriptor":{"name":"grype"}}`) },
		"an empty Grype file":                    func(dir string) { writeFile(t, dir, "grype.json", "") },
		"an empty govulncheck stream":            func(dir string) { writeFile(t, dir, "govulncheck.json", "") },
		"a govulncheck stream with no config": func(dir string) {
			writeFile(t, dir, "govulncheck.json", `{"finding":{"osv":"GO-2026-6809","trace":[{"module":"stdlib","version":"v1.27.2"}]}}`)
		},
		"a govulncheck finding with no OSV record": func(dir string) {
			writeFile(t, dir, "govulncheck.json", `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}`+"\n"+
				`{"finding":{"osv":"GO-2026-6809","trace":[{"module":"stdlib","version":"v1.27.2"}]}}`)
		},
		"a govulncheck stream cut short": func(dir string) {
			writeFile(t, dir, "govulncheck.json", `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}`+"\n"+`{"finding":{"osv":`)
		},
	}
	for name, breakScan := range cases {
		t.Run(name, func(t *testing.T) {
			dirs := editedScans(t, published172, nil)
			breakScan(dirs[1])
			code, out, log := report(t, dirs...)
			assert.NotEqual(t, 0, code)
			assert.Empty(t, out)
			assert.Contains(t, log, dirs[1])
		})
	}
}

func TestReport_TwoScansOfOneImageNameFailTheRun(t *testing.T) {
	code, out, log := report(t, published172[0], published172[0])
	assert.NotEqual(t, 0, code)
	assert.Empty(t, out)
	assert.Contains(t, log, "authserver-latest linux/amd64")
}

func TestReport_NoScanFailsTheRun(t *testing.T) {
	code, out, _ := report(t)
	assert.NotEqual(t, 0, code)
	assert.Empty(t, out)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
}

// editedScans copies each scan directory to a temporary one, passing every Trivy and Grype report,
// and every message of every govulncheck stream, to edit as a decoded JSON object, and returns the
// copies in the same order. A nil edit copies the scans unchanged.
func editedScans(t *testing.T, dirs []string, edit func(scanner string, doc map[string]any)) []string {
	t.Helper()
	var copies []string
	for _, dir := range dirs {
		copied := filepath.Join(t.TempDir(), filepath.Base(dir))
		require.NoError(t, os.MkdirAll(copied, 0o700))
		image, err := os.ReadFile(filepath.Join(dir, "image"))
		require.NoError(t, err)
		writeFile(t, copied, "image", string(image))
		for _, scanner := range []string{"trivy", "grype"} {
			content, readErr := os.ReadFile(filepath.Join(dir, scanner+".json"))
			require.NoError(t, readErr)
			if edit != nil {
				var doc map[string]any
				require.NoError(t, json.Unmarshal(content, &doc))
				edit(scanner, doc)
				content, readErr = json.Marshal(doc)
				require.NoError(t, readErr)
			}
			writeFile(t, copied, scanner+".json", string(content))
		}
		content, err := os.ReadFile(filepath.Join(dir, "govulncheck.json"))
		require.NoError(t, err)
		if edit != nil {
			var lines []string
			for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
				var doc map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &doc))
				edit("govulncheck", doc)
				out, err := json.Marshal(doc)
				require.NoError(t, err)
				lines = append(lines, string(out))
			}
			content = []byte(strings.Join(lines, "\n") + "\n")
		}
		writeFile(t, copied, "govulncheck.json", string(content))
		copies = append(copies, copied)
	}
	return copies
}

func eachTrivyVulnerability(doc map[string]any, edit func(map[string]any)) {
	results, _ := doc["Results"].([]any)
	for _, result := range results {
		vulns, _ := result.(map[string]any)["Vulnerabilities"].([]any)
		for _, v := range vulns {
			edit(v.(map[string]any))
		}
	}
}

func eachGrypeMatch(doc map[string]any, edit func(map[string]any)) {
	matches, _ := doc["matches"].([]any)
	for _, m := range matches {
		edit(m.(map[string]any))
	}
}
