// Command imagescanreport turns the weekly scan of the published images into the body of the one
// GitHub issue that lists what someone can act on (#520).
//
//	imagescanreport DIR...
//
// Each DIR is one image the Image scan workflow pulled, holding four files: image, the name the
// report calls it by, such as "authserver-latest linux/amd64"; trivy.json, from
// `trivy image --format json`; grype.json, from `grype -o json`; and govulncheck.json, from
// `govulncheck -mode=binary -format json` over the image's binary.
//
// A finding is listed when a scanner names a fixed version for it, or when it is in Go code and
// govulncheck finds the vulnerable symbol called. One advisory is one entry however many identifiers
// the scanners give it (a CVE in one, a GO- or GHSA- identifier in another), naming every image and
// package it is in and the scanners that saw it. The report goes to standard output, and is empty
// when nothing is listed, which is what tells the workflow to close the issue. Every finding left out
// is written to standard error, which is the run's log.
//
// The same scans always give the same bytes, in whatever order the directories are named, because
// the workflow decides whether anything changed by comparing the report with the issue's body. A scan
// that cannot be read stops the command with exit 1 and no report: a file missing, cut short or of
// another format would otherwise read as an image with nothing in it.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(dirs []string, stdout, stderr io.Writer) int {
	// The log is the run's, and a write to it that fails has nowhere else to be reported.
	logf := func(format string, args ...any) { _, _ = fmt.Fprintf(stderr, format+"\n", args...) }
	if len(dirs) == 0 {
		logf("usage: imagescanreport DIR...")
		return 2
	}
	var records []record
	images := map[string]string{}
	for _, dir := range dirs {
		image, scanned, err := readScan(dir)
		if err != nil {
			logf("imagescanreport: %v", err)
			return 1
		}
		if other, ok := images[image]; ok {
			logf("imagescanreport: %s and %s both scan %q", other, dir, image)
			return 1
		}
		images[image] = dir
		records = append(records, scanned...)
	}
	listed, left := classify(records)
	if _, err := io.WriteString(stdout, renderReport(listed)); err != nil {
		logf("imagescanreport: writing the report: %v", err)
		return 1
	}
	for _, line := range renderLog(left) {
		logf("%s", line)
	}
	logf("%d advisories listed, %d left out", len(listed), len(left))
	return 0
}
