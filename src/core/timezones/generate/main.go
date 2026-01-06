// This tool generates timezones.go from IANA tzdata.
//
// Usage:
//
//	go run main.go
//
// It will automatically download the latest tzdata from IANA,
// extract it, and update ../timezones.go.
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
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
)

const (
	ianaPageURL     = "https://www.iana.org/time-zones"
	ianaDataBaseURL = "https://data.iana.org/time-zones/releases/"
)

func main() {
	fmt.Println("Fetching latest tzdata version from IANA...")

	// Get the latest version from IANA page
	version, err := getLatestVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest version: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Latest version: %s\n", version)

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tzdata-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	// Download and extract tzdata
	tzdataURL := fmt.Sprintf("%stzdata%s.tar.gz", ianaDataBaseURL, version)
	fmt.Printf("Downloading %s...\n", tzdataURL)

	if err := downloadAndExtract(tzdataURL, tmpDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading/extracting tzdata: %v\n", err)
		os.Exit(1)
	}

	// Load country codes mapping
	countries, err := loadCountryCodes(filepath.Join(tmpDir, "iso3166.tab"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading iso3166.tab: %v\n", err)
		os.Exit(1)
	}

	// Load timezone data
	zones, err := loadZones(filepath.Join(tmpDir, "zone1970.tab"), countries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading zone1970.tab: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d timezone entries\n", len(zones))

	// Generate the output
	output := generateGoFile(zones, version)

	// Format the generated code
	formatted, err := format.Source([]byte(output))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting generated code: %v\n", err)
		os.Exit(1)
	}

	// Determine output path (../timezones.go relative to this file)
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: could not determine current file path\n")
		os.Exit(1)
	}
	outputPath := filepath.Join(filepath.Dir(currentFile), "..", "timezones.go")

	// Write to file
	if err := os.WriteFile(outputPath, formatted, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to %s: %v\n", outputPath, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully updated %s\n", outputPath)
}

func getLatestVersion() (string, error) {
	resp, err := http.Get(ianaPageURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch IANA page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Look for the version in the HTML - pattern: tzdata2025c.tar.gz
	re := regexp.MustCompile(`tzdata(\d{4}[a-z]?)\.tar\.gz`)
	matches := re.FindSubmatch(body)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not find tzdata version in IANA page")
	}

	return string(matches[1]), nil
}

func downloadAndExtract(url, destDir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create gzip reader
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	// Create tar reader
	tr := tar.NewReader(gzr)

	// Extract files
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Only extract regular files we need
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// We only need these files
		if header.Name != "iso3166.tab" && header.Name != "zone1970.tab" {
			continue
		}

		destPath := filepath.Join(destDir, header.Name)
		outFile, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", destPath, err)
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return fmt.Errorf("failed to write file %s: %w", destPath, err)
		}
		outFile.Close()

		fmt.Fprintf(os.Stderr, "  Extracted: %s\n", header.Name)
	}

	return nil
}

func loadCountryCodes(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	countries := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			countries[parts[0]] = parts[1]
		}
	}
	return countries, scanner.Err()
}

type zoneEntry struct {
	CountryCode string
	Zone        string
	CountryName string
	Comments    string
}

func loadZones(filename string, countries map[string]string) ([]zoneEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var zones []zoneEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}

		countryCodes := strings.Split(parts[0], ",")
		// Skip coordinates (parts[1])
		zoneName := parts[2]
		comments := ""
		if len(parts) > 3 {
			comments = parts[3]
		}

		// Create an entry for each country code
		for _, cc := range countryCodes {
			countryName := countries[cc]
			if countryName == "" {
				countryName = cc // fallback to code if name not found
			}
			zones = append(zones, zoneEntry{
				CountryCode: cc,
				Zone:        zoneName,
				CountryName: countryName,
				Comments:    comments,
			})
		}
	}

	// Sort by country name, then by zone name for consistent output
	sort.Slice(zones, func(i, j int) bool {
		if zones[i].CountryName != zones[j].CountryName {
			return zones[i].CountryName < zones[j].CountryName
		}
		return zones[i].Zone < zones[j].Zone
	})

	return zones, scanner.Err()
}

func escapeString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func generateGoFile(zones []zoneEntry, version string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`// Code generated by go run generate/main.go; DO NOT EDIT.
//
// Generated from IANA tzdata version: %s
//
// To regenerate this file, run from src/core/timezones/generate:
//   go run main.go

package timezones

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"
)

type Zone struct {
	*time.Location

	CountryCode string
	Zone        string
	Abbr        []string
	CountryName string
	Comments    string
}

var loadLocationOnce sync.Once

func Get() []*Zone {

	loadLocationOnce.Do(func() {
		for _, tz := range zones {
			var err error
			tz.Location, err = time.LoadLocation(tz.Zone)
			if err != nil {
				slog.Error(fmt.Sprintf("unable to load time zone location from the OS: %%+v", err))
				os.Exit(1)
			}
		}

		sort.Slice(zones, func(i, j int) bool {
			return zones[i].CountryName < zones[j].CountryName
		})
	})
	return zones
}

var zones = []*Zone{
`, version))

	for _, z := range zones {
		sb.WriteString(fmt.Sprintf("\t{CountryCode: %q, Zone: %q, Abbr: []string(nil), CountryName: %q, Comments: %q},\n",
			z.CountryCode,
			z.Zone,
			escapeString(z.CountryName),
			escapeString(z.Comments),
		))
	}

	sb.WriteString("}\n")

	return sb.String()
}
