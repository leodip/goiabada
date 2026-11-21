// Command screenshotcheck checks the images e2e/screenshots.sh captured before the script writes them
// over the committed ones (#534). It reads them as a tar stream on its standard input and takes their
// file names as arguments:
//
//	tar -cf - -C <capture folder> <name>... | go run ./cmd/screenshotcheck <name>...
//
// It exits non-zero, naming the image, unless no two names differ only in letter case, the stream
// holds each name once, as a regular file, and nothing else, and each is a PNG that Go's decoder reads
// whole with no byte after its IEND chunk. The script runs it in the Go image the release Dockerfiles build in, with no network, rather
// than on the host or in the browser's image, whose output it checks: the host needs Docker alone,
// and a check in the image that wrote the files would prove nothing about them.
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// The largest image read, in bytes and in pixels: far beyond any screenshot the command takes, and
// small enough that an image whose header claims a vast size is refused rather than decoded.
const (
	maxBytes  = 64 << 20
	maxPixels = 1 << 26
)

func main() {
	if err := check(os.Stdin, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "screenshotcheck: %v\n", err)
		os.Exit(1)
	}
}

// check reads the tar stream r and returns an error unless it holds exactly the images names, each a
// regular file holding one whole PNG.
func check(r io.Reader, names []string) error {
	if len(names) == 0 {
		return errs.New("no image named")
	}
	// On a disk that ignores letter case, as macOS's does by default, two such names are one file,
	// which the script would replace twice and could not put back.
	want := map[string]bool{}
	folded := map[string]string{}
	for _, name := range names {
		want[name] = true
		if other, ok := folded[strings.ToLower(name)]; ok && other != name {
			return errs.Errorf("%s and %s differ only in letter case", other, name)
		}
		folded[strings.ToLower(name)] = name
	}
	seen := map[string]bool{}
	archive := tar.NewReader(r)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errs.Wrap(err, "reading the images")
		}
		name := header.Name
		if !want[name] {
			return errs.Errorf("%q is not an image named", name)
		}
		if seen[name] {
			return errs.Errorf("%s comes twice", name)
		}
		seen[name] = true
		if header.Typeflag != tar.TypeReg {
			return errs.Errorf("%s is not a regular file", name)
		}
		if header.Size > maxBytes {
			return errs.Errorf("%s is larger than %d bytes", name, maxBytes)
		}
		data, err := io.ReadAll(archive)
		if err != nil {
			return errs.Wrapf(err, "reading %s", name)
		}
		if err := checkPNG(data); err != nil {
			return errs.Wrapf(err, "%s is not a whole PNG", name)
		}
	}
	// The padding tar writes after the archive's end is read too, so the tar writing the stream is
	// not cut off by a check that ended first, which would fail the script's pipeline.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return errs.Wrap(err, "reading the end of the images")
	}
	for _, name := range names {
		if !seen[name] {
			return errs.Errorf("%s is missing", name)
		}
	}
	return nil
}

// checkPNG returns an error unless data is one PNG that Go's decoder reads whole, of at most
// maxPixels, with nothing after it.
func checkPNG(data []byte) error {
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return errs.Wrap(err, "decoding its header")
	}
	if config.Width <= 0 || config.Height <= 0 || int64(config.Width)*int64(config.Height) > maxPixels {
		return errs.Errorf("an image of %dx%d pixels", config.Width, config.Height)
	}
	// The decoder reads from the reader as it needs, with no buffer of its own, so what it leaves
	// unread is what follows the IEND chunk.
	rest := bytes.NewReader(data)
	if _, err := png.Decode(rest); err != nil {
		return errs.Wrap(err, "decoding it")
	}
	if rest.Len() != 0 {
		return errs.Errorf("%d bytes after its IEND chunk", rest.Len())
	}
	return nil
}
