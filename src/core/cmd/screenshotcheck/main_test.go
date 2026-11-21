package main

import (
	"archive/tar"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pngChunk is one PNG chunk: its length, type, data and CRC.
func pngChunk(kind string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	body := append([]byte(kind), data...)
	b.Write(body)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(body))
	return b.Bytes()
}

// onePixel is a valid PNG of one grey pixel, written chunk by chunk so a test can leave one out.
func onePixel(t *testing.T, withData bool) []byte {
	t.Helper()
	b := []byte("\x89PNG\r\n\x1a\n")
	b = append(b, pngChunk("IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0})...)
	if withData {
		var pixels bytes.Buffer
		z := zlib.NewWriter(&pixels)
		_, err := z.Write([]byte{0, 0x80})
		require.NoError(t, err)
		require.NoError(t, z.Close())
		b = append(b, pngChunk("IDAT", pixels.Bytes())...)
	}
	return append(b, pngChunk("IEND", nil)...)
}

// entry is one file of a tar stream.
type entry struct {
	name string
	kind byte
	data []byte
}

func stream(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.kind, Mode: 0o644, Size: int64(len(e.data))}
		if e.kind == tar.TypeSymlink {
			h.Linkname, h.Size = "/etc/passwd", 0
		}
		require.NoError(t, w.WriteHeader(h))
		if e.kind == tar.TypeReg {
			_, err := w.Write(e.data)
			require.NoError(t, err)
		}
	}
	require.NoError(t, w.Close())
	return &b
}

func TestCheck_TakesEveryNamedImageAsAWholePNG(t *testing.T) {
	r := stream(t, entry{"screenshot-a.png", tar.TypeReg, onePixel(t, true)}, entry{"screenshot-b.png", tar.TypeReg, onePixel(t, true)})
	require.NoError(t, check(r, []string{"screenshot-a.png", "screenshot-b.png"}))
}

func TestCheck_RefusesWhatIsNotTheNamedImagesAsWholePNGs(t *testing.T) {
	good := onePixel(t, true)
	names := []string{"screenshot-a.png", "screenshot-b.png"}
	for _, tc := range []struct {
		name    string
		entries []entry
		want    string
	}{
		// The signature, the IHDR and the IEND chunks, and none of the image data a PNG must hold.
		{"an image with no image data", []entry{{"screenshot-a.png", tar.TypeReg, good}, {"screenshot-b.png", tar.TypeReg, onePixel(t, false)}},
			"screenshot-b.png is not a whole PNG"},
		{"an image that is not a PNG", []entry{{"screenshot-a.png", tar.TypeReg, good}, {"screenshot-b.png", tar.TypeReg, []byte("SECRET=a credential\n")}},
			"screenshot-b.png is not a whole PNG"},
		{"an image cut short", []entry{{"screenshot-a.png", tar.TypeReg, good}, {"screenshot-b.png", tar.TypeReg, good[:len(good)-12]}},
			"screenshot-b.png is not a whole PNG"},
		{"an image with bytes after its end", []entry{{"screenshot-a.png", tar.TypeReg, good}, {"screenshot-b.png", tar.TypeReg, append(append([]byte{}, good...), "SECRET"...)}},
			"screenshot-b.png is not a whole PNG: 6 bytes after its IEND chunk"},
		{"an image that is a link", []entry{{"screenshot-a.png", tar.TypeReg, good}, {"screenshot-b.png", tar.TypeSymlink, nil}},
			"screenshot-b.png is not a regular file"},
		{"a missing image", []entry{{"screenshot-a.png", tar.TypeReg, good}},
			"screenshot-b.png is missing"},
		{"an image twice", []entry{{"screenshot-a.png", tar.TypeReg, good}, {"screenshot-a.png", tar.TypeReg, good}, {"screenshot-b.png", tar.TypeReg, good}},
			"screenshot-a.png comes twice"},
		{"a file not named", []entry{{"screenshot-a.png", tar.TypeReg, good}, {"screenshot-b.png", tar.TypeReg, good}, {".env", tar.TypeReg, []byte("SECRET")}},
			`".env" is not an image named`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := check(stream(t, tc.entries...), names)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// Two names that differ only in letter case are refused before the stream is read, though the stream
// holds both as files of their own: on a disk that ignores case they are one file.
func TestCheck_RefusesNamesThatDifferOnlyInCase(t *testing.T) {
	good := onePixel(t, true)
	r := stream(t, entry{"screenshot-a.png", tar.TypeReg, good}, entry{"screenshot-A.png", tar.TypeReg, good})
	err := check(r, []string{"screenshot-a.png", "screenshot-A.png"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "screenshot-a.png and screenshot-A.png differ only in letter case")
}

func TestCheck_RefusesAnImageWhoseHeaderClaimsAVastSize(t *testing.T) {
	b := []byte("\x89PNG\r\n\x1a\n")
	b = append(b, pngChunk("IHDR", []byte{0, 1, 0, 0, 0, 1, 0, 0, 8, 0, 0, 0, 0})...)
	b = append(b, pngChunk("IEND", nil)...)
	err := check(stream(t, entry{"screenshot-a.png", tar.TypeReg, b}), []string{"screenshot-a.png"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "an image of 65536x65536 pixels")
}

func TestCheck_RefusesARunThatNamesNoImage(t *testing.T) {
	require.Error(t, check(stream(t), nil))
}
