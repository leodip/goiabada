package imageupload

import (
	"bytes"
	"encoding/binary"
)

// animated reports whether data, which DetectContentType answered as contentType and which
// decodes, is an animated image. The decoders read only the first frame's header and answer an
// animated PNG or WebP's size as a still one's, so the animation is told from the container: a
// looping animation on or behind a sign-in card has no pause control (WCAG 2.2 success criterion
// 2.2.2, #813 decision 3). A GIF is never a brand kind's type, so it is not read here.
func animated(contentType string, data []byte) bool {
	switch contentType {
	case "image/png":
		return pngAnimated(data)
	case "image/webp":
		return webpAnimated(data)
	}
	return false
}

// pngAnimated reports whether a PNG carries an acTL chunk, the animation control chunk that makes
// it an APNG (PNG Third Edition). Every chunk up to IEND is read, so an acTL is found wherever an
// encoder put it; the walk stops at a chunk that runs past the data.
func pngAnimated(data []byte) bool {
	const signatureLength = 8
	for offset := signatureLength; offset+8 <= len(data); {
		length := int64(binary.BigEndian.Uint32(data[offset:]))
		chunkType := string(data[offset+4 : offset+8])
		switch chunkType {
		case "acTL":
			return true
		case "IEND":
			return false
		}
		next := int64(offset) + 12 + length
		if next > int64(len(data)) {
			return false
		}
		offset = int(next)
	}
	return false
}

// webpAnimated reports whether a WebP is animated: its VP8X header sets the animation flag, or it
// carries an ANIM or ANMF chunk (RFC 9649, the extended file format). A simple WebP, whose first
// chunk is VP8 or VP8L, has no frames to animate.
func webpAnimated(data []byte) bool {
	const header = 12 // "RIFF", the file size, "WEBP"
	const animationFlag = 0x02
	for offset := header; offset+8 <= len(data); {
		fourCC := data[offset : offset+4]
		size := int64(binary.LittleEndian.Uint32(data[offset+4:]))
		switch {
		case bytes.Equal(fourCC, []byte("VP8X")):
			if offset+8 < len(data) && data[offset+8]&animationFlag != 0 {
				return true
			}
		case bytes.Equal(fourCC, []byte("ANIM")), bytes.Equal(fourCC, []byte("ANMF")):
			return true
		}
		// A chunk's payload is padded to an even size.
		next := int64(offset) + 8 + size + size%2
		if next > int64(len(data)) {
			return false
		}
		offset = int(next)
	}
	return false
}
