package imageupload

import (
	"bytes"
	"encoding/binary"
)

// animated reports whether data, which DetectContentType answered as contentType and which
// decodes, is an animated image. The decoders read only the first frame's header and answer an
// animated image's size as a still one's, so the animation is told from the container: a looping
// animation on or behind a sign-in card has no pause control (WCAG 2.2 success criterion 2.2.2,
// #813 decision 3).
func animated(contentType string, data []byte) bool {
	switch contentType {
	case "image/png":
		return pngAnimated(data)
	case "image/webp":
		return webpAnimated(data)
	case "image/gif":
		return gifAnimated(data)
	}
	return false
}

// gifAnimated reports whether a GIF holds more than one frame, which every browser plays as an
// animation. The walk reads the blocks' framing alone (GIF89a, sections 17 to 27) and decodes no
// frame, so a file of many small frames costs no memory; it stops at the second image descriptor,
// at the trailer, or at a block that runs past the data.
func gifAnimated(data []byte) bool {
	const header = 6 + 7 // the signature and version, then the logical screen descriptor
	if len(data) < header {
		return false
	}
	offset := header + colorTableLength(data[10])
	frames := 0
	for offset < len(data) {
		switch data[offset] {
		case 0x21: // an extension: its label, then its data sub-blocks
			offset = skipSubBlocks(data, offset+2)
		case 0x2C: // an image descriptor: nine bytes, a local color table, the LZW code size, the data
			if frames++; frames > 1 {
				return true
			}
			if offset+10 > len(data) {
				return false
			}
			offset = skipSubBlocks(data, offset+10+colorTableLength(data[offset+9])+1)
		default: // the trailer, 0x3B, or a block this walk does not know
			return false
		}
		if offset < 0 {
			return false
		}
	}
	return false
}

// colorTableLength is the length of the color table a GIF descriptor's packed field announces:
// none unless its high bit is set, otherwise three bytes for each of 2^(size+1) colors.
func colorTableLength(packed byte) int {
	if packed&0x80 == 0 {
		return 0
	}
	return 3 << ((packed & 0x07) + 1)
}

// skipSubBlocks answers the offset past the run of GIF data sub-blocks starting at offset, each a
// length byte and that many bytes, ended by a zero length, or -1 when the run is cut short.
func skipSubBlocks(data []byte, offset int) int {
	for offset < len(data) {
		size := int(data[offset])
		offset++
		if size == 0 {
			return offset
		}
		offset += size
	}
	return -1
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
