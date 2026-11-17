// Small images made on the spot, so no binary fixture is committed.
import { randomBytes } from "node:crypto";
import { crc32, deflateSync } from "node:zlib";

const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// A PNG chunk: its length, type, data and CRC (RFC 2083 section 3.2).
function chunk(type: string, data: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const typed = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typed));
  return Buffer.concat([length, typed, crc]);
}

// A truecolour PNG of these rows of pixels, each row width RGB triples, with these chunks between its
// header and its image data.
function png(width: number, height: number, row: (y: number) => Buffer, extra: Buffer[] = []): Buffer {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8; // bit depth
  header[9] = 2; // truecolour
  const pixels = Buffer.concat(Array.from({ length: height }, (_, y) => Buffer.concat([Buffer.from([0]), row(y)])));
  return Buffer.concat([pngSignature, chunk("IHDR", header), ...extra, chunk("IDAT", deflateSync(pixels)), chunk("IEND", Buffer.alloc(0))]);
}

// A PNG of one solid colour.
export function solidPng(width: number, height: number, [r, g, b]: [number, number, number]): Buffer {
  const row = Buffer.from(Array.from({ length: width }, () => [r, g, b]).flat());
  return png(width, height, () => row);
}

// A PNG of random pixels, which deflate cannot shrink, so the file is about 3 bytes a pixel: the way
// to a file of a given size.
export function noisePng(width: number, height: number): Buffer {
  return png(width, height, () => randomBytes(width * 3));
}

// A solid PNG that says it is animated: an APNG's animation control chunk after its header, naming two
// frames (the APNG specification's acTL), as far as the auth server reads to tell.
export function animatedPng(width: number, height: number): Buffer {
  const control = Buffer.alloc(8);
  control.writeUInt32BE(2, 0); // frames
  const row = Buffer.from(Array.from({ length: width }, () => [10, 20, 30]).flat());
  return png(width, height, () => row, [chunk("acTL", control)]);
}

// The PNG signature and then nothing a PNG holds: a file that says it is a PNG and cannot be read.
export function damagedPng(): Buffer {
  return Buffer.concat([pngSignature, Buffer.from("not an image at all, just text after the signature", "ascii")]);
}

// The start of a JPEG, its SOI marker and an APP0 marker, as far as the auth server reads to tell a
// file's type, which it refuses before reading more.
export function jpegStart(): Buffer {
  return Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), Buffer.from("JFIF\0", "latin1"), Buffer.alloc(64)]);
}
