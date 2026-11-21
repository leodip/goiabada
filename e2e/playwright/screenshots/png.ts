// The screenshots' post-processing, done on the PNGs Chromium writes: each is decoded to its pixels,
// cropped or given transparent rounded corners, and encoded again, with Node's zlib alone, so the
// bytes written follow the pixels and the Node of Playwright's image, nothing else (RFC 2083).
import { crc32, deflateSync, inflateSync } from "node:zlib";

const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// An image's pixels, four bytes each, red, green, blue and alpha, row by row from the top left.
export interface Pixels {
  width: number;
  height: number;
  rgba: Buffer;
}

// Decodes a PNG of 8-bit truecolour, with or without alpha and not interlaced, the forms Chromium
// writes a screenshot in. Any other form is refused rather than read wrong.
export function decodePng(file: Buffer): Pixels {
  if (file.length < 8 || !file.subarray(0, 8).equals(signature)) throw new Error("not a PNG");
  let width = 0;
  let height = 0;
  let channels = 0;
  const data: Buffer[] = [];
  for (let at = 8; at < file.length; ) {
    const length = file.readUInt32BE(at);
    const type = file.toString("ascii", at + 4, at + 8);
    const body = file.subarray(at + 8, at + 8 + length);
    if (type === "IHDR") {
      width = body.readUInt32BE(0);
      height = body.readUInt32BE(4);
      const [depth, colour, , , interlace] = body.subarray(8, 13);
      if (depth !== 8 || (colour !== 2 && colour !== 6) || interlace !== 0) {
        throw new Error(`a PNG of bit depth ${depth}, colour type ${colour}, interlace ${interlace}: only 8-bit RGB or RGBA, not interlaced, is read`);
      }
      channels = colour === 6 ? 4 : 3;
    } else if (type === "IDAT") {
      data.push(body);
    } else if (type === "IEND") {
      break;
    }
    at += 12 + length;
  }
  if (channels === 0) throw new Error("a PNG with no IHDR");
  const filtered = inflateSync(Buffer.concat(data));
  const stride = width * channels;
  if (filtered.length !== height * (stride + 1)) throw new Error("a PNG whose image data does not fill its size");
  const raw = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y++) {
    const filter = filtered[y * (stride + 1)];
    const line = filtered.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let i = 0; i < stride; i++) {
      const left = i >= channels ? raw[y * stride + i - channels] : 0;
      const up = y > 0 ? raw[(y - 1) * stride + i] : 0;
      const upLeft = y > 0 && i >= channels ? raw[(y - 1) * stride + i - channels] : 0;
      raw[y * stride + i] = (line[i] + predict(filter, left, up, upLeft)) & 0xff;
    }
  }
  if (channels === 4) return { width, height, rgba: raw };
  const rgba = Buffer.alloc(width * height * 4);
  for (let p = 0; p < width * height; p++) {
    raw.copy(rgba, p * 4, p * 3, p * 3 + 3);
    rgba[p * 4 + 3] = 255;
  }
  return { width, height, rgba };
}

// The value a row filter predicts a byte from: the byte to its left, the one above, and the one
// above that one's left (RFC 2083 section 6).
function predict(filter: number, left: number, up: number, upLeft: number): number {
  switch (filter) {
    case 0:
      return 0;
    case 1:
      return left;
    case 2:
      return up;
    case 3:
      return (left + up) >> 1;
    case 4: {
      const p = left + up - upLeft;
      const pa = Math.abs(p - left);
      const pb = Math.abs(p - up);
      const pc = Math.abs(p - upLeft);
      return pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft;
    }
    default:
      throw new Error(`a PNG row with filter ${filter}`);
  }
}

// Encodes pixels as an 8-bit PNG, RGBA when alpha is true and RGB, its alpha left out, otherwise.
// Each row takes the filter whose bytes sum smallest as signed values, the heuristic of RFC 2083
// section 9.6, and the image data is deflated at level 9.
export function encodePng(pixels: Pixels, { alpha }: { alpha: boolean }): Buffer {
  const { width, height, rgba } = pixels;
  const channels = alpha ? 4 : 3;
  const stride = width * channels;
  const raw = Buffer.alloc(height * stride);
  for (let p = 0; p < width * height; p++) rgba.copy(raw, p * channels, p * 4, p * 4 + channels);
  const filtered = Buffer.alloc(height * (stride + 1));
  const candidate = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    let best = -1;
    let bestSum = Infinity;
    for (let filter = 0; filter <= 4; filter++) {
      let sum = 0;
      for (let i = 0; i < stride; i++) {
        const left = i >= channels ? raw[y * stride + i - channels] : 0;
        const up = y > 0 ? raw[(y - 1) * stride + i] : 0;
        const upLeft = y > 0 && i >= channels ? raw[(y - 1) * stride + i - channels] : 0;
        const byte = (raw[y * stride + i] - predict(filter, left, up, upLeft)) & 0xff;
        candidate[i] = byte;
        sum += byte < 128 ? byte : 256 - byte;
      }
      if (sum < bestSum) {
        bestSum = sum;
        best = filter;
        filtered[y * (stride + 1)] = filter;
        candidate.copy(filtered, y * (stride + 1) + 1);
      }
    }
    if (best < 0) throw new Error("no filter chosen");
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = alpha ? 6 : 2;
  return Buffer.concat([
    signature,
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(filtered, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// A PNG chunk: its length, type, data and CRC (RFC 2083 section 3.2).
function chunk(type: string, data: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const typed = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typed));
  return Buffer.concat([length, typed, crc]);
}

// The rectangle of pixels at x, y, width by height, which must lie inside the image.
export function crop(pixels: Pixels, x: number, y: number, width: number, height: number): Pixels {
  if (![x, y, width, height].every(Number.isInteger) || x < 0 || y < 0 || width <= 0 || height <= 0 ||
    x + width > pixels.width || y + height > pixels.height) {
    throw new Error(`a crop of ${width}x${height} at ${x},${y} outside the ${pixels.width}x${pixels.height} image`);
  }
  const rgba = Buffer.alloc(width * height * 4);
  for (let row = 0; row < height; row++) {
    const from = ((y + row) * pixels.width + x) * 4;
    pixels.rgba.copy(rgba, row * width * 4, from, from + width * 4);
  }
  return { width, height, rgba };
}

// How many of a corner pixel's samples, on a grid of this many to a side, fall inside the corner's
// quarter circle.
const samplesPerSide = 16;

// The image with each corner cut to a quarter circle of this radius, transparent outside it: a pixel
// the arc crosses keeps the share of its alpha that the circle covers, sampled on a 16 by 16 grid.
export function roundCorners(pixels: Pixels, radius: number): Pixels {
  const { width, height } = pixels;
  if (!Number.isInteger(radius) || radius <= 0 || 2 * radius > width || 2 * radius > height) {
    throw new Error(`a corner radius of ${radius} for a ${width}x${height} image`);
  }
  const rgba = Buffer.from(pixels.rgba);
  // coverage[dy][dx] is the share of the top-left corner's pixel (dx, dy) inside the circle centred
  // at (radius, radius); the other three corners mirror it.
  const coverage: number[][] = [];
  for (let dy = 0; dy < radius; dy++) {
    coverage.push([]);
    for (let dx = 0; dx < radius; dx++) {
      let inside = 0;
      for (let sy = 0; sy < samplesPerSide; sy++) {
        for (let sx = 0; sx < samplesPerSide; sx++) {
          const px = dx + (sx + 0.5) / samplesPerSide - radius;
          const py = dy + (sy + 0.5) / samplesPerSide - radius;
          if (px * px + py * py <= radius * radius) inside++;
        }
      }
      coverage[dy].push(inside / (samplesPerSide * samplesPerSide));
    }
  }
  for (let dy = 0; dy < radius; dy++) {
    for (let dx = 0; dx < radius; dx++) {
      const share = coverage[dy][dx];
      if (share === 1) continue;
      for (const [x, y] of [
        [dx, dy],
        [width - 1 - dx, dy],
        [dx, height - 1 - dy],
        [width - 1 - dx, height - 1 - dy],
      ]) {
        const a = (y * width + x) * 4 + 3;
        rgba[a] = Math.round(rgba[a] * share);
      }
    }
  }
  return { width, height, rgba };
}
