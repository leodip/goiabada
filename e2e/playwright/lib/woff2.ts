// A real WOFF2 font made on the spot, so no font file is committed and no third-party font is
// shipped: a TrueType font whose printable ASCII characters are each a box of one advance width,
// wrapped as WOFF2 2.0 with Node's built-in Brotli (W3C WOFF2, sections 3 to 5). A browser loads it,
// unlike woff2File's bare signature, so a spec can tell the brand's font was fetched and drawn: text
// set in it measures a known width, which no fallback font draws.
import { brotliCompressSync, constants } from "node:zlib";
import type { Page } from "@playwright/test";
import type { PickedFile } from "./brands";

// What a made font draws: every printable ASCII character but the space is a box `advance` thousandths
// of an em wide, the space as wide and blank; weight is 400 or 700, as its OS/2 table and its name say.
export interface ProbeFont {
  advance: number;
  weight: 400 | 700;
}

// The width, in CSS pixels, of `characters` characters set in a made font of this advance at this
// font size.
export function probeWidth(font: { advance: number }, characters: number, fontSize: number): number {
  return (characters * font.advance * fontSize) / unitsPerEm;
}

const unitsPerEm = 1000;
const ascender = 800;
const descender = -200;
const firstChar = 0x20;
const lastChar = 0x7e;
// The glyphs: .notdef (0), the space (1), then one box per character from "!" on.
const numGlyphs = 1 + (lastChar - firstChar + 1);

// A big-endian writer of the sfnt's integer types.
class Bytes {
  private parts: Buffer[] = [];
  u8(value: number) { return this.push(1, (b) => b.writeUInt8(value)); }
  u16(value: number) { return this.push(2, (b) => b.writeUInt16BE(value & 0xffff)); }
  i16(value: number) { return this.push(2, (b) => b.writeInt16BE(value)); }
  u32(value: number) { return this.push(4, (b) => b.writeUInt32BE(value >>> 0)); }
  i64(value: number) { return this.push(8, (b) => b.writeBigInt64BE(BigInt(value))); }
  tag(value: string) { return this.raw(Buffer.from(value, "latin1")); }
  raw(value: Buffer) { this.parts.push(value); return this; }
  done(): Buffer { return Buffer.concat(this.parts); }
  private push(size: number, write: (b: Buffer) => void) {
    const b = Buffer.alloc(size);
    write(b);
    this.parts.push(b);
    return this;
  }
}

// One glyph's outline: a box from a tenth of the advance to nine tenths, from the baseline to 700,
// drawn clockwise, one contour of four on-curve points.
function boxGlyph(advance: number): { data: Buffer; xMin: number; xMax: number } {
  const xMin = Math.round(advance / 10);
  const xMax = advance - xMin;
  const top = 700;
  const g = new Bytes().i16(1).i16(xMin).i16(0).i16(xMax).i16(top);
  g.u16(3).u16(0); // the last point's index; no instructions
  for (let i = 0; i < 4; i++) g.u8(0x01); // on curve, both coordinates as int16 deltas
  for (const dx of [xMin, 0, xMax - xMin, 0]) g.i16(dx);
  for (const dy of [0, top, 0, -top]) g.i16(dy);
  return { data: g.done(), xMin, xMax };
}

function pad(data: Buffer, to: number): Buffer {
  const extra = (to - (data.length % to)) % to;
  return extra === 0 ? data : Buffer.concat([data, Buffer.alloc(extra)]);
}

// The TrueType tables, by tag.
function tables({ advance, weight }: ProbeFont): Record<string, Buffer> {
  const bold = weight === 700;
  const box = boxGlyph(advance);
  const boxData = pad(box.data, 4);

  // glyf and loca (long offsets): .notdef and the space are empty, every other glyph the box.
  const glyf = Buffer.concat(Array.from({ length: numGlyphs - 2 }, () => boxData));
  const loca = new Bytes();
  let offset = 0;
  for (let glyph = 0; glyph <= numGlyphs; glyph++) {
    loca.u32(offset);
    if (glyph >= 2 && glyph < numGlyphs) offset += boxData.length;
  }

  const head = new Bytes()
    .u32(0x00010000).u32(0x00010000).u32(0).u32(0x5f0f3cf5)
    .u16(0x0003).u16(unitsPerEm).i64(0).i64(0)
    .i16(box.xMin).i16(0).i16(box.xMax).i16(700)
    .u16(bold ? 1 : 0).u16(8).i16(2).i16(1).i16(0)
    .done();

  const hhea = new Bytes()
    .u32(0x00010000).i16(ascender).i16(descender).i16(0)
    .u16(advance).i16(0).i16(advance - box.xMax).i16(box.xMax)
    .i16(1).i16(0).i16(0).i16(0).i16(0).i16(0).i16(0).i16(0)
    .u16(numGlyphs)
    .done();

  const hmtx = new Bytes();
  for (let glyph = 0; glyph < numGlyphs; glyph++) hmtx.u16(advance).i16(glyph >= 2 ? box.xMin : 0);

  const maxp = new Bytes().u32(0x00010000).u16(numGlyphs).u16(4).u16(1).u16(0).u16(0).u16(2);
  for (let i = 0; i < 8; i++) maxp.u16(0);

  // cmap: one Windows Unicode BMP subtable, format 4, mapping the characters to their glyphs by one
  // delta, and the closing 0xFFFF segment.
  const segments = [
    { start: firstChar, end: lastChar, delta: 1 - firstChar },
    { start: 0xffff, end: 0xffff, delta: 1 },
  ];
  const format4 = new Bytes().u16(4).u16(16 + segments.length * 8).u16(0).u16(segments.length * 2).u16(4).u16(1).u16(0);
  for (const s of segments) format4.u16(s.end);
  format4.u16(0);
  for (const s of segments) format4.u16(s.start);
  for (const s of segments) format4.i16(((s.delta + 0x8000) & 0xffff) - 0x8000);
  for (let i = 0; i < segments.length; i++) format4.u16(0);
  const cmap = new Bytes().u16(0).u16(1).u16(3).u16(1).u32(12).raw(format4.done()).done();

  // name: the Windows English records a font needs, in UTF-16BE.
  const style = bold ? "Bold" : "Regular";
  const names: [number, string][] = [
    [1, "Goiabada Probe"],
    [2, style],
    [3, `Goiabada Probe ${style} ${advance}`],
    [4, `Goiabada Probe ${style}`],
    [5, "Version 1.000"],
    [6, `GoiabadaProbe-${style}`],
  ];
  const strings = names.map(([, value]) => Buffer.from(value, "utf16le").swap16());
  const name = new Bytes().u16(0).u16(names.length).u16(6 + names.length * 12);
  let stringOffset = 0;
  names.forEach(([id], i) => {
    name.u16(3).u16(1).u16(0x0409).u16(id).u16(strings[i].length).u16(stringOffset);
    stringOffset += strings[i].length;
  });
  for (const s of strings) name.raw(s);

  const os2 = new Bytes()
    .u16(4).i16(advance).u16(weight).u16(5).u16(0)
    .i16(650).i16(600).i16(0).i16(75).i16(650).i16(600).i16(0).i16(350).i16(50).i16(250)
    .i16(0)
    .raw(Buffer.alloc(10))
    .u32(1).u32(0).u32(0).u32(0)
    .tag("NONE")
    .u16(bold ? 0x0020 : 0x0040).u16(firstChar).u16(lastChar)
    .i16(ascender).i16(descender).i16(0)
    .u16(ascender).u16(-descender)
    .u32(1).u32(0)
    .i16(500).i16(700).u16(0).u16(0x20).u16(1)
    .done();

  const post = new Bytes().u32(0x00030000).u32(0).i16(-100).i16(50).u32(0).u32(0).u32(0).u32(0).u32(0).done();

  return {
    "OS/2": os2, cmap, glyf, head, hhea, hmtx: hmtx.done(), loca: loca.done(), maxp: maxp.done(), name: name.done(), post,
  };
}

// A WOFF2 table directory entry's tag index, for the tags WOFF2 names (section 5.1, table 1).
const knownTags: Record<string, number> = {
  cmap: 0, head: 1, hhea: 2, hmtx: 3, maxp: 4, name: 5, "OS/2": 6, post: 7, glyf: 10, loca: 11,
};

// UIntBase128 (section 4.1): seven bits a byte, most significant first, the high bit on all but the
// last.
function base128(value: number): Buffer {
  const out = [value & 0x7f];
  for (let rest = value >>> 7; rest > 0; rest >>>= 7) out.unshift((rest & 0x7f) | 0x80);
  return Buffer.from(out);
}

// The made font as WOFF2: every table untransformed, glyf and loca by the null transform (version 3,
// section 5.1), in one Brotli stream, glyf and loca one after the other as section 5.3 asks.
export function probeWoff2(font: ProbeFont): Buffer {
  const byTag = tables(font);
  const order = ["OS/2", "cmap", "glyf", "loca", "head", "hhea", "hmtx", "maxp", "name", "post"];

  const directory = new Bytes();
  for (const tag of order) {
    const transform = tag === "glyf" || tag === "loca" ? 3 : 0;
    directory.u8(knownTags[tag] | (transform << 6)).raw(base128(byTag[tag].length));
  }
  const directoryBytes = directory.done();
  const compressed = brotliCompressSync(Buffer.concat(order.map((tag) => byTag[tag])), {
    params: { [constants.BROTLI_PARAM_MODE]: constants.BROTLI_MODE_FONT, [constants.BROTLI_PARAM_QUALITY]: 11 },
  });
  const totalSfntSize = 12 + 16 * order.length + order.reduce((sum, tag) => sum + pad(byTag[tag], 4).length, 0);
  const body = pad(Buffer.concat([directoryBytes, compressed]), 4);
  const length = 48 + body.length;

  const header = new Bytes()
    .tag("wOF2").u32(0x00010000).u32(length).u16(order.length).u16(0)
    .u32(totalSfntSize).u32(compressed.length).u16(1).u16(0)
    .u32(0).u32(0).u32(0).u32(0).u32(0)
    .done();
  return Buffer.concat([header, body]);
}

// The two files a spec uploads as a brand's font: a regular one drawing a box half an em wide, and
// a bold one drawing a box 0.9 em wide, so text set in each measures its own width.
export const probeRegular: ProbeFont = { advance: 500, weight: 400 };
export const probeBold: ProbeFont = { advance: 900, weight: 700 };

// A made font as a file picked in the brand editor.
export function probeFontFile(name: string, font: ProbeFont): PickedFile {
  return { name, mimeType: "font/woff2", buffer: probeWoff2(font) };
}

// The font size and the text a page's probe measures.
const probeSize = 20;
const probeText = "WWWW";

// What a page draws of its brand's uploaded font: each face of the brand's family, its weight and
// whether the browser fetched and read it ("loaded") or not ("error"), and the width four characters
// measure in regular and in bold, set inside `inside` (the auth card, or the console's main), whose
// font they inherit. A probe is added to the page and removed again.
export interface DrawnProbeFont {
  faces: string[];
  regular: number;
  bold: number;
}

export function drawnProbeFont(page: Page, inside: string): Promise<DrawnProbeFont> {
  return page.evaluate(
    async ({ inside, size, text }) => {
      await document.fonts.load(`${size}px "brand-font"`, text);
      await document.fonts.load(`bold ${size}px "brand-font"`, text);
      await document.fonts.ready;
      const faces: string[] = [];
      document.fonts.forEach((face) => {
        if (face.family.replace(/["']/g, "") === "brand-font") faces.push(`${face.weight} ${face.status}`);
      });
      // A block holding an inline run, so the run measures its text and not the box it sits in.
      const measure = (weight: string) => {
        const holder = document.createElement("div");
        const run = document.createElement("span");
        run.textContent = text;
        run.style.fontSize = `${size}px`;
        run.style.fontWeight = weight;
        run.style.whiteSpace = "nowrap";
        holder.append(run);
        document.querySelector(inside)!.append(holder);
        const width = run.getBoundingClientRect().width;
        holder.remove();
        return width;
      };
      return { faces: faces.sort(), regular: measure("400"), bold: measure("700") };
    },
    { inside, size: probeSize, text: probeText },
  );
}

// The width the probe's text measures in a made font.
export function probeTextWidth(font: ProbeFont): number {
  return probeWidth(font, probeText.length, probeSize);
}
