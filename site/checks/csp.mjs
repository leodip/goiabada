// The site's Content-Security-Policy, so a browser refuses anything the site did
// not build or allow. Each page carries its own policy, as a <meta> that is the
// first element of its head, written once Astro has written the page: it holds the
// hashes of that page's inline scripts and style elements, so exactly what the
// build produced runs, and nothing injected later. A <meta> policy cannot carry
// frame-ancestors or reporting; nginx's X-Frame-Options covers framing.
//
// HTML requires a page's charset declaration within its first 1024 bytes, which a
// policy of that length ahead of it would push it past. So the step takes out the
// page's <meta charset> and starts the page with a UTF-8 byte order mark instead,
// which declares the encoding before any byte of the page and outranks the
// Content-Type header (https://html.spec.whatwg.org/multipage/semantics.html#charset).

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { fromHtml } from 'hast-util-from-html';

import { builtFiles, textOf, walk } from './privacy.mjs';

// Where Google's tag loads from and sends to once the visitor accepts Analytics:
// Google's documented list for GA4, images left out of *.analytics.google.com.
const googleTag = 'https://www.googletagmanager.com';
const googleImages = ['https://*.google-analytics.com', 'https://*.googletagmanager.com'];
const googleConnect = ['https://*.google-analytics.com', 'https://*.analytics.google.com', 'https://*.googletagmanager.com'];

// Every page's directives, in order, the page's script hashes going at the end of
// script-src and its style hashes at the end of style-src. 'wasm-unsafe-eval' is
// Pagefind's search; data: images are icons in the built CSS. Inline style
// attributes, Expressive Code's colours and Starlight's icon sizes, are allowed:
// hashing them would break any library that sets one at run time, and a style
// attribute cannot run script.
export const directives = [
	['default-src', ["'self'"]],
	['script-src', ["'self'", "'wasm-unsafe-eval'", googleTag]],
	['style-src', ["'self'"]],
	['style-src-attr', ["'unsafe-inline'"]],
	['img-src', ["'self'", 'data:', ...googleImages]],
	['connect-src', ["'self'", ...googleConnect]],
	['object-src', ["'none'"]],
	['base-uri', ["'self'"]],
	['form-action', ["'self'"]],
];

// HTML's limit on where a charset declaration may end, in bytes from the start.
const charsetLimit = 1024;
const byteOrderMark = '\uFEFF';

// Writes into every page built in distDir its policy, as the first element of its
// head, replacing its charset declaration with a byte order mark, and stops when
// there is no page. Returns how many pages it wrote.
export function writeContentSecurityPolicy({ distDir }) {
	const pages = builtFiles(distDir, '.html');
	if (pages.length === 0) throw new Error(`found no built page in ${distDir}: the step reached nothing`);
	for (const file of pages) {
		const path = join(distDir, file);
		let { html } = readPage(path);
		const tree = fromHtml(html);
		const scripts = new Set();
		const styles = new Set();
		for (const piece of inlinePieces(tree)) (piece.kind === 'script' ? scripts : styles).add(`'sha256-${piece.hash}'`);
		const policy = directives
			.map(([name, sources]) => {
				const hashes = name === 'script-src' ? scripts : name === 'style-src' ? styles : [];
				return [name, ...sources, ...hashes].join(' ');
			})
			.join('; ');
		const meta = `<meta http-equiv="Content-Security-Policy" content="${escapeAttribute(policy)}">`;
		let at = headStart(tree, html);
		for (const { start, end } of charsetDeclarations(tree).reverse()) {
			html = html.slice(0, start) + html.slice(end);
			if (end <= at) at -= end - start;
		}
		writeFileSync(path, byteOrderMark + html.slice(0, at) + meta + html.slice(at));
	}
	return pages.length;
}

// Throws an error naming every page built in distDir whose policy is not the first
// element of its head, whose policy leaves out the hash of one of its inline
// scripts or style elements, that has an inline event handler, which no hash
// allows, or whose charset declaration ends past its first 1024 bytes or that has
// none, neither a byte order mark nor a <meta charset>. Stops when there is no
// page. Returns how many pages it read.
export function assertContentSecurityPolicy({ distDir }) {
	const pages = builtFiles(distDir, '.html');
	if (pages.length === 0) throw new Error(`found no built page in ${distDir}: the check reached nothing`);
	const findings = [];
	for (const file of pages) {
		const { html, bom } = readPage(join(distDir, file));
		const tree = fromHtml(html);
		const declarations = charsetDeclarations(tree);
		if (!bom && declarations.length === 0) {
			findings.push(`  ${file}: no character encoding declaration, neither a UTF-8 byte order mark nor a <meta charset>`);
		}
		for (const { end } of declarations) {
			const endByte = (bom ? Buffer.byteLength(byteOrderMark) : 0) + Buffer.byteLength(html.slice(0, end));
			if (endByte > charsetLimit) {
				findings.push(`  ${file}: the character encoding declaration ends at byte ${endByte}, past the first ${charsetLimit}`);
			}
		}
		const headElements = (headOf(tree)?.children ?? []).filter((node) => node.type === 'element');
		const meta = headElements.find(isPolicyMeta);
		if (meta === undefined) {
			findings.push(`  ${file}: no Content-Security-Policy in the head`);
		} else {
			if (headElements[0] !== meta) findings.push(`  ${file}: the Content-Security-Policy is not the first element of the head`);
			const policy = parsePolicy(String(meta.properties.content ?? ''));
			for (const piece of inlinePieces(tree)) {
				const sources = piece.kind === 'script' ? effectiveSources(policy, 'script') : effectiveSources(policy, 'style');
				if (!sources.includes(`'sha256-${piece.hash}'`)) {
					findings.push(`  ${file}: inline ${piece.kind} not in the policy, 'sha256-${piece.hash}': ${excerpt(piece.text)}`);
				}
			}
		}
		walk(tree, (node) => {
			for (const property of Object.keys(node.properties ?? {})) {
				if (/^on./i.test(property)) findings.push(`  ${file}: inline event handler ${property.toLowerCase()} on <${node.tagName}>`);
			}
		});
	}

	if (findings.length > 0) {
		throw new Error(
			`${findings.length} Content-Security-Policy problem(s): every page must carry its policy as the first element of its head, listing the hash of each of its inline scripts and style elements, have no inline event handler, and declare its character encoding within its first ${charsetLimit} bytes:\n${findings.join('\n')}`,
		);
	}
	return pages.length;
}

// A built page's text, without the byte order mark that starts it, if one does,
// as a browser reads it: the HTML parser would take the mark for text.
function readPage(path) {
	const text = readFileSync(path, 'utf8');
	const bom = text.startsWith(byteOrderMark);
	return { html: bom ? text.slice(byteOrderMark.length) : text, bom };
}

// Where each of the page's charset declarations is in its text, in document order:
// a <meta charset>, or a <meta http-equiv="content-type">, which declares one too.
function charsetDeclarations(tree) {
	const declarations = [];
	walk(tree, (node) => {
		if (node.tagName !== 'meta' || !node.position) return;
		const httpEquiv = [node.properties?.httpEquiv ?? []].flat().join(' ').toLowerCase();
		if (node.properties?.charSet === undefined && httpEquiv !== 'content-type') return;
		declarations.push({ start: node.position.start.offset, end: node.position.end.offset });
	});
	return declarations;
}

// The script types a browser runs, and so a policy governs; any other type is a
// data block, such as JSON, which the browser never runs.
const runnableScriptTypes = new Set(['module', 'importmap', 'speculationrules']);
const javaScriptMimeTypes = new Set([
	'application/ecmascript',
	'application/javascript',
	'application/x-ecmascript',
	'application/x-javascript',
	'text/ecmascript',
	'text/javascript',
	'text/javascript1.0',
	'text/javascript1.1',
	'text/javascript1.2',
	'text/javascript1.3',
	'text/javascript1.4',
	'text/javascript1.5',
	'text/jscript',
	'text/livescript',
	'text/x-ecmascript',
	'text/x-javascript',
]);

function runs(type) {
	if (type === undefined) return true;
	const value = String(type).trim().toLowerCase();
	return value === '' || runnableScriptTypes.has(value) || javaScriptMimeTypes.has(value);
}

// Every inline script a browser runs and every style element in the page, in
// document order, as { kind, text, hash }: the base64 SHA-256 of the element's
// text in UTF-8, as the browser hashes it.
function inlinePieces(tree) {
	const pieces = [];
	walk(tree, (node) => {
		const props = node.properties ?? {};
		let kind;
		if (node.tagName === 'script' && props.src === undefined && runs(props.type)) kind = 'script';
		else if (node.tagName === 'style') kind = 'style';
		else return;
		const text = textOf(node);
		pieces.push({ kind, text, hash: createHash('sha256').update(text, 'utf8').digest('base64') });
	});
	return pieces;
}

// Where the page's head begins: just past its <head> tag, or, when the page leaves
// that tag out, past its <html> tag or its doctype, where an element starts the
// head the browser adds.
function headStart(tree, html) {
	const root = tree.children.find((node) => node.type === 'element' && node.tagName === 'html');
	const head = headOf(tree);
	if (head?.position) return endOfStartTag(html, head.position.start.offset);
	if (root?.position) return endOfStartTag(html, root.position.start.offset);
	return tree.children.find((node) => node.type === 'doctype')?.position?.end.offset ?? 0;
}

function headOf(tree) {
	const html = tree.children.find((node) => node.type === 'element' && node.tagName === 'html');
	return html?.children.find((node) => node.type === 'element' && node.tagName === 'head');
}

function isPolicyMeta(node) {
	const httpEquiv = [node.properties?.httpEquiv ?? []].flat().join(' ');
	return node.tagName === 'meta' && httpEquiv.toLowerCase() === 'content-security-policy';
}

// The policy's directives by name, as the browser reads them: names in any case,
// and the first of a repeated directive the one that counts.
function parsePolicy(content) {
	const policy = new Map();
	for (const directive of content.split(';')) {
		const [name, ...sources] = directive.trim().split(/\s+/);
		if (name && !policy.has(name.toLowerCase())) policy.set(name.toLowerCase(), sources);
	}
	return policy;
}

// The sources that allow an inline script or style element: its -elem directive,
// or else its -src directive, or else default-src.
function effectiveSources(policy, kind) {
	for (const name of [`${kind}-src-elem`, `${kind}-src`, 'default-src']) {
		if (policy.has(name)) return policy.get(name);
	}
	return [];
}

// The index just past the start tag beginning at offset, its quoted attribute
// values skipped.
function endOfStartTag(html, offset) {
	let quote;
	for (let at = offset; at < html.length; at++) {
		const char = html[at];
		if (quote) {
			if (char === quote) quote = undefined;
		} else if (char === '"' || char === "'") {
			quote = char;
		} else if (char === '>') {
			return at + 1;
		}
	}
	throw new Error(`a start tag at offset ${offset} never ends`);
}

function escapeAttribute(value) {
	return value.replaceAll('&', '&amp;').replaceAll('"', '&quot;');
}

// A piece's first words, on one line.
function excerpt(text) {
	const line = text.replace(/\s+/g, ' ').trim();
	return line.length > 60 ? `${line.slice(0, 60)}…` : line;
}
