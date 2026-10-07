// The shipped-link check: every goiabada.dev link in the repository's code must
// name a page the build published, and a fragment on it must name a heading that
// page renders. The binaries print these links and the setup wizard writes them
// into every file it generates, so a page that moves without them reaches users
// as a dead link.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';

// A link to the site, ending at the first character no URL in source text
// carries: whitespace, a quote, a bracket or a backslash. The lookahead refuses a
// longer host such as goiabada.dev.example.com.
const siteLink = /https?:\/\/goiabada\.dev(?![\w-]|\.[\w-])[^\s"'`<>()[\]{}\\]*/g;

// Punctuation that ends a sentence rather than the link.
const trailingPunctuation = /[.,;:!?]+$/;

// Directories git ignores in a working tree: local build output and dependencies,
// not code anyone ships.
const ignoredDirectories = new Set(['.git', 'node_modules', 'tmp', '.devdata']);

// Every goiabada.dev link in the text files under srcDir, as { file, line, url },
// file being the path from srcDir's parent, so it reads src/... Throws when
// srcDir cannot be read.
export function findShippedLinks(srcDir) {
	const base = dirname(srcDir);
	const links = [];
	for (const path of textFiles(srcDir)) {
		const lines = readFileSync(path, 'utf8').split('\n');
		lines.forEach((text, index) => {
			for (const match of text.matchAll(siteLink)) {
				links.push({
					file: relative(base, path).split(sep).join('/'),
					line: index + 1,
					url: match[0].replace(trailingPunctuation, ''),
				});
			}
		});
	}
	return links;
}

function* textFiles(dir) {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) {
			if (!ignoredDirectories.has(entry.name)) yield* textFiles(path);
		} else if (entry.isFile() && !isBinary(path)) {
			yield path;
		}
	}
}

// The test git applies: a NUL byte in the first 8000 bytes.
function isBinary(path) {
	return readFileSync(path).subarray(0, 8000).includes(0);
}

// The links found under srcDir and, for each one that names nothing in distDir,
// a finding { file, line, url, problem }.
export function findShippedLinkProblems({ distDir, srcDir }) {
	const links = findShippedLinks(srcDir);
	const headingsByPage = new Map();
	const findings = [];
	for (const link of links) {
		const url = new URL(link.url);
		const pathname = safeDecode(url.pathname);
		const page = join(distDir, pathname.endsWith('/') ? pathname : `${pathname}/`, 'index.html');
		if (!existsSync(page)) {
			findings.push({ ...link, problem: 'names no built page' });
			continue;
		}
		const fragment = safeDecode(url.hash.slice(1));
		if (fragment === '') continue;
		if (!headingsByPage.has(page)) headingsByPage.set(page, headingIds(readFileSync(page, 'utf8')));
		if (!headingsByPage.get(page).has(fragment)) {
			findings.push({ ...link, problem: 'names no heading on its page' });
		}
	}
	return { links, findings };
}

function safeDecode(text) {
	try {
		return decodeURIComponent(text);
	} catch {
		return text;
	}
}

// The ids the page's headings carry, which are the fragments a link may name.
function headingIds(html) {
	const ids = new Set();
	for (const tag of html.matchAll(/<h[1-6]\b[^>]*>/gi)) {
		const id = /\sid\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag[0]);
		if (id) ids.add(decodeEntities(id[1] ?? id[2] ?? id[3]));
	}
	return ids;
}

function decodeEntities(text) {
	const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
	return text.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (entity, name) => {
		if (name[0] === '#') {
			const code = name[1] === 'x' || name[1] === 'X' ? parseInt(name.slice(2), 16) : parseInt(name.slice(1), 10);
			return String.fromCodePoint(code);
		}
		return named[name.toLowerCase()] ?? entity;
	});
}

// Throws an error naming every link that names nothing, and stops when the walk
// reached nothing: a source tree that is missing, or that holds no link at all,
// would otherwise pass whatever the code links to. Returns the links it checked.
export function assertShippedLinks({ distDir, srcDir }) {
	let result;
	try {
		result = findShippedLinkProblems({ distDir, srcDir });
	} catch (error) {
		throw new Error(`cannot read the source tree ${srcDir}: ${error.message}`);
	}
	const { links, findings } = result;
	if (links.length === 0) {
		throw new Error(`found no goiabada.dev link under ${srcDir}: the shipped-link check reached nothing`);
	}
	if (findings.length > 0) {
		const lines = findings.map((f) => `  ${f.file}:${f.line}: ${f.url} ${f.problem}`);
		throw new Error(
			`${findings.length} goiabada.dev link(s) in shipped code name nothing this build published:\n${lines.join('\n')}`,
		);
	}
	return links;
}
