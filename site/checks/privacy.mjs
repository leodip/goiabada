// The checks behind the Privacy page's promises, on the finished pages. No page or
// stylesheet the build wrote may load anything from another site, so nothing
// reaches another server, Google's tag above all, before the visitor accepts it:
// the consent prompt's script adds Google's tag at run time, after Accept, and is
// a script, which this check does not read. And every page must carry that prompt
// and the footer's Privacy and Cookie settings links, so the choice is offered and
// can be changed on every page.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import { fromHtml } from 'hast-util-from-html';

import { builtLinkProblem } from './shipped-links.mjs';

// The attributes that make each element fetch what they name, as hast names them,
// with the attribute's name for the message. srcset-like attributes hold a list of
// candidates. Links are handled apart, by their rel.
const loadingAttributes = {
	script: [['src', 'src']],
	img: [['src', 'src'], ['srcSet', 'srcset']],
	source: [['src', 'src'], ['srcSet', 'srcset']],
	iframe: [['src', 'src']],
	frame: [['src', 'src']],
	video: [['src', 'src'], ['poster', 'poster']],
	audio: [['src', 'src']],
	track: [['src', 'src']],
	embed: [['src', 'src']],
	object: [['data', 'data']],
	input: [['src', 'src']],
	image: [['href', 'href'], ['xLinkHref', 'xlink:href']],
	use: [['href', 'href'], ['xLinkHref', 'xlink:href']],
	feImage: [['href', 'href'], ['xLinkHref', 'xlink:href']],
};
const candidateLists = new Set(['srcSet', 'imageSrcSet']);

// The link types that fetch nothing: a link whose every type is one of these
// points somewhere without loading it. Any other link, stylesheet, preload,
// modulepreload, prefetch, preconnect, dns-prefetch, icon, manifest or a type
// this list does not know, counts as a load.
const nonLoadingRels = new Set([
	'alternate',
	'author',
	'bookmark',
	'canonical',
	'external',
	'help',
	'license',
	'me',
	'next',
	'nofollow',
	'noopener',
	'noreferrer',
	'prev',
	'sitemap',
	'tag',
]);

// A CSS load: an @import, of a string or a url(), or any other url(). The quoted
// forms may hold a parenthesis; an unquoted url() cannot.
const cssString = String.raw`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`;
const cssUrl = String.raw`url\(\s*(?:${cssString}|([^)\s"']*))\s*\)`;
const cssLoad = new RegExp(String.raw`@import\s*(?:${cssUrl}|${cssString})|${cssUrl}`, 'gi');
const cssComment = /\/\*[\s\S]*?\*\//g;

// Throws an error naming every load from another origin than site's in the pages
// and stylesheets built in distDir, and stops when there is no page, since the
// check would have read nothing. data: URLs load nothing from anywhere. Returns
// how many pages and stylesheets it read.
export function assertNoOffSiteLoads({ distDir, site }) {
	const origin = new URL(site).origin;
	const pages = builtFiles(distDir, '.html');
	if (pages.length === 0) throw new Error(`found no built page in ${distDir}: the check reached nothing`);
	const stylesheets = builtFiles(distDir, '.css');
	const findings = [];
	const report = (file, what, value, base) => {
		if (isOffSite(value, base, origin)) findings.push(`  ${file}: ${what} ${value}`);
	};

	for (const file of pages) {
		const pageUrl = servedUrl(origin, file);
		walk(fromHtml(readFileSync(join(distDir, file), 'utf8')), (node) => {
			const props = node.properties ?? {};
			if (node.tagName === 'link') {
				const rels = relTokens(props.rel);
				if (props.href !== undefined && !rels.every((rel) => nonLoadingRels.has(rel))) {
					report(file, `link rel="${rels.join(' ')}"`, String(props.href), pageUrl);
				}
				if (props.imageSrcSet !== undefined) {
					for (const url of candidateUrls(String(props.imageSrcSet))) report(file, 'link imagesrcset', url, pageUrl);
				}
			}
			for (const [property, name] of loadingAttributes[node.tagName] ?? []) {
				if (props[property] === undefined) continue;
				const value = String(props[property]);
				for (const url of candidateLists.has(property) ? candidateUrls(value) : [value]) {
					report(file, `${node.tagName} ${name}`, url, pageUrl);
				}
			}
			if (node.tagName === 'style') {
				for (const [kind, url] of cssLoads(textOf(node))) report(file, `style ${kind}`, url, pageUrl);
			}
			if (typeof props.style === 'string') {
				for (const [kind, url] of cssLoads(props.style)) report(file, `${node.tagName} style ${kind}`, url, pageUrl);
			}
		});
	}
	for (const file of stylesheets) {
		const sheetUrl = `${origin}/${file}`;
		for (const [kind, url] of cssLoads(readFileSync(join(distDir, file), 'utf8'))) report(file, kind, url, sheetUrl);
	}

	if (findings.length > 0) {
		throw new Error(
			`${findings.length} load(s) from another site in the built pages and stylesheets; the site must serve everything it loads:\n${findings.join('\n')}`,
		);
	}
	return { pages: pages.length, stylesheets: stylesheets.length };
}

// The prompt's library, vanilla-cookieconsent, mounts it in an element with this
// id, so a script holding it is the prompt's: the Footer override's script, which
// bundles the library with the site's configuration (src/consent/config.mjs).
const promptMarker = 'cc-main';

// Every static import in a built module, which the browser loads with it.
const moduleImport = /\bimport\s*(?:[\w$*{}\s,]+?\s*from\s*)?["']([^"']+)["']/g;

// Throws an error naming every page built in distDir that lacks the consent
// prompt's script, a link with the words Privacy to privacyPage, or the Cookie
// settings element that reopens the choice, and when privacyPage is not a built
// page. Stops when there is no page. Returns how many pages it read.
export function assertConsentOnEveryPage({ distDir, site, privacyPage }) {
	const origin = new URL(site).origin;
	const pages = builtFiles(distDir, '.html');
	if (pages.length === 0) throw new Error(`found no built page in ${distDir}: the check reached nothing`);
	const privacyUrl = new URL(privacyPage, origin);
	if (builtLinkProblem(distDir, privacyUrl, new Map())) {
		throw new Error(`the footer's Privacy link, ${privacyPage}, names no built page`);
	}

	const promptByScript = new Map();
	const findings = [];
	for (const file of pages) {
		const pageUrl = servedUrl(origin, file);
		let prompt = false;
		let privacyLink = false;
		let cookieSettings = false;
		walk(fromHtml(readFileSync(join(distDir, file), 'utf8')), (node) => {
			const props = node.properties ?? {};
			if (node.tagName === 'script' && props.type === 'module') {
				if (props.src === undefined) {
					prompt ||= textOf(node).includes(promptMarker);
				} else {
					const url = new URL(String(props.src), pageUrl);
					prompt ||= url.origin === origin && holdsPrompt(distDir, url.pathname, promptByScript, new Set());
				}
			}
			if (node.tagName === 'a' && props.href !== undefined && textOf(node).trim() === 'Privacy') {
				const url = new URL(String(props.href), pageUrl);
				privacyLink ||= url.origin === origin && url.pathname === privacyUrl.pathname && url.hash === '';
			}
			if (props.dataCc === 'show-preferencesModal' && textOf(node).trim() === 'Cookie settings') {
				cookieSettings = true;
			}
		});
		if (!prompt) findings.push(`  ${file}: no consent prompt`);
		if (!privacyLink) findings.push(`  ${file}: no Privacy link to ${privacyPage}`);
		if (!cookieSettings) findings.push(`  ${file}: no Cookie settings link`);
	}

	if (findings.length > 0) {
		throw new Error(
			`${findings.length} page problem(s): every page must carry the consent prompt and the footer's Privacy and Cookie settings links:\n${findings.join('\n')}`,
		);
	}
	return pages.length;
}

// Whether the built module at pathname, or one it imports, holds the prompt.
// cache keeps each module's answer; seen stops an import cycle.
function holdsPrompt(distDir, pathname, cache, seen) {
	if (cache.has(pathname)) return cache.get(pathname);
	if (seen.has(pathname)) return false;
	seen.add(pathname);
	const file = join(distDir, decodeURIComponent(pathname));
	let found = false;
	if (existsSync(file)) {
		const code = readFileSync(file, 'utf8');
		found = code.includes(promptMarker);
		for (const [, specifier] of found ? [] : code.matchAll(moduleImport)) {
			const url = new URL(specifier, `https://site.invalid${pathname}`);
			if (url.origin === 'https://site.invalid' && holdsPrompt(distDir, url.pathname, cache, seen)) {
				found = true;
				break;
			}
		}
	}
	cache.set(pathname, found);
	return found;
}

// Whether value, resolved against base, is fetched from another origin.
function isOffSite(value, base, origin) {
	const trimmed = value.trim();
	if (trimmed === '' || trimmed.startsWith('#')) return false;
	let url;
	try {
		url = new URL(trimmed, base);
	} catch {
		return false;
	}
	if (url.protocol === 'data:') return false;
	return url.origin !== origin;
}

// The URLs of a srcset's candidates, each a URL and an optional descriptor, as
// the HTML standard splits them: a URL runs to the next whitespace, and a comma
// ending it ends the candidate; otherwise the descriptor runs to the next comma.
function candidateUrls(srcset) {
	const urls = [];
	let at = 0;
	while (at < srcset.length) {
		while (at < srcset.length && /[\s,]/.test(srcset[at])) at++;
		if (at >= srcset.length) break;
		const start = at;
		while (at < srcset.length && !/\s/.test(srcset[at])) at++;
		let url = srcset.slice(start, at);
		if (url.endsWith(',')) {
			url = url.replace(/,+$/, '');
		} else {
			let depth = 0;
			while (at < srcset.length && (srcset[at] !== ',' || depth > 0)) {
				if (srcset[at] === '(') depth++;
				if (srcset[at] === ')') depth--;
				at++;
			}
		}
		urls.push(url);
	}
	return urls;
}

// Every load in a piece of CSS, as [kind, url], kind being @import or url().
function cssLoads(css) {
	const loads = [];
	for (const match of css.replace(cssComment, '').matchAll(cssLoad)) {
		const [, importUrlDq, importUrlSq, importUrlBare, importDq, importSq, urlDq, urlSq, urlBare] = match;
		const imported = importUrlDq ?? importUrlSq ?? importUrlBare ?? importDq ?? importSq;
		if (imported !== undefined) loads.push(['@import', imported]);
		else loads.push(['url()', urlDq ?? urlSq ?? urlBare]);
	}
	return loads;
}

function relTokens(rel) {
	const tokens = Array.isArray(rel) ? rel : String(rel ?? '').split(/\s+/);
	return tokens.map((token) => String(token).toLowerCase()).filter(Boolean);
}

// The URL a built file is served at: a page's directory for its index.html.
function servedUrl(origin, file) {
	return `${origin}/${file.replace(/(^|\/)index\.html$/, '$1')}`;
}

// Calls visit with every element in the tree, in document order, a template's
// content included.
function walk(node, visit) {
	if (node.type === 'element') visit(node);
	for (const child of node.children ?? []) walk(child, visit);
	if (node.content) walk(node.content, visit);
}

function textOf(node) {
	if (node.type === 'text') return node.value;
	return (node.children ?? []).map(textOf).join('');
}

// The files under distDir ending in extension, as sorted paths from distDir with
// forward slashes.
function builtFiles(distDir, extension) {
	const files = [];
	const visit = (dir) => {
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) visit(path);
			else if (entry.isFile() && entry.name.endsWith(extension)) files.push(relative(distDir, path).split(sep).join('/'));
		}
	};
	visit(distDir);
	return files.sort();
}
