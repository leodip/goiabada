// The check of links into the generated API reference. starlight-links-validator
// checks every other internal link, but it knows the pages of the content
// collection, and starlight-openapi generates the reference's pages from
// openapi.yaml outside it, so astro.config.mjs leaves links to them to this
// check. It reads the finished pages, so a link to an operation that was renamed,
// or to a heading no generated page renders, fails the build like any other.

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import { builtLinkProblem } from './shipped-links.mjs';

// Where the two generated references are published. astro.config.mjs mounts them
// here, keeps links under them from starlight-links-validator, and hands them to
// buildChecks for this check.
export const apiReferences = { admin: 'reference/api/admin', account: 'reference/api/account' };

// Every anchor a page carries, its target captured. An anchor whose role is tab
// is a control of Starlight's tabs, pointing at a tab panel rather than a heading,
// and not a link.
const anchor = /<a\b[^>]*>/gi;
const anchorHref = /\shref\s*=\s*(?:"([^"]*)"|'([^']*)')/i;
const tabRole = /\srole\s*=\s*(?:"tab"|'tab'|tab\b)/i;

// Throws an error naming every link, on any page built in distDir, that points
// under one of bases and names nothing there, and stops when no page links under
// them at all, since that check would have read nothing. Returns how many links it
// checked.
export function assertApiReferenceLinks({ distDir, site, bases }) {
	const origin = new URL(site).origin;
	const prefixes = bases.map((base) => `/${base}/`);
	const headingsByPage = new Map();
	const findings = [];
	let checked = 0;
	for (const file of htmlFiles(distDir)) {
		const page = relative(distDir, file).split(sep).join('/');
		// The URL the page is served at, which a relative link resolves against.
		const pageUrl = `${origin}/${page.replace(/(^|\/)index\.html$/, '$1')}`;
		for (const [tag] of readFileSync(file, 'utf8').matchAll(anchor)) {
			const match = anchorHref.exec(tag);
			if (!match || tabRole.test(tag)) continue;
			const href = match[1] ?? match[2];
			const url = new URL(href.replaceAll('&amp;', '&'), pageUrl);
			if (url.origin !== origin || !prefixes.some((prefix) => url.pathname.startsWith(prefix))) continue;
			checked++;
			const problem = builtLinkProblem(distDir, url, headingsByPage);
			if (problem) findings.push(`  ${page}: ${href} ${problem}`);
		}
	}
	if (checked === 0) {
		throw new Error(`found no link into the generated API reference in ${distDir}: the check reached nothing`);
	}
	if (findings.length > 0) {
		throw new Error(
			`${findings.length} link(s) into the generated API reference name nothing this build published:\n${findings.join('\n')}`,
		);
	}
	return checked;
}

function* htmlFiles(dir) {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) yield* htmlFiles(path);
		else if (entry.isFile() && entry.name.endsWith('.html')) yield path;
	}
}
