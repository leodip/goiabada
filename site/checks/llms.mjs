// The llms files: /llms.txt, the llmstxt.org index of every page with its title,
// URL and description, and /llms-full.txt, every page's content as Markdown, each
// headed by its title and URL. Both are written from the pages the build
// published, so the generated API reference is in them like any other page, and
// the sync check reads them back and fails the build when they and the pages
// disagree: a page missing from either file, an entry naming no page, or an
// entry missing text its page renders. The 404 page documents nothing and is in
// neither.

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import { fromHtml } from 'hast-util-from-html';
import { select, selectAll } from 'hast-util-select';
import { toMdast } from 'hast-util-to-mdast';
import { fromMarkdown } from 'mdast-util-from-markdown';
import { gfmStrikethroughToMarkdown } from 'mdast-util-gfm-strikethrough';
import { gfmTableToMarkdown } from 'mdast-util-gfm-table';
import { gfmTaskListItemToMarkdown } from 'mdast-util-gfm-task-list-item';
import { toMarkdown } from 'mdast-util-to-markdown';
import { toString } from 'mdast-util-to-string';

// The two files' names, at the site's root. A page may link to them, and
// astro.config.mjs keeps those two links from the link check, which runs before
// they are written.
export const indexFile = 'llms.txt';
export const fullFile = 'llms-full.txt';

// GitHub's tables, strikethrough and task lists, which the converter emits, but
// not its autolink literals: those escape the colon of every URL in prose.
const markdownOptions = {
	bullet: '-',
	listItemIndent: 'one',
	fences: true,
	extensions: [gfmTableToMarkdown({ tablePipeAlign: false }), gfmStrikethroughToMarkdown(), gfmTaskListItemToMarkdown()],
};

// The text of a parsed entry, as a reader sees it: link and image targets and
// raw HTML are not text.
const textOptions = { includeImageAlt: false, includeHtml: false };

// Elements that sit inside a line of text. Any other element starts and ends a
// block, and the text of each block is one piece the sync check looks for.
const inlineElements = new Set([
	'a', 'abbr', 'b', 'bdi', 'bdo', 'br', 'cite', 'code', 'data', 'del', 'dfn', 'em', 'i', 'img', 'ins',
	'kbd', 'mark', 'q', 's', 'samp', 'small', 'span', 'strong', 'sub', 'sup', 'time', 'u', 'var', 'wbr',
]);

// Elements that render no text a reader needs: scripts, icons and controls.
const droppedElements = new Set(['script', 'style', 'svg', 'template', 'button']);

// Every page the build published under distDir, ordered by URL, as
// { url, title, description, content, tree }. content is the page's main
// content as hast, without what Starlight renders around it (the page footer)
// or for screen readers and controls only, and without the title heading, which
// heads the page's entry instead.
function readPages(distDir, site) {
	const pages = [];
	for (const file of htmlFiles(distDir)) {
		const path = relative(distDir, file).split(sep).join('/');
		if (path === '404.html') continue;
		const url = new URL(`/${path.replace(/(^|\/)index\.html$/, '$1')}`, site).href;
		const tree = fromHtml(readFileSync(file, 'utf8'));
		const title = metaContent(tree, 'meta[property="og:title"]') ?? oneLine(textOf(select('h1#_top', tree)));
		const description = metaContent(tree, 'meta[name="description"]');
		const main = select('main', tree) ?? select('body', tree) ?? tree;
		const content = { type: 'root', children: prune(main.children, title, false) };
		pages.push({ url, title, description, content, tree });
	}
	return pages.sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
}

function* htmlFiles(dir) {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) yield* htmlFiles(path);
		else if (entry.isFile() && entry.name.endsWith('.html')) yield path;
	}
}

function prune(nodes, title, inMarkdown) {
	const kept = [];
	for (const node of nodes) {
		if (node.type === 'text') {
			kept.push(node);
			continue;
		}
		if (node.type !== 'element') continue;
		const classes = node.properties.className ?? [];
		if (droppedElements.has(node.tagName)) continue;
		if (node.properties.dataPagefindIgnore !== undefined) continue;
		if (classes.includes('sr-only') || classes.includes('sl-anchor-link')) continue;
		if (node.tagName === 'footer' && !inMarkdown) continue;
		if (node.tagName === 'h1' && node.properties.id === '_top' && oneLine(textOf(node)) === title) continue;
		const markdown = inMarkdown || classes.includes('sl-markdown-content');
		kept.push({ ...node, children: prune(node.children, title, markdown) });
	}
	return kept;
}

function metaContent(tree, selector) {
	const content = select(selector, tree)?.properties.content;
	return content === undefined ? undefined : oneLine(String(content));
}

function textOf(node) {
	if (!node) return '';
	if (node.type === 'text') return node.value;
	return (node.children ?? []).map(textOf).join('');
}

function oneLine(text) {
	return text.replace(/\s+/g, ' ').trim();
}

// The letters and digits of a text, which is what the sync check compares:
// Markdown adds and escapes punctuation, and moves whitespace, but keeps these.
function squash(text) {
	return text.normalize('NFC').replace(/[^\p{L}\p{N}]+/gu, '');
}

// The pages in the order the files list them: the sidebar's groups in its order,
// a nested group's pages within its top-level group, then every page the sidebar
// does not list, by URL. Returns [{ label, pages }].
function sections(pages, site) {
	const byUrl = new Map(pages.map((page) => [page.url, page]));
	const placed = new Set();
	const result = [];
	const sidebar = pages.map((page) => select('#starlight__sidebar .top-level', page.tree)).find(Boolean);
	for (const item of sidebar?.children ?? []) {
		const group = item.type === 'element' ? select('details', item) : undefined;
		if (!group) continue;
		const grouped = [];
		for (const link of selectAll('a[href]', group)) {
			const page = byUrl.get(new URL(String(link.properties.href), site).href);
			if (page && !placed.has(page.url)) {
				placed.add(page.url);
				grouped.push(page);
			}
		}
		if (grouped.length > 0) result.push({ label: oneLine(textOf(select('summary', group))), pages: grouped });
	}
	const rest = pages.filter((page) => !placed.has(page.url));
	if (rest.length > 0) result.push({ label: 'Other pages', pages: rest });
	return result;
}

// Writes llms.txt and llms-full.txt into distDir, from the pages there, and
// returns how many pages they hold. title and summary head llms.txt.
export function writeLlmsFiles({ distDir, site, title, summary }) {
	const ordered = sections(readPages(distDir, site), site);
	const fullUrl = new URL(`/${fullFile}`, site).href;

	const index = [
		{ type: 'heading', depth: 1, children: [text(title)] },
		{ type: 'blockquote', children: [paragraph([text(summary)])] },
		paragraph([text('Every page below, in full and as Markdown, is in one file: '), link(fullUrl, fullFile)]),
	];
	for (const section of ordered) {
		index.push({ type: 'heading', depth: 2, children: [text(section.label)] });
		index.push({
			type: 'list',
			spread: false,
			children: section.pages.map((page) => ({
				type: 'listItem',
				spread: false,
				children: [
					paragraph([link(page.url, page.title), ...(page.description ? [text(`: ${page.description}`)] : [])]),
				],
			})),
		});
	}
	writeFileSync(join(distDir, indexFile), toMarkdown({ type: 'root', children: index }, markdownOptions));

	const entries = ordered.flatMap((section) => section.pages).map((page) => {
		const body = toMdast({ type: 'root', children: transform(page.content.children, page.url) });
		const entry = [
			{ type: 'heading', depth: 1, children: [text(page.title)] },
			paragraph([text(`Source: ${page.url}`)]),
			...body.children,
		];
		return toMarkdown({ type: 'root', children: entry }, markdownOptions);
	});
	writeFileSync(join(distDir, fullFile), entries.join('\n'));

	return entries.length;
}

function text(value) {
	return { type: 'text', value };
}

function paragraph(children) {
	return { type: 'paragraph', children };
}

function link(url, label) {
	return { type: 'link', url, children: [text(label)] };
}

function element(tagName, properties, children) {
	return { type: 'element', tagName, properties, children };
}

// Rewrites what Starlight renders from its components into the plain HTML a
// Markdown converter knows: a code frame into a fenced block, tabs into each
// panel under its label, an aside into a block quote under its title, and a link
// card into a link and its description. Links and images become absolute, since
// the file is read away from the site.
function transform(nodes, pageUrl) {
	return nodes.flatMap((node) => {
		if (node.type !== 'element') return [node];
		const classes = node.properties.className ?? [];
		if (classes.includes('expressive-code')) return codeFrame(node);
		if (node.tagName === 'starlight-tabs') return tabs(node, pageUrl);
		if (classes.includes('starlight-aside')) {
			const heading = select('.starlight-aside__title', node);
			const body = select('.starlight-aside__content', node);
			return [
				element('blockquote', {}, [
					element('p', {}, [element('strong', {}, [text(oneLine(textOf(heading)))])]),
					...transform(body?.children ?? [], pageUrl),
				]),
			];
		}
		if (classes.includes('sl-link-card')) {
			const anchor = select('a[href]', node);
			const description = oneLine(textOf(select('.description', node)));
			return [
				element('p', {}, [
					element('a', { href: absolute(anchor.properties.href, pageUrl) }, [text(oneLine(textOf(anchor)))]),
					text(`: ${description}`),
				]),
			];
		}
		const properties = { ...node.properties };
		if (node.tagName === 'a' && properties.href !== undefined) properties.href = absolute(properties.href, pageUrl);
		if (node.tagName === 'img' && properties.src !== undefined) properties.src = absolute(properties.src, pageUrl);
		return [{ ...node, properties, children: transform(node.children, pageUrl) }];
	});
}

function absolute(href, pageUrl) {
	return new URL(String(href), pageUrl).href;
}

function codeFrame(node) {
	const pre = select('pre', node);
	if (!pre) return [];
	const lines = selectAll('.ec-line', pre);
	const code = lines.length > 0 ? lines.map(textOf).join('\n') : textOf(pre);
	const language = pre.properties.dataLanguage;
	const result = [];
	const caption = oneLine(textOf(select('figcaption .title', node)));
	if (caption !== '') result.push(element('p', {}, [element('em', {}, [text(caption)])]));
	result.push(
		element('pre', {}, [element('code', language ? { className: [`language-${language}`] } : {}, [text(code)])]),
	);
	return result;
}

function tabs(node, pageUrl) {
	const labels = selectAll('[role=tablist] [role=tab]', node).map((tab) => oneLine(textOf(tab)));
	const panels = node.children.filter((child) => child.type === 'element' && child.properties.role === 'tabpanel');
	return panels.flatMap((panel, index) => [
		element('p', {}, [element('strong', {}, [text(labels[index] ?? '')])]),
		...transform(panel.children, pageUrl),
	]);
}

// The text a page renders, as the pieces the sync check looks for: the text of
// each block, as { text, key }, key being its letters and digits.
function renderedText(content) {
	const pieces = new Map();
	let buffer = '';
	const flush = () => {
		const key = squash(buffer);
		if (key !== '' && !pieces.has(key)) pieces.set(key, oneLine(buffer));
		buffer = '';
	};
	const walk = (node) => {
		if (node.type === 'text') {
			buffer += node.value;
			return;
		}
		const block = node.type === 'element' && !inlineElements.has(node.tagName);
		if (block) flush();
		for (const child of node.children ?? []) walk(child);
		if (block) flush();
	};
	walk(content);
	flush();
	return [...pieces].map(([key, text]) => ({ key, text }));
}

// The entries of llms.txt: each list item that opens with a link, as
// { url, title, description }.
function indexEntries(markdown) {
	const entries = [];
	const walk = (node) => {
		if (node.type === 'listItem') {
			const [first] = node.children;
			if (first?.type === 'paragraph' && first.children[0]?.type === 'link') {
				const [anchor, ...rest] = first.children;
				entries.push({
					url: anchor.url,
					title: oneLine(toString(anchor, textOptions)),
					description: oneLine(rest.map((child) => toString(child, textOptions)).join('')).replace(/^:\s*/, ''),
				});
			}
		}
		for (const child of node.children ?? []) walk(child);
	};
	walk(fromMarkdown(markdown));
	return entries;
}

// The entries of llms-full.txt: each top-level heading followed by its Source
// line, holding everything up to the next, as { url, title, text }.
function fullEntries(markdown) {
	const nodes = fromMarkdown(markdown).children;
	const sourceOf = (index) => {
		const [heading, next] = [nodes[index], nodes[index + 1]];
		if (heading.type !== 'heading' || heading.depth !== 1 || next?.type !== 'paragraph') return undefined;
		return /^Source: (\S+)$/.exec(toString(next, textOptions))?.[1];
	};
	const entries = [];
	for (let index = 0; index < nodes.length; index++) {
		const url = sourceOf(index);
		if (url === undefined) {
			entries.at(-1)?.body.push(nodes[index]);
			continue;
		}
		entries.push({ url, title: oneLine(toString(nodes[index], textOptions)), body: [] });
		index++;
	}
	return entries.map(({ url, title, body }) => ({
		url,
		title,
		text: toString({ type: 'root', children: body }, textOptions),
	}));
}

function readText(path) {
	try {
		return readFileSync(path, 'utf8');
	} catch (error) {
		throw new Error(`cannot read ${path}: ${error.message}`);
	}
}

function canonical(url) {
	try {
		return new URL(url).href;
	} catch {
		return url;
	}
}

// Every way llms.txt and llms-full.txt in distDir disagree with the pages there,
// as one line each. Throws when there is no page to check, or a file cannot be
// read.
export function findLlmsProblems({ distDir, site }) {
	const pages = readPages(distDir, site);
	if (pages.length === 0) {
		throw new Error(`found no built page under ${distDir}: the llms check reached nothing`);
	}
	const byUrl = new Map(pages.map((page) => [page.url, page]));
	const findings = [];

	const check = (file, entries, checkEntry) => {
		const named = new Set();
		for (const entry of entries) {
			const page = byUrl.get(canonical(entry.url));
			if (!page) {
				findings.push(`${file}: the entry ${entry.url} names no built page`);
				continue;
			}
			named.add(page.url);
			if (entry.title !== page.title) {
				findings.push(`${file}: the entry ${page.url} lacks the title its page renders: "${page.title}"`);
			}
			checkEntry(entry, page);
		}
		for (const page of pages) {
			if (!named.has(page.url)) findings.push(`${file} has no entry for the page ${page.url}`);
		}
	};

	check(indexFile, indexEntries(readText(join(distDir, indexFile))), (entry, page) => {
		if (page.description && entry.description !== page.description) {
			findings.push(`llms.txt: the entry ${page.url} lacks the description its page renders: "${page.description}"`);
		}
	});
	check(fullFile, fullEntries(readText(join(distDir, fullFile))), (entry, page) => {
		const entryText = squash(entry.text);
		for (const piece of renderedText(page.content)) {
			if (!entryText.includes(piece.key)) {
				findings.push(`llms-full.txt: the entry ${page.url} lacks text its page renders: "${piece.text}"`);
			}
		}
	});
	return findings;
}

// Throws an error naming every disagreement between the llms files in distDir
// and the pages there.
export function assertLlmsFiles({ distDir, site }) {
	const findings = findLlmsProblems({ distDir, site });
	if (findings.length > 0) {
		throw new Error(
			`the llms files and the pages disagree in ${findings.length} place(s):\n${findings.map((f) => `  ${f}`).join('\n')}`,
		);
	}
}
