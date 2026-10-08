// The shipped-link check, driven the way the build drives it: through the
// integration's astro:build:done hook, on a fixture build and a fixture source
// tree. Each case states its expected links and messages as literals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

import buildChecks from './build-checks.mjs';
import { findShippedLinks } from './shipped-links.mjs';

// A built page as Starlight renders one: its description, the title as h1, the
// sections as h2 and h3, and an element with an id that is not a heading.
const guidePage = `<!doctype html><html><head><meta name="description" content="Run behind a proxy."/></head><body>
<h1 id="_top">A guide</h1>
<div class="sl-heading-wrapper level-h2"><h2 id="client-ip-resolution">Client IP resolution</h2></div>
<div class="sl-heading-wrapper level-h3"><h3 id="security-settings" class="x">Security settings</h3></div>
<div id="not-a-heading">A box</div>
</body></html>`;

function fixture(files) {
	const root = mkdtempSync(join(tmpdir(), 'shipped-links-'));
	for (const [path, content] of Object.entries(files)) {
		const full = join(root, path);
		mkdirSync(dirname(full), { recursive: true });
		writeFileSync(full, content);
	}
	return root;
}

function builtSite(extraSource) {
	return fixture({
		'site/dist/index.html': '<!doctype html><meta name="description" content="The home page."/><h1 id="_top">Home</h1>',
		'site/dist/guides/proxy/index.html': guidePage,
		'site/dist/404.html': '<!doctype html><h1 id="_top">404</h1>',
		...extraSource,
	});
}

// Runs the hook as `astro build` does, and returns what it threw, if anything.
async function runBuildDone(root) {
	const logged = [];
	const logger = {
		info: (m) => logged.push(m),
		warn: (m) => logged.push(m),
		error: (m) => logged.push(m),
	};
	const integration = buildChecks({ srcDir: join(root, 'src'), llms: { title: 'Goiabada', summary: 'Docs.' } });
	try {
		await integration.hooks['astro:config:done']({ config: { site: 'https://goiabada.dev' } });
		await integration.hooks['astro:build:done']({ dir: pathToFileURL(join(root, 'site/dist') + '/'), logger });
		return { error: undefined, logged };
	} catch (error) {
		return { error, logged };
	}
}

test('a link to a built page, with or without its slash, and to a heading on it, passes', async (t) => {
	const root = builtSite({
		'src/server/warn.go': 'const msg = "See https://goiabada.dev/guides/proxy/#client-ip-resolution"\n',
		'src/wizard/compose.yml': '# https://goiabada.dev/guides/proxy/#security-settings\n# https://goiabada.dev/guides/proxy\n',
		'src/admin/index.html': '<a href="https://goiabada.dev">Docs</a>\n',
		'src/wizard/flags.go': 'p("For more information, visit: https://goiabada.dev\\n")\n',
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuildDone(root);

	assert.equal(error, undefined);
});

test('a link to no built page fails the build, naming the file, the line and the link', async (t) => {
	const root = builtSite({
		'src/server/warn.go': 'package server\n\nconst msg = "See https://goiabada.dev/production-deployment/reverse-proxy/"\n',
		'src/wizard/compose.yml': '# https://goiabada.dev/guides/proxy/\n',
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuildDone(root);

	assert.ok(error, 'the build must fail');
	assert.match(
		error.message,
		/src\/server\/warn\.go:3: https:\/\/goiabada\.dev\/production-deployment\/reverse-proxy\/ names no built page/,
	);
	assert.doesNotMatch(error.message, /compose\.yml/);
});

test('a fragment no heading on its page produces fails the build', async (t) => {
	const root = builtSite({
		'src/wizard/config.go':
			'package main\n\nconst a = "https://goiabada.dev/guides/proxy/#gone"\nconst b = "https://goiabada.dev/guides/proxy/#not-a-heading"\nconst c = "https://goiabada.dev/guides/proxy/#client-ip-resolution"\n',
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuildDone(root);

	assert.ok(error, 'the build must fail');
	assert.match(error.message, /src\/wizard\/config\.go:3: https:\/\/goiabada\.dev\/guides\/proxy\/#gone names no heading on its page/);
	assert.match(
		error.message,
		/src\/wizard\/config\.go:4: https:\/\/goiabada\.dev\/guides\/proxy\/#not-a-heading names no heading on its page/,
	);
	assert.doesNotMatch(error.message, /config\.go:5/);
});

test('the 404 page is not a page a link may name', async (t) => {
	const root = builtSite({ 'src/a.go': '"https://goiabada.dev/404.html" "https://goiabada.dev/404/"\n' });
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuildDone(root);

	assert.ok(error, 'the build must fail');
	assert.match(error.message, /src\/a\.go:1: https:\/\/goiabada\.dev\/404\.html names no built page/);
	assert.match(error.message, /src\/a\.go:1: https:\/\/goiabada\.dev\/404\/ names no built page/);
});

test('a source tree with no goiabada.dev link stops the build rather than pass', async (t) => {
	const root = builtSite({ 'src/a.go': 'package a // mail noreply@goiabada.dev, not a link\n' });
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuildDone(root);

	assert.ok(error, 'the build must fail');
	assert.match(error.message, /found no goiabada\.dev link under .*src/);
});

test('a missing source tree stops the build rather than pass', async (t) => {
	const root = builtSite({});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuildDone(root);

	assert.ok(error, 'the build must fail');
	assert.match(error.message, /cannot read the source tree .*src/);
});

test('links are read from text, up to the character that ends them', (t) => {
	const root = fixture({
		'src/a.go': 'x := "https://goiabada.dev/a/#b"\n// See https://goiabada.dev/c/d/.\n',
		'src/b.md': 'Read [the docs](https://goiabada.dev/e/), or http://goiabada.dev/f/?x=1#g.\nnoreply@goiabada.dev\n',
		'src/c.html': "<a href='https://goiabada.dev/h/'>h</a> https://goiabada.dev\n",
		'src/d.tmpl': '`https://goiabada.dev/i/` https://goiabada.dev.example.com/no/\n',
		// A compiled binary carries the same strings; it is not source.
		'src/tool/goiabada-setup': Buffer.concat([Buffer.from('\x7fELF\0\0'), Buffer.from('https://goiabada.dev/binary/')]),
		// Local build output, which git ignores.
		'src/server/tmp/out.log': 'https://goiabada.dev/tmp/\n',
		'src/web/node_modules/x/index.js': '"https://goiabada.dev/node-modules/"\n',
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const links = findShippedLinks(join(root, 'src'))
		.map((l) => `${l.file}:${l.line} ${l.url}`)
		.sort();

	assert.deepEqual(links, [
		'src/a.go:1 https://goiabada.dev/a/#b',
		'src/a.go:2 https://goiabada.dev/c/d/',
		'src/b.md:1 http://goiabada.dev/f/?x=1#g',
		'src/b.md:1 https://goiabada.dev/e/',
		'src/c.html:1 https://goiabada.dev',
		'src/c.html:1 https://goiabada.dev/h/',
		'src/d.tmpl:1 https://goiabada.dev/i/',
	]);
});
