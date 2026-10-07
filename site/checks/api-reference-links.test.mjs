// The check of links into the generated API reference, on fixture builds. Each
// case states the links it expects reported as literals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { apiReferences, assertApiReferenceLinks } from './api-reference-links.mjs';
import buildChecks from './build-checks.mjs';

const site = 'https://goiabada.dev';
const bases = ['reference/api/admin', 'reference/api/account'];

// An operation page as starlight-openapi renders one: the title as h1 and the
// sections as h2.
const operationPage = `<!doctype html><html><body>
<h1 id="_top">Get user</h1>
<h2 id="responses">Responses</h2>
</body></html>`;

function builtSite(pages) {
	const dist = mkdtempSync(join(tmpdir(), 'api-reference-links-'));
	const files = {
		'reference/api/admin/index.html': '<!doctype html><h1 id="_top">Overview</h1>',
		'reference/api/admin/operations/getuser/index.html': operationPage,
		'reference/api/account/index.html': '<!doctype html><h1 id="_top">Overview</h1>',
		...pages,
	};
	for (const [path, content] of Object.entries(files)) {
		mkdirSync(dirname(join(dist, path)), { recursive: true });
		writeFileSync(join(dist, path), content);
	}
	return dist;
}

function guide(links) {
	return `<!doctype html><html><body><h1 id="_top">A guide</h1>${links
		.map((href) => `<p><a class="x" href="${href}">a link</a></p>`)
		.join('\n')}</body></html>`;
}

test('links into the reference that name a built page and heading pass, counted', () => {
	const dist = builtSite({
		'guides/a/index.html': guide([
			'/reference/api/admin/',
			'/reference/api/admin/operations/getuser/#responses',
			'https://goiabada.dev/reference/api/account/',
			'/concepts/clients/',
			'https://example.com/reference/api/admin/nothing/',
		]),
	});
	assert.equal(assertApiReferenceLinks({ distDir: dist, site, bases }), 3);
});

test('a link to no generated page, or to no heading on one, fails the build naming the page and the link', () => {
	const dist = builtSite({
		'guides/a/index.html': guide([
			'/reference/api/admin/operations/getusers/',
			'/reference/api/admin/operations/getuser/#response',
			'/reference/api/account/operations/getaccountprofile/',
		]),
	});
	assert.throws(() => assertApiReferenceLinks({ distDir: dist, site, bases }), {
		message: [
			'3 link(s) into the generated API reference name nothing this build published:',
			'  guides/a/index.html: /reference/api/admin/operations/getusers/ names no built page',
			'  guides/a/index.html: /reference/api/admin/operations/getuser/#response names no heading on its page',
			'  guides/a/index.html: /reference/api/account/operations/getaccountprofile/ names no built page',
		].join('\n'),
	});
});

test('a fragment link on a reference page is checked against that page, a tab control is not', () => {
	const dist = builtSite({
		'reference/api/admin/operations/getuser/index.html': operationPage.replace(
			'</body>',
			'<a href="#responses">Responses</a><a href="#_top">Top</a><a href="#nope">Gone</a>' +
				'<a href="#tab-panel-0-0" id="tab-0" role="tab">cURL</a></body>',
		),
	});
	assert.throws(() => assertApiReferenceLinks({ distDir: dist, site, bases }), {
		message: [
			'1 link(s) into the generated API reference name nothing this build published:',
			'  reference/api/admin/operations/getuser/index.html: #nope names no heading on its page',
		].join('\n'),
	});
});

test('a build with no link into the reference stops rather than passing', () => {
	const dist = mkdtempSync(join(tmpdir(), 'api-reference-links-'));
	writeFileSync(join(dist, 'index.html'), guide(['/concepts/clients/']));
	assert.throws(() => assertApiReferenceLinks({ distDir: dist, site, bases }), {
		message: /found no link into the generated API reference/,
	});
});

test('the references are published under the bases the check is given', () => {
	assert.deepEqual(Object.values(apiReferences), bases);
});

// Runs the integration as `astro build` does, on a fixture build holding the
// reference, and returns what it threw, if anything.
async function runBuildDone(root, options) {
	const logger = { info() {}, warn() {}, error() {} };
	mkdirSync(join(root, 'src'), { recursive: true });
	writeFileSync(join(root, 'src/a.go'), '"https://goiabada.dev/"\n');
	const integration = buildChecks({ srcDir: join(root, 'src'), llms: { title: 'Goiabada', summary: 'x' }, ...options });
	try {
		await integration.hooks['astro:config:done']({ config: { site } });
		await integration.hooks['astro:build:done']({ dir: pathToFileURL(join(root, 'dist') + '/'), logger });
		return undefined;
	} catch (error) {
		return error;
	}
}

test('the build fails on a broken link into a reference it is given, and only then', async () => {
	const root = mkdtempSync(join(tmpdir(), 'api-reference-links-'));
	const dist = join(root, 'dist');
	const page = (title, body) => `<!doctype html><html><head><meta property="og:title" content="${title}"></head><body><main><div class="sl-markdown-content"><h1 id="_top">${title}</h1>${body}</div></main></body></html>`;
	for (const [path, content] of Object.entries({
		'index.html': page('Home', '<p><a href="/reference/api/admin/operations/getusers/">Users</a></p>'),
		'reference/api/admin/index.html': page('Overview', '<p>The Admin API.</p>'),
	})) {
		mkdirSync(dirname(join(dist, path)), { recursive: true });
		writeFileSync(join(dist, path), content);
	}

	const error = await runBuildDone(root, { apiReferences });
	assert.match(error?.message ?? '', /index\.html: \/reference\/api\/admin\/operations\/getusers\/ names no built page/);
	assert.equal(await runBuildDone(root, {}), undefined);
});
