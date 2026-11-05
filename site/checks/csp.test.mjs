// The step that writes each page's Content-Security-Policy, and the checks that
// every page carries it first in its head, that it covers every inline script and
// style element, that no page has an inline event handler, and that each page
// declares its encoding within its first 1024 bytes, on fixture builds.
// Each hash below was computed apart from the code, with
// `printf '%s' '<text>' | openssl dgst -sha256 -binary | base64`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

import buildChecks from './build-checks.mjs';
import { assertContentSecurityPolicy, writeContentSecurityPolicy } from './csp.mjs';

const site = 'https://goiabada.dev';

function builtSite(files) {
	const dist = mkdtempSync(join(tmpdir(), 'csp-'));
	for (const [path, content] of Object.entries(files)) {
		mkdirSync(dirname(join(dist, path)), { recursive: true });
		writeFileSync(join(dist, path), content);
	}
	return dist;
}

// A page as Astro writes it, its charset declaration first in its head.
function page(head, body = '') {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>${head}</head><body><h1 id="_top">A page</h1>${body}</body></html>`;
}

// The UTF-8 byte order mark, which declares a page's encoding before its first byte.
const bom = '\uFEFF';

// A page as the step leaves it: the byte order mark in place of its charset declaration.
function written(head, body = '') {
	return `${bom}<!DOCTYPE html><html lang="en"><head>${head}</head><body><h1 id="_top">A page</h1>${body}</body></html>`;
}

const themeScript = 'document.documentElement.dataset.theme="dark";';
const themeHash = "'sha256-nNoDk1IArGcpZ7jex4gHehJ95Th18XJDNaT2EIlmtkw='";
const moduleScript = 'import "/_astro/page.js";';
const moduleHash = "'sha256-GL7HlVvjYe8AFyIARkzO33giCYmsyUsvc6rYsA3Ahi8='";
const style = '.a{color:red}';
const styleHash = "'sha256-AYkV/wUaXEz1i9pndN1veIXFHZVFTj4Ojce2rMK7bSc='";
const svgStyle = 'svg{fill:red}';
const svgStyleHash = "'sha256-Z23pp48M9ujEGsnXCzIXozjIQ4YuG3a9Ov7tX/uw3Wc='";
const emptyHash = "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='";

// Decision 9's directives, the hashes going at the end of script-src and style-src.
function policy(scriptHashes, styleHashes) {
	return [
		"default-src 'self'",
		["script-src 'self' 'wasm-unsafe-eval' https://www.googletagmanager.com", ...scriptHashes].join(' '),
		["style-src 'self'", ...styleHashes].join(' '),
		"style-src-attr 'unsafe-inline'",
		"img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com",
		"connect-src 'self' https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	].join('; ');
}

function policyMeta(content) {
	return `<meta http-equiv="Content-Security-Policy" content="${content}">`;
}

test("the step writes each page's policy first in its head, with the hashes of that page's inline scripts and style elements", (t) => {
	const dist = builtSite({
		'index.html': page(
			[
				`<script aria-hidden="true">${themeScript}</script>`,
				'<script type="module" src="/_astro/page.js"></script>',
				`<style>${style}</style>`,
				// Its hash is the same as the first one's, so it is listed once.
				`<script>${themeScript}</script>`,
			].join(''),
			[
				`<script type="module">${moduleScript}</script>`,
				`<svg><style>${svgStyle}</style></svg>`,
				'<script></script>',
				// A data block is not run, so it needs no hash.
				'<script type="application/ld+json">{"@type":"WebSite"}</script>',
				'<p style="--sl-icon-size: 1.5em">text</p>',
			].join(''),
		),
		// A page with nothing inline still gets the policy.
		'404.html': page('<link rel="stylesheet" href="/_astro/index.css">'),
		'_astro/index.css': '.b{color:blue}',
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.equal(writeContentSecurityPolicy({ distDir: dist }), 2);

	const index = readFileSync(join(dist, 'index.html'), 'utf8');
	const expectedIndexPolicy = policy([themeHash, moduleHash, emptyHash], [styleHash, svgStyleHash]);
	assert.equal(
		index,
		written(
			[
				policyMeta(expectedIndexPolicy),
				`<script aria-hidden="true">${themeScript}</script>`,
				'<script type="module" src="/_astro/page.js"></script>',
				`<style>${style}</style>`,
				`<script>${themeScript}</script>`,
			].join(''),
			[
				`<script type="module">${moduleScript}</script>`,
				`<svg><style>${svgStyle}</style></svg>`,
				'<script></script>',
				'<script type="application/ld+json">{"@type":"WebSite"}</script>',
				'<p style="--sl-icon-size: 1.5em">text</p>',
			].join(''),
		),
	);
	assert.equal(
		readFileSync(join(dist, '404.html'), 'utf8'),
		written(`${policyMeta(policy([], []))}<link rel="stylesheet" href="/_astro/index.css">`),
	);
	assert.equal(readFileSync(join(dist, '_astro/index.css'), 'utf8'), '.b{color:blue}');
});

test('a hash is of the text the browser runs: a script is hashed as written, entities and all, in UTF-8; an SVG style after its entities are read', (t) => {
	const dist = builtSite({
		'index.html': page('<script>var s="&amp;é";</script>', '<svg><style>a{content:"&gt;"}</style></svg>'),
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	writeContentSecurityPolicy({ distDir: dist });

	const html = readFileSync(join(dist, 'index.html'), 'utf8');
	const content = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/)?.[1];
	assert.equal(
		content,
		policy(["'sha256-wy8SXwatUxdRQHCdtlT26Y16A6pgqeydvmXmprREvn0='"], ["'sha256-tlWgOYiZSUPR0T9zYn3Q+nNnd37UofFUfxrvuDKMwYs='"]),
	);
	assertContentSecurityPolicy({ distDir: dist });
});

test('a page whose head tag has attributes gets the policy just after it', (t) => {
	const dist = builtSite({ 'index.html': '<!doctype html><html><head data-x="a>b"><title>A</title></head><body></body></html>' });
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	writeContentSecurityPolicy({ distDir: dist });

	assert.equal(
		readFileSync(join(dist, 'index.html'), 'utf8'),
		`${bom}<!doctype html><html><head data-x="a>b">${policyMeta(policy([], []))}<title>A</title></head><body></body></html>`,
	);
});

test('a page that leaves out its head tag, or its html tag too, gets the policy where its head begins', (t) => {
	const dist = builtSite({
		'index.html': '<!doctype html><html lang="en"><title>A</title><h1>A</h1>',
		'404.html': '<!doctype html><meta name="description" content="Not found."><h1>404</h1>',
		'bare.html': '<h1>Bare</h1>',
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	writeContentSecurityPolicy({ distDir: dist });

	const meta = policyMeta(policy([], []));
	assert.equal(readFileSync(join(dist, 'index.html'), 'utf8'), `${bom}<!doctype html><html lang="en">${meta}<title>A</title><h1>A</h1>`);
	assert.equal(readFileSync(join(dist, '404.html'), 'utf8'), `${bom}<!doctype html>${meta}<meta name="description" content="Not found."><h1>404</h1>`);
	assert.equal(readFileSync(join(dist, 'bare.html'), 'utf8'), `${bom}${meta}<h1>Bare</h1>`);
	assert.equal(assertContentSecurityPolicy({ distDir: dist }), 3);
});

test("the step takes out a page's charset declarations, however written, and starts it with the byte order mark once", (t) => {
	const dist = builtSite({
		'index.html': '<!DOCTYPE html><html><head>\n<META CharSet=UTF-8>\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>é</title></head><body></body></html>',
		// A page that starts with the mark already keeps the one.
		'404.html': `${bom}<!DOCTYPE html><html><head><meta charset="utf-8"><title>404</title></head></html>`,
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	writeContentSecurityPolicy({ distDir: dist });

	const meta = policyMeta(policy([], []));
	const index = readFileSync(join(dist, 'index.html'));
	assert.deepEqual([...index.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
	assert.equal(index.toString('utf8'), `${bom}<!DOCTYPE html><html><head>${meta}\n\n<title>é</title></head><body></body></html>`);
	assert.equal(readFileSync(join(dist, '404.html'), 'utf8'), `${bom}<!DOCTYPE html><html><head>${meta}<title>404</title></head></html>`);
	assert.equal(assertContentSecurityPolicy({ distDir: dist }), 2);
});

test('a page whose policy pushes its charset declaration past byte 1024 passes once the step has written it', (t) => {
	// Ten script hashes, as a Starlight page has, make a policy over a thousand bytes long.
	const scripts = Array.from({ length: 10 }, (_, n) => `<script>var n=${n};</script>`).join('');
	const dist = builtSite({ 'index.html': page(scripts) });
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	writeContentSecurityPolicy({ distDir: dist });

	const html = readFileSync(join(dist, 'index.html'), 'utf8');
	assert.ok(Buffer.byteLength(html.slice(0, html.indexOf('<script>'))) > 1024, 'the policy is over 1024 bytes');
	assert.ok(!/<meta charset/i.test(html), html);
	assert.equal(assertContentSecurityPolicy({ distDir: dist }), 1);
});

test('a page whose charset declaration ends past its first 1024 bytes, or that declares no encoding, fails the build, naming the page and the byte', (t) => {
	// A head whose first 1002 bytes are the policy and a <meta> padded with é, two bytes
	// each, so a check counting characters rather than bytes would pass every page here.
	const head = `<!DOCTYPE html><html><head>${policyMeta(policy([], []))}<meta name="x" content="">`;
	const padding = 1002 - Buffer.byteLength(head);
	const lead = head.replace('content=""', `content="${'é'.repeat(Math.floor(padding / 2))}${'a'.repeat(padding % 2)}"`);
	assert.equal(Buffer.byteLength(lead), 1002);
	const dist = builtSite({
		// Its 22-byte declaration ends at byte 1024 exactly: within the limit.
		'about/index.html': `${lead}<meta charset="utf-8"></head></html>`,
		// The same page after the 3 bytes of a byte order mark ends at 1027, past it.
		'guides/a/index.html': `${bom}${lead}<meta charset="utf-8"></head></html>`,
		// A 67-byte <meta http-equiv="content-type"> is a declaration too.
		'guides/b/index.html': `${lead}<meta http-equiv="content-type" content="text/html; charset=utf-8"></head></html>`,
		// No byte order mark and no <meta charset>.
		'index.html': `<!DOCTYPE html><html><head>${policyMeta(policy([], []))}<title>A</title></head></html>`,
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertContentSecurityPolicy({ distDir: dist }), {
		message: [
			'3 Content-Security-Policy problem(s): every page must carry its policy as the first element of its head, listing the hash of each of its inline scripts and style elements, have no inline event handler, and declare its character encoding within its first 1024 bytes:',
			'  guides/a/index.html: the character encoding declaration ends at byte 1027, past the first 1024',
			'  guides/b/index.html: the character encoding declaration ends at byte 1069, past the first 1024',
			'  index.html: no character encoding declaration, neither a UTF-8 byte order mark nor a <meta charset>',
		].join('\n'),
	});
});

test('pages whose policy is first in their head and covers their inline scripts and style elements pass, counted', (t) => {
	const meta = policyMeta(policy([themeHash, moduleHash], [styleHash, svgStyleHash]));
	const dist = builtSite({
		'index.html': page(
			`<script>${themeScript}</script><style>${style}</style><script type="module" src="/_astro/page.js"></script>`,
			`<script type="module">${moduleScript}</script><svg><style>${svgStyle}</style></svg><script type="application/json">{}</script>`,
		).replace('<head>', `<head>\n\t${meta}`),
		// Directive names and http-equiv are case-insensitive, and a hash may sit in
		// script-src-elem or style-src-elem, or in default-src when there is no more
		// specific directive.
		'404.html': page(`<script>${themeScript}</script><style>${style}</style>`).replace(
			'<head>',
			`<head><meta http-equiv="content-security-policy" content="DEFAULT-SRC 'self' ${styleHash}; Script-Src-Elem 'self' ${themeHash}">`,
		),
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.equal(assertContentSecurityPolicy({ distDir: dist }), 2);
});

test('a page without its policy first in its head, or with an inline script or style element the policy leaves out, or an inline event handler, fails the build, naming the page and the problem', (t) => {
	const meta = policyMeta(policy([themeHash], [styleHash]));
	const dist = builtSite({
		// No policy at all.
		'index.html': page(`<script>${themeScript}</script>`),
		// A policy, but after the charset: whatever precedes it is not covered.
		'about/index.html': page(`${meta}<script>${themeScript}</script>`),
		// A policy in the body is not a page's policy.
		'about/license/index.html': page('', meta),
		// First in the head, but leaving out a script, a style element, and an SVG
		// style; a script's hash in style-src, and a style's in script-src, do not count.
		'guides/a/index.html': page(
			`<script>${themeScript}</script><script type="module">${moduleScript}</script><style>${style}</style>`,
			`<svg><style>${svgStyle}</style></svg>`,
		).replace('<head>', `<head>${policyMeta(policy([themeHash, svgStyleHash], [moduleHash]))}`),
		// A script-src that would allow it, overridden by script-src-elem.
		'guides/b/index.html': page(`<script>${themeScript}</script>`).replace(
			'<head>',
			`<head>${policyMeta(`default-src 'self'; script-src ${themeHash}; script-src-elem 'self'`)}`,
		),
		// Inline event handlers, whatever the policy.
		'guides/c/index.html': page(
			'',
			'<button type="button" onclick="go()">Go</button><img src="/a.png" onerror="x()"><svg><circle onload="y()"></circle></svg>',
		).replace('<head>', `<head>${meta}`),
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertContentSecurityPolicy({ distDir: dist }), {
		message: [
			'10 Content-Security-Policy problem(s): every page must carry its policy as the first element of its head, listing the hash of each of its inline scripts and style elements, have no inline event handler, and declare its character encoding within its first 1024 bytes:',
			'  about/index.html: the Content-Security-Policy is not the first element of the head',
			'  about/license/index.html: no Content-Security-Policy in the head',
			`  guides/a/index.html: inline script not in the policy, ${moduleHash}: import "/_astro/page.js";`,
			`  guides/a/index.html: inline style not in the policy, ${styleHash}: .a{color:red}`,
			`  guides/a/index.html: inline style not in the policy, ${svgStyleHash}: svg{fill:red}`,
			`  guides/b/index.html: inline script not in the policy, ${themeHash}: document.documentElement.dataset.theme="dark";`,
			'  guides/c/index.html: inline event handler onclick on <button>',
			'  guides/c/index.html: inline event handler onerror on <img>',
			'  guides/c/index.html: inline event handler onload on <circle>',
			'  index.html: no Content-Security-Policy in the head',
		].join('\n'),
	});
});

test('a long inline script is named by its first words on one line', (t) => {
	const script = `\n\t(function () {\n\t\t${'var x = 1; '.repeat(20)}\n\t})();\n`;
	const dist = builtSite({ 'index.html': page(`<script>${script}</script>`).replace('<head>', `<head>${policyMeta(policy([], []))}`) });
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertContentSecurityPolicy({ distDir: dist }), {
		message: /index\.html: inline script not in the policy, 'sha256-[^']+': \(function \(\) \{ var x = 1; var x = 1; var x = 1; var x = 1; v…$/,
	});
});

test('a build with no page stops the Content-Security-Policy step and check rather than pass', (t) => {
	const dist = builtSite({ '_astro/index.css': '.a{color:red}' });
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => writeContentSecurityPolicy({ distDir: dist }), { message: /found no built page in .*: the step reached nothing/ });
	assert.throws(() => assertContentSecurityPolicy({ distDir: dist }), { message: /found no built page in .*: the check reached nothing/ });
});

// Runs the integration as `astro build` does, on a fixture build, and returns the
// pages it left and what it threw, if anything.
async function runBuildDone(files) {
	const root = mkdtempSync(join(tmpdir(), 'csp-'));
	for (const [path, content] of Object.entries({ 'src/a.go': '"https://goiabada.dev/"\n', ...files })) {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), content);
	}
	const integration = buildChecks({ srcDir: join(root, 'src'), llms: { title: 'Goiabada', summary: 'x' } });
	let error;
	try {
		await integration.hooks['astro:config:done']({ config: { site } });
		await integration.hooks['astro:build:done']({ dir: pathToFileURL(join(root, 'dist') + '/'), logger: { info() {} } });
	} catch (thrown) {
		error = thrown;
	}
	const index = readFileSync(join(root, 'dist/index.html'), 'utf8');
	rmSync(root, { recursive: true, force: true });
	return { error, index };
}

function starlightPage(title, head, body) {
	return `<!doctype html><html><head><meta property="og:title" content="${title}">${head}</head><body><main><div class="sl-markdown-content"><h1 id="_top">${title}</h1><p>Text.</p></div></main>${body}</body></html>`;
}

test('the build writes every page its policy and checks it', async () => {
	const { error, index } = await runBuildDone({
		'dist/index.html': starlightPage('Home', `<script>${themeScript}</script>`, ''),
	});
	assert.equal(error, undefined);
	assert.ok(index.startsWith(`${bom}<!doctype html><html><head>${policyMeta(policy([themeHash], []))}<meta property="og:title"`), index);
});

test('the build fails on a page with an inline event handler', async () => {
	const { error } = await runBuildDone({
		'dist/index.html': starlightPage('Home', '', '<button onclick="go()">Go</button>'),
	});
	assert.match(error?.message ?? '', /index\.html: inline event handler onclick on <button>/);
});
