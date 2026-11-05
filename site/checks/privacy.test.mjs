// The checks that no built page loads anything from another site, and that every
// page carries the consent prompt and the footer's Privacy and Cookie settings
// links, on fixture builds. Each case states the findings it expects as literals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

import buildChecks from './build-checks.mjs';
import { assertConsentOnEveryPage, assertNoOffSiteLoads } from './privacy.mjs';

const site = 'https://goiabada.dev';
const privacyPage = '/about/privacy/';

function builtSite(files) {
	const dist = mkdtempSync(join(tmpdir(), 'privacy-'));
	for (const [path, content] of Object.entries(files)) {
		mkdirSync(dirname(join(dist, path)), { recursive: true });
		writeFileSync(join(dist, path), content);
	}
	return dist;
}

function page(head, body = '') {
	return `<!doctype html><html><head><meta charset="utf-8">${head}</head><body><h1 id="_top">A page</h1>${body}</body></html>`;
}

test('pages and stylesheets that load only from the site pass, counted; links that load nothing are not loads', (t) => {
	const dist = builtSite({
		'index.html': page(
			[
				'<script type="module" src="/_astro/page.js"></script>',
				'<script>window.x = "https://example.com/inline.js";</script>',
				'<link rel="stylesheet" href="/_astro/index.css">',
				'<link rel="stylesheet" href="https://goiabada.dev/_astro/print.css" media="print">',
				'<link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">',
				'<link rel="canonical" href="https://goiabada.dev/">',
				'<link rel="sitemap" href="https://other.example/sitemap-index.xml">',
				'<link rel="alternate" href="https://other.example/feed.xml">',
				'<style>.a{background:url(/img/a.png)}.b{background:url("data:image/svg+xml,<svg></svg>")}</style>',
			].join(''),
			[
				'<a href="https://github.com/leodip/goiabada">GitHub</a>',
				'<img src="../img/goiaba.png" srcset="/img/a.webp 1x, img/b.webp 2x, data:image/png;base64,iVBOR,w 3x">',
				'<img src="data:image/gif;base64,R0lGOD">',
				'<svg><use href="#icon"></use></svg>',
				'<p style="--sl-icon-size: 1.333em; background: url(/img/c.png)">text</p>',
			].join(''),
		),
		'guides/a/index.html': page('<link rel="stylesheet" href="../../_astro/index.css">'),
		'_astro/index.css': '@import "./reset.css";@import url(/_astro/more.css);.c{background:url(../img/d.png)}.d{mask:url(data:image/svg+xml;base64,PHN2Zz4=)}',
		'_astro/print.css': '/* url(https://example.com/in-a-comment.png) */ .e{color:red}',
		'pagefind/pagefind-ui.css': '.f{background:url(https://goiabada.dev/pagefind/x.svg)}',
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.deepEqual(assertNoOffSiteLoads({ distDir: dist, site }), { pages: 2, stylesheets: 3 });
});

test('each kind of load from another site in a page fails the build, naming the page, what loads it and the URL', (t) => {
	const dist = builtSite({
		'index.html': page(
			[
				'<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYZXDTHNB1"></script>',
				'<script type="module" src="//cdn.example.com/a.js"></script>',
				'<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">',
				'<link rel="preload" as="font" href="https://fonts.example/a.woff2">',
				'<link rel="modulepreload" href="https://cdn.example/b.js">',
				'<link rel="prefetch" href="https://cdn.example/c.js">',
				'<link rel="preconnect" href="https://fonts.gstatic.com">',
				'<link rel="dns-prefetch" href="https://www.google-analytics.com">',
				'<link rel="icon" href="https://cdn.example/favicon.svg">',
				'<link rel="apple-touch-icon" href="https://cdn.example/touch.png">',
				'<link rel="manifest" href="https://cdn.example/site.webmanifest">',
				'<link rel="prerender" href="https://other.example/next/">',
				'<link rel="preload" as="image" href="/img/hero.png" imagesrcset="https://cdn.example/hero-2x.png 2x">',
				'<style>.a{background:url("https://cdn.example/bg.png")}@import url(https://cdn.example/x.css);@import "https://cdn.example/y.css";</style>',
			].join(''),
			[
				'<img src="https://cdn.example/a.png">',
				'<img src="/img/b.png" srcset="/img/b.png 1x, https://cdn.example/b-2x.png 2x">',
				'<picture><source srcset="https://cdn.example/c.webp" type="image/webp"><img src="/img/c.png"></picture>',
				'<iframe src="https://www.youtube.com/embed/x"></iframe>',
				'<video src="https://cdn.example/v.mp4" poster="https://cdn.example/v.jpg"><track src="https://cdn.example/v.vtt"></video>',
				'<audio src="https://cdn.example/a.mp3"></audio>',
				'<object data="https://cdn.example/o.svg"></object>',
				'<embed src="https://cdn.example/e.swf">',
				'<svg><image href="https://cdn.example/s.png"></image></svg>',
				'<p style="background: url(\'https://cdn.example/p.png\')">text</p>',
			].join(''),
		),
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertNoOffSiteLoads({ distDir: dist, site }), {
		message: [
			'28 load(s) from another site in the built pages and stylesheets; the site must serve everything it loads:',
			'  index.html: script src https://www.googletagmanager.com/gtag/js?id=G-CYZXDTHNB1',
			'  index.html: script src //cdn.example.com/a.js',
			'  index.html: link rel="stylesheet" https://fonts.googleapis.com/css2?family=Inter',
			'  index.html: link rel="preload" https://fonts.example/a.woff2',
			'  index.html: link rel="modulepreload" https://cdn.example/b.js',
			'  index.html: link rel="prefetch" https://cdn.example/c.js',
			'  index.html: link rel="preconnect" https://fonts.gstatic.com',
			'  index.html: link rel="dns-prefetch" https://www.google-analytics.com',
			'  index.html: link rel="icon" https://cdn.example/favicon.svg',
			'  index.html: link rel="apple-touch-icon" https://cdn.example/touch.png',
			'  index.html: link rel="manifest" https://cdn.example/site.webmanifest',
			'  index.html: link rel="prerender" https://other.example/next/',
			'  index.html: link imagesrcset https://cdn.example/hero-2x.png',
			'  index.html: style url() https://cdn.example/bg.png',
			'  index.html: style @import https://cdn.example/x.css',
			'  index.html: style @import https://cdn.example/y.css',
			'  index.html: img src https://cdn.example/a.png',
			'  index.html: img srcset https://cdn.example/b-2x.png',
			'  index.html: source srcset https://cdn.example/c.webp',
			'  index.html: iframe src https://www.youtube.com/embed/x',
			'  index.html: video src https://cdn.example/v.mp4',
			'  index.html: video poster https://cdn.example/v.jpg',
			'  index.html: track src https://cdn.example/v.vtt',
			'  index.html: audio src https://cdn.example/a.mp3',
			'  index.html: object data https://cdn.example/o.svg',
			'  index.html: embed src https://cdn.example/e.swf',
			'  index.html: image href https://cdn.example/s.png',
			'  index.html: p style url() https://cdn.example/p.png',
		].join('\n'),
	});
});

test('a stylesheet that loads from another site fails the build, naming the stylesheet and the URL', (t) => {
	const dist = builtSite({
		'index.html': page('<link rel="stylesheet" href="/_astro/index.css">'),
		'_astro/index.css': '@import url("https://fonts.googleapis.com/css2?family=Inter");.a{background:url(/img/a.png)}@font-face{src:url(https://fonts.gstatic.com/s/inter.woff2) format("woff2")}',
		'_astro/ec.css': '@import \'https://cdn.example/ec.css\';.b{background-image:url(//cdn.example/b.png)}',
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertNoOffSiteLoads({ distDir: dist, site }), {
		message: [
			'4 load(s) from another site in the built pages and stylesheets; the site must serve everything it loads:',
			'  _astro/ec.css: @import https://cdn.example/ec.css',
			'  _astro/ec.css: url() //cdn.example/b.png',
			'  _astro/index.css: @import https://fonts.googleapis.com/css2?family=Inter',
			'  _astro/index.css: url() https://fonts.gstatic.com/s/inter.woff2',
		].join('\n'),
	});
});

test('a build with no page stops the off-site check rather than pass', (t) => {
	const dist = builtSite({ '_astro/index.css': '.a{color:red}' });
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertNoOffSiteLoads({ distDir: dist, site }), { message: /found no built page in .*: the check reached nothing/ });
});

// What every page carries once the Footer override renders: Starlight's footer,
// the Privacy and Cookie settings links, and the module script that runs the
// prompt, its library holding the element id cc-main.
const footer =
	'<footer class="sl-flex"></footer><nav class="site-links" aria-label="Privacy">' +
	'<a href="/about/privacy/" class="x">Privacy</a>' +
	'<button type="button" class="cookie-settings" data-cc="show-preferencesModal">Cookie settings</button></nav>' +
	'<script type="module" src="/_astro/Footer.astro_astro_type_script_index_0_lang.js"></script>';
const promptScript = 'var e="cc-main";function run(){document.body.append(Object.assign(document.createElement("div"),{id:e}))}run();';

test('pages with the consent prompt and the footer links pass, counted, the prompt found through an import or inline', (t) => {
	const dist = builtSite({
		'index.html': page('', footer),
		'404.html': page('', footer),
		'about/privacy/index.html': page('', footer.replace('href="/about/privacy/"', 'href="https://goiabada.dev/about/privacy/"')),
		'guides/a/index.html': page(
			'',
			footer.replace(
				'<script type="module" src="/_astro/Footer.astro_astro_type_script_index_0_lang.js"></script>',
				'<script type="module" src="../../_astro/entry.js"></script>',
			),
		),
		'guides/b/index.html': page(
			'',
			footer.replace(
				'<script type="module" src="/_astro/Footer.astro_astro_type_script_index_0_lang.js"></script>',
				`<script type="module">${promptScript}</script>`,
			),
		),
		'_astro/Footer.astro_astro_type_script_index_0_lang.js': promptScript,
		'_astro/entry.js': 'import{r as run}from"./cookieconsent.js";run();',
		'_astro/cookieconsent.js': promptScript,
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.equal(assertConsentOnEveryPage({ distDir: dist, site, privacyPage }), 5);
});

test('a page without the prompt, the Privacy link or the Cookie settings link fails the build, naming the page and what it lacks', (t) => {
	const dist = builtSite({
		'index.html': page('', footer),
		'about/privacy/index.html': page('', footer),
		// The 404 page rendered without the Footer override.
		'404.html': page('', '<footer class="sl-flex"></footer>'),
		// A script that is not the prompt, and one the build did not write.
		'guides/a/index.html': page(
			'',
			footer
				.replace('Footer.astro_astro_type_script_index_0_lang.js', 'page.js')
				.replace('</nav>', '</nav><script type="module" src="/_astro/missing.js"></script>'),
		),
		// Links that look like the footer's but are not: the wrong page, the wrong
		// words, and Cookie settings that opens nothing.
		'guides/b/index.html': page(
			'',
			footer
				.replace('href="/about/privacy/" class="x">Privacy', 'href="/about/license/" class="x">Privacy')
				.replace('data-cc="show-preferencesModal">Cookie settings', 'data-cc="show-preferencesModal">Preferences'),
		),
		'guides/c/index.html': page(
			'',
			footer
				.replace('class="x">Privacy', 'class="x">License')
				.replace(' data-cc="show-preferencesModal"', ''),
		),
		'_astro/Footer.astro_astro_type_script_index_0_lang.js': promptScript,
		'_astro/page.js': 'document.title="x";',
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertConsentOnEveryPage({ distDir: dist, site, privacyPage }), {
		message: [
			"8 page problem(s): every page must carry the consent prompt and the footer's Privacy and Cookie settings links:",
			'  404.html: no consent prompt',
			'  404.html: no Privacy link to /about/privacy/',
			'  404.html: no Cookie settings link',
			'  guides/a/index.html: no consent prompt',
			'  guides/b/index.html: no Privacy link to /about/privacy/',
			'  guides/b/index.html: no Cookie settings link',
			'  guides/c/index.html: no Privacy link to /about/privacy/',
			'  guides/c/index.html: no Cookie settings link',
		].join('\n'),
	});
});

test('a Privacy page the build did not publish fails the build', (t) => {
	const dist = builtSite({
		'index.html': page('', footer),
		'_astro/Footer.astro_astro_type_script_index_0_lang.js': promptScript,
	});
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertConsentOnEveryPage({ distDir: dist, site, privacyPage }), {
		message: "the footer's Privacy link, /about/privacy/, names no built page",
	});
});

test('a build with no page stops the consent check rather than pass', (t) => {
	const dist = builtSite({ 'about/privacy/x.txt': 'x' });
	t.after(() => rmSync(dist, { recursive: true, force: true }));

	assert.throws(() => assertConsentOnEveryPage({ distDir: dist, site, privacyPage }), {
		message: /found no built page in .*: the check reached nothing/,
	});
});

// Runs the integration as `astro build` does, on a fixture build, and returns
// what it threw, if anything.
async function runBuildDone(files, options) {
	const root = mkdtempSync(join(tmpdir(), 'privacy-'));
	for (const [path, content] of Object.entries({ 'src/a.go': '"https://goiabada.dev/"\n', ...files })) {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), content);
	}
	const integration = buildChecks({ srcDir: join(root, 'src'), llms: { title: 'Goiabada', summary: 'x' }, ...options });
	try {
		await integration.hooks['astro:config:done']({ config: { site } });
		await integration.hooks['astro:build:done']({ dir: pathToFileURL(join(root, 'dist') + '/'), logger: { info() {} } });
		return undefined;
	} catch (error) {
		return error;
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
}

function starlightPage(title, head, body) {
	return `<!doctype html><html><head><meta property="og:title" content="${title}">${head}</head><body><main><div class="sl-markdown-content"><h1 id="_top">${title}</h1><p>Text.</p></div></main>${body}</body></html>`;
}

test("the build fails on Google's tag in a page's head, as every page had it before the consent prompt", async () => {
	const error = await runBuildDone({
		'dist/index.html': starlightPage('Home', '<script src="https://www.googletagmanager.com/gtag/js?id=G-CYZXDTHNB1"></script>', ''),
	});
	assert.match(error?.message ?? '', /index\.html: script src https:\/\/www\.googletagmanager\.com\/gtag\/js\?id=G-CYZXDTHNB1/);
});

test('the build fails on a page without the consent prompt when it is given the Privacy page, and only then', async () => {
	const files = {
		'dist/index.html': starlightPage('Home', '', footer),
		'dist/about/privacy/index.html': starlightPage('Privacy', '', footer),
		'dist/guides/a/index.html': starlightPage('A guide', '', ''),
		'dist/_astro/Footer.astro_astro_type_script_index_0_lang.js': promptScript,
	};
	const error = await runBuildDone(files, { privacyPage });
	assert.match(error?.message ?? '', /guides\/a\/index\.html: no consent prompt/);
	assert.equal(await runBuildDone(files, {}), undefined);
	assert.equal(
		await runBuildDone({ ...files, 'dist/guides/a/index.html': starlightPage('A guide', '', footer) }, { privacyPage }),
		undefined,
	);
});
