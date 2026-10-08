// The llms files and their sync check, driven on fixture builds: the files the
// integration's astro:build:done hook writes, and the check that fails the build
// when they and the pages disagree. Expected files and messages are literals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

import buildChecks from './build-checks.mjs';
import { assertLlmsFiles, findLlmsProblems } from './llms.mjs';

const site = 'https://goiabada.dev';

// A sidebar as Starlight renders one: two groups, the second holding a nested
// group, and a link off the site.
const sidebar = `<sl-sidebar-pane id="starlight__sidebar"><ul class="top-level">
<li><details open><summary><span class="group-label"><span class="large">Get started</span></span></summary><ul>
<li><a href="/get-started/introduction/"><span>Introduction</span></a></li>
<li><a href="/get-started/quickstart/" aria-current="page"><span>Quickstart</span></a></li>
</ul></details></li>
<li><details open><summary><span class="group-label"><span class="large">Reference</span></span></summary><ul>
<li><a href="/reference/errors/"><span>Errors</span></a></li>
<li><details><summary><span class="group-label"><span class="large">Admin API</span></span></summary><ul>
<li><a href="/reference/admin-api/clients/"><span>Clients</span></a></li>
</ul></details></li>
<li><a href="https://github.com/leodip/goiabada"><span>GitHub</span></a></li>
</ul></details></li>
</ul></sl-sidebar-pane>`;

// A built page as Starlight renders one: the title in og:title and as the h1,
// the description, the sidebar, the content, and the footer with its edit link
// and pagination.
function page({ title, description, body, withSidebar = true }) {
	const meta = description === undefined ? '' : `<meta name="description" content="${description}"/>`;
	return `<!doctype html><html lang="en"><head><title>${title} | Goiabada</title>
<meta property="og:title" content="${title}"/>${meta}</head><body>
${withSidebar ? sidebar : ''}
<main data-pagefind-body><div class="content-panel"><div class="sl-container"><h1 id="_top">${title}</h1></div></div>
<div class="content-panel"><div class="sl-container"><div class="sl-markdown-content">${body}</div>
<footer class="sl-flex"><div class="meta sl-flex"><a href="https://github.com/leodip/goiabada/edit/main/site/x.md" class="sl-flex">Edit page</a></div>
<div class="pagination-links"><a href="/get-started/quickstart/" rel="next"><span>Next<br/><span class="link-title">Quickstart</span></span></a></div></footer>
</div></div></main></body></html>`;
}

function fixture(files) {
	const root = mkdtempSync(join(tmpdir(), 'llms-'));
	for (const [path, content] of Object.entries(files)) {
		const full = join(root, path);
		mkdirSync(dirname(full), { recursive: true });
		writeFileSync(full, content);
	}
	return root;
}

// The four sidebar pages, a page the sidebar does not list, the home page, and
// the 404 page.
const builtPages = {
	'index.html': page({ title: 'Welcome', description: 'The home page.', body: '<p>Welcome home.</p>' }),
	'get-started/introduction/index.html': page({
		title: 'Introduction',
		description: 'What Goiabada is.',
		body: '<p>Goiabada is an authentication server.</p>',
	}),
	'get-started/quickstart/index.html': page({
		title: 'Quickstart',
		description: 'Run it on your machine.',
		body: '<p>Run the setup wizard.</p>',
	}),
	'reference/errors/index.html': page({
		title: 'Errors',
		description: 'The API error codes.',
		body: '<p>Every error code.</p>',
	}),
	'reference/admin-api/clients/index.html': page({
		title: 'Clients',
		description: 'Manage clients.',
		body: '<p>List, create and delete clients.</p>',
	}),
	'reference/orphan/index.html': page({ title: 'Orphan', body: '<p>A page no sidebar lists.</p>' }),
	'404.html': page({ title: 'Page not found', body: '<p>This page may have moved.</p>' }),
};

function builtSite(pages) {
	return fixture(Object.fromEntries(Object.entries(pages).map(([path, html]) => [`site/dist/${path}`, html])));
}

// Runs the integration as `astro build` does, on a fixture build and a source
// tree holding one link, to a page the build has, and returns what it threw, if
// anything.
async function runBuild(root, link = 'https://goiabada.dev/') {
	const logged = [];
	const logger = {
		info: (m) => logged.push(m),
		warn: (m) => logged.push(m),
		error: (m) => logged.push(m),
	};
	mkdirSync(join(root, 'src'), { recursive: true });
	writeFileSync(join(root, 'src/a.go'), `"${link}"\n`);
	const integration = buildChecks({
		srcDir: join(root, 'src'),
		llms: { title: 'Goiabada', summary: 'An open-source OAuth2 and OpenID Connect server.' },
	});
	try {
		await integration.hooks['astro:config:done']({ config: { site } });
		await integration.hooks['astro:build:done']({ dir: pathToFileURL(join(root, 'site/dist') + '/'), logger });
		return { error: undefined, logged };
	} catch (error) {
		return { error, logged };
	}
}

function read(root, file) {
	return readFileSync(join(root, 'site/dist', file), 'utf8');
}

test('llms.txt names the project, points to llms-full.txt, and lists every page in sidebar order', async (t) => {
	const root = builtSite(builtPages);
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error, logged } = await runBuild(root);

	assert.equal(error, undefined);
	assert.equal(
		read(root, 'llms.txt'),
		`# Goiabada

> An open-source OAuth2 and OpenID Connect server.

Every page below, in full and as Markdown, is in one file: [llms-full.txt](https://goiabada.dev/llms-full.txt)

## Get started

- [Introduction](https://goiabada.dev/get-started/introduction/): What Goiabada is.
- [Quickstart](https://goiabada.dev/get-started/quickstart/): Run it on your machine.

## Reference

- [Errors](https://goiabada.dev/reference/errors/): The API error codes.
- [Clients](https://goiabada.dev/reference/admin-api/clients/): Manage clients.

## Other pages

- [Welcome](https://goiabada.dev/): The home page.
- [Orphan](https://goiabada.dev/reference/orphan/): A page no sidebar lists.
`,
	);
	assert.ok(logged.includes('llms.txt and llms-full.txt hold all 6 pages'), logged.join('\n'));
});

test('llms-full.txt holds every page, headed by its title and URL, in the same order', async (t) => {
	const root = builtSite(builtPages);
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuild(root);

	assert.equal(error, undefined);
	assert.equal(
		read(root, 'llms-full.txt'),
		`# Introduction

Source: https://goiabada.dev/get-started/introduction/

Goiabada is an authentication server.

# Quickstart

Source: https://goiabada.dev/get-started/quickstart/

Run the setup wizard.

# Errors

Source: https://goiabada.dev/reference/errors/

Every error code.

# Clients

Source: https://goiabada.dev/reference/admin-api/clients/

List, create and delete clients.

# Welcome

Source: https://goiabada.dev/

Welcome home.

# Orphan

Source: https://goiabada.dev/reference/orphan/

A page no sidebar lists.
`,
	);
});

// An operation page as starlight-openapi renders one: no description meta tag,
// the method and path, a URL in a popover, the code samples, the operation's
// description, and its parameters, each with a description of its own.
const operationPage = page({
	title: 'Search users',
	withSidebar: false,
	body: `<div class="not-content sl-openapi-operation-description"><div class="sl-openapi-operation-description-header"><button aria-label="Toggle operation URLs" class="sl-openapi-operation-description-button"></button><div class="sl-openapi-operation-method"><div class="sl-openapi-operation-method-badge get">GET</div><div class="sl-openapi-operation-method-path">/api/v1/admin/users/search</div></div></div>
<div class="sl-openapi-snippets"><div class="sl-openapi-snippet" data-openapi-snippet-id="shell:curl"><div class="expressive-code"><figure class="frame not-content"><figcaption class="header"></figcaption><pre data-language="sh"><code><div class="ec-line"><div class="code"><span>curl --request GET</span></div></div></code></pre></figure></div></div></div></div>
<div id="sl-openapi-operation-description-popover" popover><ul class="sl-openapi-operation-description-urls"><li class="sl-openapi-operation-url"><label>Auth server base URL<input readonly type="text" value="{baseUrl}/api/v1/admin/users/search"></label></li></ul></div>
<div class="sl-openapi-markdown"><p>Search for users with pagination. Each returned user can be annotated against one group (e.g. admins) or one permission.</p>
<p>Sending both annotations is refused.</p></div>
<section class="sl-openapi-section"><div class="sl-heading-wrapper level-h2"><h2 id="parameters">Parameters</h2></div><div class="sl-openapi-markdown"><p>Search term (matches email, username, name)</p></div></section>`,
});

test('a generated API page with no description meta tag is listed with the first sentence it renders', async (t) => {
	const root = builtSite({ 'reference/api/admin/operations/searchusers/index.html': operationPage });
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuild(root, 'https://goiabada.dev/reference/api/admin/operations/searchusers/');

	assert.equal(error, undefined);
	assert.match(
		read(root, 'llms.txt'),
		/\n- \[Search users\]\(https:\/\/goiabada\.dev\/reference\/api\/admin\/operations\/searchusers\/\): Search for users with pagination\.\n/,
	);
});

// One page holding what Starlight renders from Markdown and its components.
const richPage = page({
	title: 'A guide',
	description: 'Every component.',
	withSidebar: false,
	body: `<p>Read <a href="/concepts/clients/#public">the clients page</a>, the <a href="#client-ip">next section</a> and <code dir="auto">client_id</code>.</p>
<div class="sl-heading-wrapper level-h2"><h2 id="client-ip">Client IP</h2><a class="sl-anchor-link" href="#client-ip"><span aria-hidden="true" class="sl-anchor-icon"><svg width="16" height="16"><path d="m12"></path></svg></span><span class="sr-only" data-pagefind-ignore>Section titled “Client IP”</span></a></div>
<div class="expressive-code"><figure class="frame is-terminal not-content"><figcaption class="header"><span class="title"></span><span class="sr-only">Terminal window</span></figcaption><pre data-language="bash"><code><div class="ec-line"><div class="code"><span style="--0:#82AAFF">docker</span><span style="--0:#d6deeb"> compose up -d</span></div></div><div class="ec-line"><div class="code"><span class="indent">  </span><span>curl http://localhost:9091</span></div></div></code></pre><div class="copy"><div aria-live="polite"></div><button title="Copy to clipboard" data-copied="Copied!" data-code="docker compose up -d\u007f  curl http://localhost:9091"><div></div></button></div></figure></div>
<div class="expressive-code"><figure class="frame has-title not-content"><figcaption class="header"><span class="title">docker-compose.yml</span></figcaption><pre data-language="yaml"><code><div class="ec-line"><div class="code"><span>services:</span></div></div></code></pre><div class="copy"><button title="Copy to clipboard" data-code="services:"><div></div></button></div></figure></div>
<starlight-tabs><div class="tablist-wrapper not-content"><ul role="tablist"><li role="presentation" class="tab"><a role="tab" href="#tab-panel-0-0" id="tab-0-0" aria-selected="true" tabindex="0">Linux</a></li><li role="presentation" class="tab"><a role="tab" href="#tab-panel-0-1" id="tab-0-1" aria-selected="false" tabindex="-1">Windows</a></li></ul></div><div id="tab-panel-0-0" aria-labelledby="tab-0-0" role="tabpanel"><p>Run it on Linux.</p></div><div id="tab-panel-0-1" aria-labelledby="tab-0-1" role="tabpanel" hidden><p>Run it on Windows.</p></div></starlight-tabs>
<aside aria-label="Caution" class="starlight-aside starlight-aside--caution"><p class="starlight-aside__title" aria-hidden="true"><svg aria-hidden="true" class="starlight-aside__icon"><path d="M1"/></svg>Caution</p><div class="starlight-aside__content"><p>Not for production.</p></div></aside>
<table><thead><tr><th>Variable</th><th>Default</th></tr></thead><tbody><tr><td><code dir="auto">GOIABADA_PORT</code></td><td>9090 | 9091</td></tr></tbody></table>
<div class="sl-link-card"><span class="sl-flex stack"><a href="/concepts/clients/"><span class="title">Clients</span></a><span class="description">Applications that request access.</span></span><svg aria-hidden="true" class="icon"><path d="M17"/></svg></div>
<p><img src="/_astro/logo.png" alt="The logo"> Escapes: 1 * 2 and _b_, but not snake_case.</p>`,
});

test('a page is converted to Markdown: links absolute, code as fences, tabs labeled, controls left out', async (t) => {
	const root = builtSite({ 'guides/a-guide/index.html': richPage });
	t.after(() => rmSync(root, { recursive: true, force: true }));

	const { error } = await runBuild(root, 'https://goiabada.dev/guides/a-guide/');

	assert.equal(error, undefined);
	assert.equal(
		read(root, 'llms-full.txt'),
		`# A guide

Source: https://goiabada.dev/guides/a-guide/

Read [the clients page](https://goiabada.dev/concepts/clients/#public), the [next section](https://goiabada.dev/guides/a-guide/#client-ip) and \`client_id\`.

## Client IP

\`\`\`bash
docker compose up -d
  curl http://localhost:9091
\`\`\`

*docker-compose.yml*

\`\`\`yaml
services:
\`\`\`

**Linux**

Run it on Linux.

**Windows**

Run it on Windows.

> **Caution**
>
> Not for production.

| Variable | Default |
| - | - |
| \`GOIABADA_PORT\` | 9090 \\| 9091 |

[Clients](https://goiabada.dev/concepts/clients/): Applications that request access.

![The logo](https://goiabada.dev/_astro/logo.png) Escapes: 1 \\* 2 and \\_b\\_, but not snake_case.
`,
	);
});

// A build of three pages whose llms files are written by hand, so each case can
// break them the way it needs.
const checkedPages = {
	'index.html': page({ title: 'Welcome', description: 'The home page.', body: '<p>Welcome home.</p>' }),
	'guides/proxy/index.html': page({
		title: 'Proxy',
		description: 'Run behind a proxy.',
		body: `<p>Set the trusted proxy header.</p>
<div class="expressive-code"><figure class="frame"><figcaption class="header"></figcaption><pre data-language="bash"><code><div class="ec-line"><div class="code"><span>export GOIABADA_TRUST_PROXY_HEADERS=true</span></div></div></code></pre></figure></div>
<table><thead><tr><th>Header</th><th>Read</th></tr></thead><tbody><tr><td>X-Forwarded-For</td><td>When trusted</td></tr></tbody></table>`,
	}),
	'reference/errors/index.html': page({ title: 'Errors', body: '<p>Every error code.</p>' }),
	'404.html': page({ title: 'Page not found', body: '<p>This page may have moved.</p>' }),
};

const goodIndex = `# Goiabada

> An authentication server.

Everything: [llms-full.txt](https://goiabada.dev/llms-full.txt)

## Pages

- [Welcome](https://goiabada.dev/): The home page.
- [Proxy](https://goiabada.dev/guides/proxy/): Run behind a proxy.
- [Errors](https://goiabada.dev/reference/errors/): Every error code.
`;

const welcomeEntry = `# Welcome

Source: https://goiabada.dev/

Welcome home.
`;

const proxyEntry = `# Proxy

Source: https://goiabada.dev/guides/proxy/

Set the trusted proxy header.

\`\`\`bash
export GOIABADA_TRUST_PROXY_HEADERS=true
\`\`\`

| Header | Read |
| - | - |
| X-Forwarded-For | When trusted |
`;

const errorsEntry = `# Errors

Source: https://goiabada.dev/reference/errors/

Every error code.
`;

const goodFull = [welcomeEntry, proxyEntry, errorsEntry].join('\n');

function checkedSite({ index = goodIndex, full = goodFull, pages = checkedPages } = {}) {
	const files = { ...pages };
	if (index !== null) files['llms.txt'] = index;
	if (full !== null) files['llms-full.txt'] = full;
	return builtSite(files);
}

function problems(root) {
	return findLlmsProblems({ distDir: join(root, 'site/dist'), site }).sort();
}

test('llms files that match the pages pass', (t) => {
	const root = checkedSite();
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), []);
	assert.doesNotThrow(() => assertLlmsFiles({ distDir: join(root, 'site/dist'), site }));
});

test('a page missing from either file is a finding', (t) => {
	const root = checkedSite({
		index: goodIndex.replace('- [Proxy](https://goiabada.dev/guides/proxy/): Run behind a proxy.\n', ''),
		full: [welcomeEntry, proxyEntry].join('\n'),
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), [
		'llms-full.txt has no entry for the page https://goiabada.dev/reference/errors/',
		'llms.txt has no entry for the page https://goiabada.dev/guides/proxy/',
	]);
});

test('an entry naming no built page is a finding, the 404 page included', (t) => {
	const root = checkedSite({
		index: goodIndex + '- [Gone](https://goiabada.dev/guides/gone/): A page that moved.\n',
		full:
			goodFull +
			'\n# Page not found\n\nSource: https://goiabada.dev/404.html\n\nThis page may have moved.\n' +
			'\n# Elsewhere\n\nSource: https://example.com/guides/proxy/\n\nSet the trusted proxy header.\n',
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), [
		'llms-full.txt: the entry https://example.com/guides/proxy/ names no built page',
		'llms-full.txt: the entry https://goiabada.dev/404.html names no built page',
		'llms.txt: the entry https://goiabada.dev/guides/gone/ names no built page',
	]);
});

test('an llms.txt entry without its page title or description is a finding', (t) => {
	const root = checkedSite({
		index: goodIndex
			.replace('[Proxy](https://goiabada.dev/guides/proxy/): Run behind a proxy.', '[Proxies](https://goiabada.dev/guides/proxy/): Run behind a proxy.')
			.replace('[Welcome](https://goiabada.dev/): The home page.', '[Welcome](https://goiabada.dev/)'),
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), [
		'llms.txt: the entry https://goiabada.dev/ lacks the description its page renders: "The home page."',
		'llms.txt: the entry https://goiabada.dev/guides/proxy/ lacks the title its page renders: "Proxy"',
	]);
});

test('an llms.txt entry without the description of a page that has no description meta tag is a finding', (t) => {
	const root = checkedSite({
		index: goodIndex.replace('[Errors](https://goiabada.dev/reference/errors/): Every error code.', '[Errors](https://goiabada.dev/reference/errors/)'),
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), [
		'llms.txt: the entry https://goiabada.dev/reference/errors/ lacks the description its page renders: "Every error code."',
	]);
});

test('a page that renders no description is a finding', (t) => {
	const root = checkedSite({
		pages: {
			...checkedPages,
			'reference/errors/index.html': page({ title: 'Errors', body: '<ul><li>INVALID_REQUEST</li></ul>' }),
		},
		index: goodIndex.replace('[Errors](https://goiabada.dev/reference/errors/): Every error code.', '[Errors](https://goiabada.dev/reference/errors/)'),
		full: [welcomeEntry, proxyEntry, errorsEntry.replace('Every error code.', '- INVALID_REQUEST')].join('\n'),
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), [
		'llms.txt: the page https://goiabada.dev/reference/errors/ renders no description, neither a description meta tag nor a paragraph',
	]);
});

test('an llms-full.txt entry missing text its page renders is a finding', (t) => {
	const root = checkedSite({
		full: [
			welcomeEntry.replace('# Welcome', '# Home'),
			proxyEntry
				.replace('Set the trusted proxy header.\n\n', '')
				.replace('export GOIABADA_TRUST_PROXY_HEADERS=true', 'export GOIABADA_TRUST_PROXY_HEADERS=false')
				.replace('| X-Forwarded-For | When trusted |', '| X-Forwarded-For | |'),
			errorsEntry,
		].join('\n'),
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), [
		'llms-full.txt: the entry https://goiabada.dev/ lacks the title its page renders: "Welcome"',
		'llms-full.txt: the entry https://goiabada.dev/guides/proxy/ lacks text its page renders: "Set the trusted proxy header."',
		'llms-full.txt: the entry https://goiabada.dev/guides/proxy/ lacks text its page renders: "When trusted"',
		'llms-full.txt: the entry https://goiabada.dev/guides/proxy/ lacks text its page renders: "export GOIABADA_TRUST_PROXY_HEADERS=true"',
	]);
});

test('text another entry holds does not stand in for an entry that lacks it', (t) => {
	const root = checkedSite({
		full: [
			welcomeEntry.replace('Welcome home.', 'Every error code.'),
			proxyEntry,
			errorsEntry.replace('Every error code.', 'Welcome home.'),
		].join('\n'),
	});
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.deepEqual(problems(root), [
		'llms-full.txt: the entry https://goiabada.dev/ lacks text its page renders: "Welcome home."',
		'llms-full.txt: the entry https://goiabada.dev/reference/errors/ lacks text its page renders: "Every error code."',
	]);
});

test('the check fails the build naming every finding', (t) => {
	const root = checkedSite({ full: [welcomeEntry, proxyEntry].join('\n') });
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.throws(() => assertLlmsFiles({ distDir: join(root, 'site/dist'), site }), {
		message:
			'the llms files and the pages disagree in 1 place(s):\n' +
			'  llms-full.txt has no entry for the page https://goiabada.dev/reference/errors/',
	});
});

test('a build with no page stops the check rather than pass', (t) => {
	const root = checkedSite({ pages: { '404.html': checkedPages['404.html'] }, index: '# Goiabada\n', full: '' });
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.throws(() => assertLlmsFiles({ distDir: join(root, 'site/dist'), site }), {
		message: /found no built page under .*dist: the llms check reached nothing/,
	});
});

test('a missing llms file stops the check rather than pass', (t) => {
	const root = checkedSite({ full: null });
	t.after(() => rmSync(root, { recursive: true, force: true }));

	assert.throws(() => assertLlmsFiles({ distDir: join(root, 'site/dist'), site }), {
		message: /cannot read .*llms-full\.txt/,
	});
});

test('a build without the site URL stops rather than write relative links', async (t) => {
	const root = builtSite(builtPages);
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const integration = buildChecks({ srcDir: join(root, 'src'), llms: { title: 'Goiabada', summary: 'x' } });

	await integration.hooks['astro:config:done']({ config: {} });
	await assert.rejects(
		async () => integration.hooks['astro:build:done']({ dir: pathToFileURL(join(root, 'site/dist') + '/'), logger: { info() {} } }),
		{ message: /the llms files need the site's URL: set site in astro\.config\.mjs/ },
	);
});
