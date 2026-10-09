// The table code plugin, run through Sätteri on Markdown as the site writes it. Each case states
// its expected HTML as a literal.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { markdownToHtml } from 'satteri';

import { tableCodeWords } from './table-code-words.mjs';

function html(markdown) {
	return markdownToHtml(markdown, { hastPlugins: [tableCodeWords] }).html;
}

function cell(markdown) {
	const out = html(`| A |\n|---|\n| ${markdown} |\n`);
	return out.slice(out.indexOf('<td>') + 4, out.indexOf('</td>'));
}

test('a hyphenated word of code in a cell is kept whole', () => {
	assert.equal(cell('`goiabada-authserver`'), '<code><span class="code-word">goiabada-authserver</span></code>');
});

test('the spaces between words are left to break, and only the hyphenated words are wrapped', () => {
	assert.equal(
		cell('`goiabada-authserver migrate to <version>`'),
		'<code><span class="code-word">goiabada-authserver</span> migrate to &lt;version&gt;</code>',
	);
});

test('code in a cell with no hyphen, and text outside code, are untouched', () => {
	assert.equal(cell('a well-known name, `POST /connect/register`'), 'a well-known name, <code>POST /connect/register</code>');
});

test('code nested in a link inside a cell is reached', () => {
	assert.equal(cell('[`--db-password-file`](/x/)'), '<a href="/x/"><code><span class="code-word">--db-password-file</span></code></a>');
});

test('a header cell is reached as a body cell is', () => {
	const out = html('| `goiabada-authserver` |\n|---|\n| x |\n');
	assert.match(out, /<th><code><span class="code-word">goiabada-authserver<\/span><\/code><\/th>/);
});

test('code outside a table, and a code block, are untouched', () => {
	assert.equal(
		html('`goiabada-authserver` in prose\n\n```\ngoiabada-authserver\n```\n'),
		'<p><code>goiabada-authserver</code> in prose</p>\n<pre><code>goiabada-authserver\n</code></pre>\n',
	);
});
