// The consent setup: the prompt's configuration and the loader of Google's tag it
// holds back until Accept. The docs build has no browser, so the rules the prompt
// enforces are pinned here, on the configuration the Footer override hands to
// vanilla-cookieconsent. The DOM the loader writes to is a small fake, the one
// boundary these tests cross. Expected values are literals from the agreement.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { consentConfig } from './config.mjs';

// The window the loader writes to: a head that records what is appended to it, and
// the dataLayer Google's tag reads its commands from.
function fakeWindow() {
	const appended = [];
	const document = {
		createElement: (tagName) => ({ tagName: tagName.toUpperCase() }),
		head: { append: (...nodes) => appended.push(...nodes) },
	};
	return { window: { document }, appended };
}

// Every gtag command queued in the dataLayer, each as a plain array.
function commands(window) {
	return (window.dataLayer ?? []).map((entry) => Array.from(entry));
}

// Every callback anywhere in the configuration, with its path, so a test can call
// all of them but the Analytics accept callback.
function callbacks(value, path = []) {
	if (typeof value === 'function') return [{ path: path.join('.'), fn: value }];
	if (value === null || typeof value !== 'object') return [];
	return Object.entries(value).flatMap(([key, child]) => callbacks(child, [...path, key]));
}

const acceptPath = 'categories.analytics.services.googleAnalytics.onAccept';

test('the choice is kept in localStorage for 182 days', () => {
	const { window } = fakeWindow();
	const { cookie } = consentConfig(window);
	assert.equal(cookie.useLocalStorage, true);
	assert.equal(cookie.expiresAfterDays, 182);
});

test('a browser sending Global Privacy Control is treated as having refused', () => {
	const { window } = fakeWindow();
	const config = consentConfig(window);
	assert.equal(config.respectGpc, true);
	assert.notEqual(config.mode, 'opt-out');
	assert.notEqual(config.categories.analytics.enabled, true);
});

test('Analytics is the one category, off until the visitor accepts it', () => {
	const { window } = fakeWindow();
	const { categories } = consentConfig(window);
	assert.deepEqual(Object.keys(categories), ['analytics']);
	assert.notEqual(categories.analytics.enabled, true);
	assert.notEqual(categories.analytics.readOnly, true);
});

test('withdrawing clears every _ga cookie and reloads the page', () => {
	const { window } = fakeWindow();
	const config = consentConfig(window);
	assert.notEqual(config.autoClearCookies, false);
	const { autoClear } = config.categories.analytics;
	assert.equal(autoClear.reloadPage, true);
	const cleared = (name) => autoClear.cookies.some(({ name: pattern }) =>
		pattern instanceof RegExp ? pattern.test(name) : pattern === name);
	for (const name of ['_ga', '_ga_CYZXDTHNB1', '_gat', '_gid']) {
		assert.ok(cleared(name), `${name} is not cleared`);
	}
	for (const name of ['session', 'cc_cookie', 'my_ga']) {
		assert.ok(!cleared(name), `${name} is cleared`);
	}
});

test('building the configuration loads nothing from Google', () => {
	const { window, appended } = fakeWindow();
	consentConfig(window);
	assert.deepEqual(appended, []);
	assert.deepEqual(commands(window), []);
});

test('no callback but the Analytics accept callback loads Google\'s tag', () => {
	const { window, appended } = fakeWindow();
	const config = consentConfig(window);
	const others = callbacks(config).filter(({ path }) => path !== acceptPath);
	for (const { fn } of others) fn({ cookie: { categories: ['analytics'] }, changedCategories: ['analytics'], modalName: 'consentModal' });
	assert.deepEqual(appended, []);
	assert.deepEqual(commands(window), []);
});

test('accepting Analytics loads Google\'s tag once, with the minimum settings', () => {
	const { window, appended } = fakeWindow();
	const config = consentConfig(window);
	const accept = config.categories.analytics.services.googleAnalytics.onAccept;
	accept();
	accept();

	assert.equal(appended.length, 1);
	assert.equal(appended[0].tagName, 'SCRIPT');
	assert.equal(appended[0].src, 'https://www.googletagmanager.com/gtag/js?id=G-CYZXDTHNB1');
	assert.equal(appended[0].async, true);

	const queued = commands(window);
	assert.equal(queued.length, 2);
	assert.equal(queued[0][0], 'js');
	assert.ok(queued[0][1] instanceof Date);
	assert.deepEqual(queued[1], ['config', 'G-CYZXDTHNB1', {
		allow_google_signals: false,
		allow_ad_personalization_signals: false,
		// 390 days: thirteen months whichever months they span is at least 393. No
		// cookie_update: Google's default renews the cookies on each page view, which
		// the Privacy page and Cookie settings state.
		cookie_expires: 33696000,
	}]);
});

test('the prompt offers Accept and Reject and links the Privacy page', () => {
	const { window } = fakeWindow();
	const config = consentConfig(window);
	const prompt = config.language.translations[config.language.default].consentModal;
	assert.equal(prompt.acceptAllBtn, 'Accept');
	assert.equal(prompt.acceptNecessaryBtn, 'Reject');
	assert.match(prompt.description + (prompt.footer ?? ''), /href="\/about\/privacy\/"/);
	assert.notEqual(config.disablePageInteraction, true);
	assert.notEqual(config.guiOptions?.consentModal?.equalWeightButtons, false);
});
