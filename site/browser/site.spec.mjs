// The docs site in a real browser, against a running docs image (checks/docs-browser.sh): its pages
// work under their Content-Security-Policy, and the consent prompt holds Google Analytics back until
// the visitor accepts. Every test fails on a policy violation (fixtures.mjs).
import { expect, googleHitUrl, googleTagUrl, isGoogle, settle, test } from './fixtures.mjs';

// Pages that between them hold what the policy must let run: Starlight's own scripts, Expressive
// Code's colours and copy buttons, tabs, the generated API reference, the image zoom, and the
// consent prompt on each. Each is searched and switched to both themes.
const pages = [
	{
		name: 'the home page',
		path: '/',
		async exercise(page) {
			const zoomed = page.locator('dialog.image-zoom');
			await page.getByRole('button', { name: /^Enlarge: The sign-in page/ }).click();
			await expect(zoomed).toBeVisible();
			await expect.poll(() => zoomed.locator('img').evaluate((image) => image.complete && image.naturalWidth)).toBeGreaterThan(0);
			await page.keyboard.press('Escape');
			await expect(zoomed).toBeHidden();
		},
	},
	{
		name: 'a page with code blocks and tabs',
		path: '/deploy/database/',
		async exercise(page) {
			const tabs = page.locator('starlight-tabs').first().getByRole('tab');
			const second = tabs.nth(1);
			await second.click();
			await expect(second).toHaveAttribute('aria-selected', 'true');
			await expect(page.locator('.expressive-code').first()).toBeVisible();
		},
	},
	{
		name: 'an Admin API operation page',
		path: '/reference/api/admin/operations/getuser/',
		async exercise(page) {
			await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
		},
	},
	{
		name: 'the Privacy page',
		path: '/about/privacy/',
		async exercise(page) {
			await expect(page.getByRole('heading', { level: 1, name: 'Privacy' })).toBeVisible();
		},
	},
];

for (const { name, path, exercise } of pages) {
	test(`${name} works under its Content-Security-Policy`, async ({ page }) => {
		const response = await page.goto(path);
		expect(response.status(), `${path} is a built page`).toBe(200);
		await expect(page.locator('head > meta[http-equiv="Content-Security-Policy"]')).toHaveCount(1);
		await expect(consentPrompt(page)).toBeVisible();

		await exercise(page);

		// Pagefind's search, which runs WebAssembly.
		await page.getByRole('button', { name: 'Search' }).click();
		const search = page.locator('#starlight__search');
		await search.locator('input').fill('database');
		await expect(search.locator('.pagefind-ui__result').first()).toBeVisible();
		await page.keyboard.press('Escape');

		const theme = page.getByRole('combobox', { name: 'Select theme' });
		for (const choice of ['light', 'dark']) {
			await theme.selectOption(choice);
			await expect(page.locator('html')).toHaveAttribute('data-theme', choice);
		}
	});
}

test('the policy refuses an inline script the build did not produce', async ({ page, cspViolations }) => {
	await page.goto('/');
	await page.evaluate(() => {
		const script = document.createElement('script');
		script.textContent = 'window.injected = true';
		document.head.append(script);
	});
	await settle([page]);
	expect(await page.evaluate(() => window.injected)).toBeUndefined();
	expect(cspViolations).toEqual([expect.stringMatching(/: script-src-elem blocked inline/)]);
	// The refusal this test caused, so the watcher's end-of-test check passes.
	cspViolations.length = 0;
});

test('nothing reaches Google before Accept, its tag loads after Accept, and nothing after withdrawal', async ({
	page,
	context,
	offSite,
}) => {
	await page.goto('/');
	await expect(consentPrompt(page)).toBeVisible();
	await page.waitForLoadState('networkidle');
	expect(offSite, 'requests to other sites before any choice').toEqual([]);
	expect(await context.cookies(), 'cookies before any choice').toEqual([]);

	let tag = page.waitForRequest(googleTagUrl);
	await consentPrompt(page).getByRole('button', { name: 'Accept' }).click();
	await tag;
	await expect.poll(() => offSite.some((url) => googleHitUrl.test(url)), 'a hit after Accept').toBe(true);
	await expect.poll(() => cookieNames(context)).toEqual(['_ga', '_ga_CYZXDTHNB1']);
	await expect(consentPrompt(page)).toBeHidden();

	// The choice stands on the next page, with no prompt.
	tag = page.waitForRequest(googleTagUrl);
	await page.goto('/deploy/database/');
	await tag;
	await expect(consentPrompt(page)).toBeHidden();
	expect(offSite.filter((url) => !isGoogle(url)), 'requests to other sites than Google').toEqual([]);

	// Withdrawing from Cookie settings deletes Analytics' cookies and reloads the page.
	await cookieSettings(page).click();
	const settings = page.getByRole('dialog', { name: 'Cookie settings' });
	await expect(settings).toBeVisible();
	const reloaded = page.waitForEvent('load');
	offSite.length = 0;
	await settings.getByRole('button', { name: 'Reject' }).click();
	await reloaded;
	await page.waitForLoadState('networkidle');
	expect(offSite, 'requests to other sites after withdrawal').toEqual([]);
	expect(await cookieNames(context), 'cookies after withdrawal').toEqual([]);

	await page.goto('/about/privacy/');
	await page.waitForLoadState('networkidle');
	await expect(consentPrompt(page)).toBeHidden();
	expect(offSite, 'requests to other sites on the next page').toEqual([]);
});

test('Reject sends nothing to Google, on this page or the next', async ({ page, context, offSite }) => {
	await page.goto('/');
	await expect(consentPrompt(page)).toBeVisible();
	await consentPrompt(page).getByRole('button', { name: 'Reject' }).click();
	await expect(consentPrompt(page)).toBeHidden();
	await page.goto('/deploy/database/');
	await page.waitForLoadState('networkidle');
	await expect(consentPrompt(page)).toBeHidden();
	expect(offSite).toEqual([]);
	expect(await context.cookies()).toEqual([]);
});

test('a browser sending Global Privacy Control gets no prompt and nothing from Google', async ({
	page,
	context,
	offSite,
}) => {
	await context.addInitScript(() => {
		Object.defineProperty(Navigator.prototype, 'globalPrivacyControl', { get: () => true });
	});
	await page.goto('/');
	await page.waitForLoadState('networkidle');
	await expect(consentPrompt(page)).toBeHidden();
	expect(offSite).toEqual([]);
	expect(await context.cookies()).toEqual([]);

	// Cookie settings still opens, so the visitor can opt in.
	await cookieSettings(page).click();
	await expect(page.getByRole('dialog', { name: 'Cookie settings' })).toBeVisible();
});

for (const { width, height } of [
	{ width: 1280, height: 900 },
	{ width: 375, height: 667 },
]) {
	test(`Accept and Reject sit side by side, alike, ${width} pixels wide`, async ({ page }) => {
		await page.setViewportSize({ width, height });
		await page.goto('/');
		const prompt = consentPrompt(page);
		await expect(prompt).toBeVisible();
		// Measured once the prompt has finished sliding in, both at the same moment.
		await page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished)));
		const boxes = await page.evaluate(() =>
			['Accept', 'Reject'].map((name) => {
				const button = [...document.querySelectorAll('#cc-main .cm button')].find((b) => b.textContent.trim() === name);
				const { x, y, width, height } = button.getBoundingClientRect();
				return { x, y, width, height };
			}),
		);
		const [accept, reject] = boxes;
		await expect(prompt.getByRole('button', { name: 'Accept' })).toBeVisible();
		await expect(prompt.getByRole('button', { name: 'Reject' })).toBeVisible();

		expect(Math.abs(accept.y - reject.y), 'Accept and Reject on one line').toBeLessThan(1);
		const [left, right] = accept.x < reject.x ? [accept, reject] : [reject, accept];
		expect(left.x + left.width, 'Accept and Reject apart').toBeLessThanOrEqual(right.x);
		expect(Math.abs(accept.width - reject.width), 'Accept and Reject the same width').toBeLessThan(1);
		expect(accept.height).toBe(reject.height);
		for (const box of [accept, reject]) {
			expect(box.x).toBeGreaterThanOrEqual(0);
			expect(box.x + box.width).toBeLessThanOrEqual(width);
		}
	});
}

// WCAG 2.2's 1.4.3: text at least 4.5:1 against its background, which the prompt's and Cookie
// settings' buttons meet in both themes, as they are and under the pointer.
for (const theme of ['light', 'dark']) {
	test(`the consent buttons' text has at least 4.5:1 contrast in the ${theme} theme`, async ({ page }) => {
		await page.goto('/');
		await page.getByRole('combobox', { name: 'Select theme' }).selectOption(theme);
		await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

		const prompt = consentPrompt(page);
		await expect(prompt).toBeVisible();
		for (const name of ['Accept', 'Reject']) await expectContrast(page, prompt.getByRole('button', { name }), `prompt's ${name}`);

		await cookieSettings(page).click();
		const settings = page.getByRole('dialog', { name: 'Cookie settings' });
		await expect(settings).toBeVisible();
		for (const name of ['Accept', 'Reject', 'Save']) {
			await expectContrast(page, settings.getByRole('button', { name, exact: true }), `Cookie settings' ${name}`);
		}
	});
}

async function expectContrast(page, button, what) {
	// Its colours change at once under the pointer, not through a transition half-way.
	await button.evaluate((element) => {
		element.style.transition = 'none';
	});
	await page.mouse.move(0, 0);
	expect(contrast(await colours(button)), `${what}'s contrast`).toBeGreaterThanOrEqual(4.5);
	await button.hover();
	expect(contrast(await colours(button)), `${what}'s contrast under the pointer`).toBeGreaterThanOrEqual(4.5);
}

// The button's text colour and the first opaque background behind it, as [r, g, b] each.
function colours(button) {
	return button.evaluate((element) => {
		const rgb = (value) => {
			const [r, g, b, a = 1] = value.match(/[\d.]+/g).map(Number);
			return { rgb: [r, g, b], a };
		};
		let node = element;
		let background = rgb(getComputedStyle(node).backgroundColor);
		while (background.a === 0 && node.parentElement) {
			node = node.parentElement;
			background = rgb(getComputedStyle(node).backgroundColor);
		}
		if (background.a !== 1) throw new Error(`a translucent background behind the button: ${getComputedStyle(node).backgroundColor}`);
		return { text: rgb(getComputedStyle(element).color).rgb, background: background.rgb };
	});
}

// WCAG's contrast ratio of two sRGB colours, from their relative luminance.
function contrast({ text, background }) {
	const luminance = (rgb) => {
		const [r, g, b] = rgb.map((channel) => {
			const c = channel / 255;
			return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
		});
		return 0.2126 * r + 0.7152 * g + 0.0722 * b;
	};
	const [lighter, darker] = [luminance(text), luminance(background)].sort((a, b) => b - a);
	return (lighter + 0.05) / (darker + 0.05);
}

// A region rather than a dialog: the prompt doesn't stop the visitor reading.
function consentPrompt(page) {
	return page.getByRole('region', { name: 'Can we count your visit?' });
}

function cookieSettings(page) {
	return page.getByRole('navigation', { name: 'Privacy' }).getByRole('button', { name: 'Cookie settings' });
}

async function cookieNames(context) {
	return (await context.cookies()).map((cookie) => cookie.name).sort();
}
