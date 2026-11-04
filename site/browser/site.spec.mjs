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
