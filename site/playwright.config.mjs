import { defineConfig, devices } from '@playwright/test';

// The site in a real browser: browser/*.spec.mjs against a running docs image, whose address is
// DOCS_URL. checks/docs-browser.sh starts the image and runs these; see the README.

const docsUrl = process.env.DOCS_URL;
if (!docsUrl) throw new Error('DOCS_URL is not set: run checks/docs-browser.sh <image>, or set it to a running docs image');

export default defineConfig({
	testDir: './browser',
	testMatch: /.*\.spec\.mjs/,
	timeout: 60_000,
	expect: { timeout: 10_000 },
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: 0,
	reporter: [['list'], ['html', { open: 'never' }]],
	use: {
		...devices['Desktop Chrome'],
		baseURL: docsUrl,
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
		locale: 'en-US',
	},
});
