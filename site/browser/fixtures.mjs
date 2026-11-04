// What every browser test of the site watches, in each test's own browser context:
//
// - Content-Security-Policy violations. A page that reports one fails its test, as in the e2e
//   suite's watcher (e2e/playwright/lib/csp-violations.ts): it listens for the
//   securitypolicyviolation event rather than console messages, which a refused eval leaves empty.
// - Requests to other sites. None reaches the network: Google's are answered here with a stand-in,
//   so CI never sends a hit to the site's Analytics property, and any other is refused. Each is
//   recorded, so a test can assert what a page asked for and when.
//
// vanilla-cookieconsent hides its prompt from a browser that reports automation, as Playwright's
// does through navigator.webdriver. Each page is told it is not automated, so the prompt shows as it
// does to a visitor, without turning that option off for real visitors.
import { test as base, expect } from '@playwright/test';

export { expect };

export const googleAnalyticsId = 'G-CYZXDTHNB1';
export const googleTagUrl = `https://www.googletagmanager.com/gtag/js?id=${googleAnalyticsId}`;

// Google's hosts for GA4, as Google documents them.
const googleHost = /(^|\.)(googletagmanager\.com|google-analytics\.com|analytics\.google\.com)$/;

export function isGoogle(url) {
	return googleHost.test(new URL(url).hostname);
}

// Stands in for Google's tag: it sets Analytics' cookies on the site and sends a hit, as the real
// one does, so a test sees both start after Accept and stop after withdrawal, and a policy that
// left Google's hosts out would refuse them.
const googleTagStub = `
document.cookie = '_ga=GA1.1.1.1; path=/; max-age=33696000; SameSite=Lax';
document.cookie = '_ga_${googleAnalyticsId.slice(2)}=GS1.1.1; path=/; max-age=33696000; SameSite=Lax';
fetch('https://region1.google-analytics.com/g/collect?v=2&tid=${googleAnalyticsId}&en=page_view', { method: 'POST', mode: 'no-cors', keepalive: true });
`;

export const googleHitUrl = /^https:\/\/region1\.google-analytics\.com\/g\/collect\?/;

export const test = base.extend({
	// The URL of every request a page of the test made to another site, in order.
	offSite: async ({}, use) => use([]),
	// One line per Content-Security-Policy violation a page reported: the page, the directive and
	// what it refused, then where the code was. Each test's must be empty when it ends.
	cspViolations: async ({}, use) => use([]),

	context: async ({ context, baseURL, offSite, cspViolations }, use) => {
		const site = new URL(baseURL).origin;

		await context.addInitScript(() => {
			Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => false });
		});

		await context.route(
			(url) => url.origin !== site,
			(route) => {
				const url = route.request().url();
				offSite.push(url);
				const { hostname, pathname } = new URL(url);
				if (hostname === 'www.googletagmanager.com' && pathname === '/gtag/js') {
					return route.fulfill({ contentType: 'text/javascript', body: googleTagStub });
				}
				if (isGoogle(url)) return route.fulfill({ status: 204 });
				return route.abort('blockedbyclient');
			},
		);

		await context.exposeBinding('__cspViolation', (_source, report) => {
			const where = report.sourceFile ? `, at ${report.sourceFile}:${report.lineNumber}` : '';
			cspViolations.push(`${report.documentURI}: ${report.effectiveDirective} blocked ${report.blockedURI}${where}`);
		});
		await context.addInitScript(() => {
			document.addEventListener('securitypolicyviolation', (event) => {
				window.__cspViolation({
					documentURI: event.documentURI,
					effectiveDirective: event.effectiveDirective,
					blockedURI: event.blockedURI,
					sourceFile: event.sourceFile,
					lineNumber: event.lineNumber,
				});
			});
		});

		await use(context);

		await settle(context.pages());
		expect(cspViolations, 'pages of the docs site reported Content-Security-Policy violations').toEqual([]);
	},
});

// Lets each open page hand over a violation it has fired but not yet reported.
export async function settle(pages) {
	await Promise.all(
		pages.map((page) => page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 0))).catch(() => undefined)),
	);
}
