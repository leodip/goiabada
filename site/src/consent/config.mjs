// The consent prompt's configuration, for vanilla-cookieconsent, and the loader of
// Google's tag it holds back. Nothing from Google loads until the visitor accepts
// Analytics: the tag is added only by that category's accept callback, which the
// library calls on Accept and on each later page while the choice stands. The
// Privacy page (src/content/docs/about/privacy.mdx) states each setting here, so
// change the two together.

export const googleAnalyticsId = 'G-CYZXDTHNB1';

// Google's cookies last 390 days: thirteen months, whichever months they span, is
// at least 393 days, so they never outlive the thirteen months the Privacy page says.
const googleCookieSeconds = 390 * 24 * 60 * 60;

// Adds Google's tag to the page, once, set to keep as little as it can: no Google
// signals, no ads personalization, and cookies of at most thirteen months.
export function loadGoogleTag(window) {
	if (window.googleTagLoaded) return;
	window.googleTagLoaded = true;

	window.dataLayer = window.dataLayer || [];
	function gtag() {
		window.dataLayer.push(arguments);
	}
	gtag('js', new Date());
	gtag('config', googleAnalyticsId, {
		allow_google_signals: false,
		allow_ad_personalization_signals: false,
		cookie_expires: googleCookieSeconds,
	});

	const script = window.document.createElement('script');
	script.async = true;
	script.src = `https://www.googletagmanager.com/gtag/js?id=${googleAnalyticsId}`;
	window.document.head.append(script);
}

const privacyLink = '<a href="/about/privacy/">Privacy</a>';

export function consentConfig(window) {
	return {
		// Nothing is on until the visitor turns it on, and a browser sending Global
		// Privacy Control gets no prompt and no Analytics; Cookie settings still opens.
		mode: 'opt-in',
		respectGpc: true,
		// The choice is kept in localStorage, never sent to a server, so the site sets
		// no cookie for anyone who hasn't accepted. It's asked again after 182 days.
		cookie: {
			name: 'cc_cookie',
			useLocalStorage: true,
			expiresAfterDays: 182,
		},
		// Accept and Reject side by side, alike, in a box that doesn't stop the visitor
		// reading; the Footer override keeps them side by side on a phone too.
		guiOptions: {
			consentModal: { layout: 'box inline', position: 'bottom right', equalWeightButtons: true },
			preferencesModal: { layout: 'box', equalWeightButtons: true },
		},
		categories: {
			analytics: {
				// Withdrawing deletes Google's cookies and reloads the page, so the tag
				// already running stops at once.
				autoClear: {
					cookies: [{ name: /^_ga/ }, { name: '_gid' }, { name: /^_gat/ }],
					reloadPage: true,
				},
				services: {
					googleAnalytics: {
						label: 'Google Analytics',
						onAccept: () => loadGoogleTag(window),
					},
				},
			},
		},
		language: {
			default: 'en',
			translations: {
				en: {
					consentModal: {
						title: 'Can we count your visit?',
						description:
							'With your OK, Google Analytics tells us which pages people read and how they found them. ' +
							'Nothing from Google loads unless you accept, and you can change your mind any time from Cookie settings at the bottom of every page.',
						acceptAllBtn: 'Accept',
						acceptNecessaryBtn: 'Reject',
						footer: privacyLink,
					},
					preferencesModal: {
						title: 'Cookie settings',
						acceptAllBtn: 'Accept',
						acceptNecessaryBtn: 'Reject',
						savePreferencesBtn: 'Save',
						closeIconLabel: 'Close',
						sections: [
							{
								description:
									'Your choice is kept in your browser for 182 days and is never sent to us. ' +
									'Turning Analytics off deletes its cookies and reloads the page.',
							},
							{
								title: 'Analytics',
								description:
									'Google Analytics counts page views, where visitors came from and how long they stayed. ' +
									'Its cookies last up to 13 months, and what it collects is never used for ads.',
								linkedCategory: 'analytics',
							},
							{
								title: 'More information',
								description: `What the site stores and logs, and how to ask about it: ${privacyLink}.`,
							},
						],
					},
				},
			},
		},
	};
}
