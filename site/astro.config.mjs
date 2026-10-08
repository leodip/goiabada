// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import starlightOpenAPI, { openAPISidebarGroups } from 'starlight-openapi';
import { fileURLToPath } from 'node:url';

import { writeApiReference } from './checks/api-reference.mjs';
import { apiReferences } from './checks/api-reference-links.mjs';
import buildChecks from './checks/build-checks.mjs';
import { fullFile, indexFile } from './checks/llms.mjs';

const googleAnalyticsId = 'G-CYZXDTHNB1'

// The Admin API and the Account API reference, rendered from the auth server's
// openapi.yaml, the same file it serves at /openapi.yaml. It is split into the
// two documents first, the internal Browser Sessions operations left out.
const apiReference = writeApiReference({
	specPath: fileURLToPath(new URL('../src/authserver/web/openapi.yaml', import.meta.url)),
	outDir: fileURLToPath(new URL('./.openapi/', import.meta.url)),
});

// The generated pages, each one's sidebar group collapsed and its operations
// labelled with their method. Code samples are curl only, as every example of
// calling Goiabada is.
function apiReferenceSchema(base, label, schema) {
	return {
		base,
		schema,
		sidebar: { label, collapsed: true, operations: { badges: true } },
		snippets: { operation: { clients: { shell: ['curl'] } } },
	};
}

// https://astro.build/config
export default defineConfig({
	site: 'https://goiabada.dev',
	integrations: [
		starlight({
			title: 'Goiabada',
			// The links validator fails the build on an internal link to no page, or to a
			// fragment no heading on its target produces (#511). An http://localhost link is
			// an example of a local install, not a link to this site, so it is not checked.
			// Nor are the links to the two llms files: buildChecks writes them after this
			// check has run, under the names excluded here, and fails the build when it
			// cannot read them back. Links into the generated API reference, whose pages the
			// validator cannot see, are checked by buildChecks against the built pages.
			plugins: [
				starlightOpenAPI([
					apiReferenceSchema(apiReferences.admin, 'Admin API', apiReference.admin),
					apiReferenceSchema(apiReferences.account, 'Account API', apiReference.account),
				]),
				starlightLinksValidator({
					errorOnLocalLinks: false,
					exclude: [
						`/${indexFile}`,
						`/${fullFile}`,
						...Object.values(apiReferences).flatMap((base) => [`/${base}/`, `/${base}/**`]),
					],
				}),
			],
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/leodip/goiabada' }],
			favicon: '/favicon.ico',
			head: [
				{
					tag: 'script',
					attrs: {
						src: `https://www.googletagmanager.com/gtag/js?id=${googleAnalyticsId}`,
					},
				},
				{
					tag: 'script',
					content: `
					window.dataLayer = window.dataLayer || [];
					function gtag(){dataLayer.push(arguments);}
					gtag('js', new Date());

					gtag('config', '${googleAnalyticsId}');
					`,
				},
			],
			// Organized by task. A page's URL is its group's path and its own label, so the
			// two read alike: Deploy > Monitoring is /deploy/monitoring/.
			sidebar: [
				{
					label: 'Get started',
					items: [
						{ label: 'Introduction', slug: 'get-started/introduction' },
						{ label: 'Quickstart', slug: 'get-started/quickstart' },
						{ label: 'Setup wizard', slug: 'get-started/setup-wizard' },
						{ label: 'First sign-in', slug: 'get-started/first-sign-in' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'Add sign-in to a web app', slug: 'guides/add-sign-in-to-a-web-app' },
						{ label: 'Add sign-in to a SPA or mobile app', slug: 'guides/add-sign-in-to-a-spa-or-mobile-app' },
						{ label: 'Sign users out', slug: 'guides/sign-users-out' },
						{ label: 'Protect an API', slug: 'guides/protect-an-api' },
						{ label: 'Require two-factor authentication', slug: 'guides/require-two-factor-authentication' },
						{ label: 'Single sign-on across clients', slug: 'guides/single-sign-on-across-clients' },
						{ label: 'Let clients register themselves (DCR)', slug: 'guides/let-clients-register-themselves-dcr' },
						{ label: 'Customize and translate the pages', slug: 'guides/customize-and-translate-the-pages' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Clients', slug: 'concepts/clients' },
						{ label: 'Users and groups', slug: 'concepts/users-and-groups' },
						{ label: 'Self-registration', slug: 'concepts/self-registration' },
						{ label: 'Password recovery', slug: 'concepts/password-recovery' },
						{ label: 'Resources and permissions', slug: 'concepts/resources-and-permissions' },
						{ label: 'Scopes', slug: 'concepts/scopes' },
						{ label: 'Tokens', slug: 'concepts/tokens' },
						{ label: 'Refresh tokens', slug: 'concepts/refresh-tokens' },
						{ label: 'Sessions', slug: 'concepts/sessions' },
						{ label: 'Ending sessions', slug: 'concepts/ending-sessions' },
						{ label: 'ACR and AMR', slug: 'concepts/acr-and-amr' },
						{ label: 'prompt', slug: 'concepts/prompt' },
						{ label: 'id_token_hint', slug: 'concepts/id-token-hint' },
						{ label: 'PKCE', slug: 'concepts/pkce' },
						{ label: 'Audit log', slug: 'concepts/audit-log' },
						{ label: 'Glossary', slug: 'concepts/glossary' },
					],
				},
				{
					label: 'Deploy',
					items: [
						{ label: 'Choose a method', slug: 'deploy/choose-a-method' },
						{ label: 'Docker Compose', slug: 'deploy/docker-compose' },
						{ label: 'Cloudflare Tunnel', slug: 'deploy/cloudflare-tunnel' },
						{ label: 'Cloudflare + Nginx', slug: 'deploy/cloudflare-nginx' },
						{ label: 'Reverse proxy', slug: 'deploy/reverse-proxy' },
						{
							label: 'Kubernetes',
							items: [
								{ label: 'Overview', slug: 'deploy/kubernetes/overview' },
								{ label: 'Gateway and certificates', slug: 'deploy/kubernetes/gateway-and-certificates' },
								{ label: 'High availability', slug: 'deploy/kubernetes/high-availability' },
								{ label: 'Security', slug: 'deploy/kubernetes/security' },
								{ label: 'Secrets', slug: 'deploy/kubernetes/secrets' },
								{ label: 'Probes and shutdown', slug: 'deploy/kubernetes/probes-and-shutdown' },
							],
						},
						{ label: 'Native binaries', slug: 'deploy/native-binaries' },
						{ label: 'Client IP and proxy trust', slug: 'deploy/client-ip-and-proxy-trust' },
						{ label: 'Database', slug: 'deploy/database' },
						{ label: 'Secrets', slug: 'deploy/secrets' },
						{ label: 'Rotate secrets', slug: 'deploy/rotate-secrets' },
						{ label: 'Upgrade Goiabada', slug: 'deploy/upgrade-goiabada' },
						{ label: 'Monitoring', slug: 'deploy/monitoring' },
						{ label: 'Logs', slug: 'deploy/logs' },
						{ label: 'Production checklist', slug: 'deploy/production-checklist' },
					],
				},
				{
					label: 'Reference',
					items: [
						{
							label: 'Endpoints',
							items: [
								{ label: 'Authorize', slug: 'reference/endpoints/authorize' },
								{ label: 'Token', slug: 'reference/endpoints/token' },
								{ label: 'Logout', slug: 'reference/endpoints/logout' },
								{ label: 'UserInfo', slug: 'reference/endpoints/userinfo' },
								{ label: 'Dynamic client registration', slug: 'reference/endpoints/dynamic-client-registration' },
								{ label: 'Discovery and JWKS', slug: 'reference/endpoints/discovery-and-jwks' },
								{ label: 'Logo and picture', slug: 'reference/endpoints/logo-and-picture' },
							],
						},
						{
							label: 'API',
							items: [
								{ label: 'Authentication', slug: 'reference/api/authentication' },
								{ label: 'Scopes', slug: 'reference/api/scopes' },
								{ label: 'Administrators', slug: 'reference/api/administrators' },
								{ label: 'Errors', slug: 'reference/api/errors' },
								...openAPISidebarGroups,
							],
						},
						{ label: 'Environment variables', slug: 'reference/environment-variables' },
						{ label: 'Security', slug: 'reference/security' },
					],
				},
				{
					label: 'Troubleshooting',
					items: [
						{ label: 'Invalid redirect_uri', slug: 'troubleshooting/invalid-redirect-uri' },
						{ label: 'The app gets no error back', slug: 'troubleshooting/the-app-gets-no-error-back' },
						{ label: 'invalid_scope', slug: 'troubleshooting/invalid-scope' },
						{ label: 'login_required', slug: 'troubleshooting/login-required' },
						{ label: 'This refresh token has been revoked', slug: 'troubleshooting/this-refresh-token-has-been-revoked' },
						{ label: 'Sign-out answers 403', slug: 'troubleshooting/sign-out-answers-403' },
						{ label: 'Too many attempts or 429', slug: 'troubleshooting/too-many-attempts-or-429' },
						{ label: 'Locked out of the admin console', slug: 'troubleshooting/locked-out-of-the-admin-console' },
						{ label: 'Unable to load the configuration from the auth server', slug: 'troubleshooting/unable-to-load-the-configuration-from-the-auth-server' },
						{ label: 'A user cannot reset their password', slug: 'troubleshooting/a-user-cannot-reset-their-password' },
						{ label: 'Certificates are not issued', slug: 'troubleshooting/certificates-are-not-issued' },
						{ label: 'CrashLoopBackOff or unable to create the database connection', slug: 'troubleshooting/crashloopbackoff-or-unable-to-create-the-database-connection' },
						{ label: 'attempt to write a readonly database', slug: 'troubleshooting/attempt-to-write-a-readonly-database' },
						{ label: 'Waiting for the migration lock, or marked dirty', slug: 'troubleshooting/waiting-for-the-migration-lock-or-marked-dirty' },
						{ label: 'Metrics are not scraped', slug: 'troubleshooting/metrics-are-not-scraped' },
					],
				},
				{
					label: 'Legacy flows',
					items: [
						{ label: 'Implicit', slug: 'legacy-flows/implicit' },
						{ label: 'ROPC', slug: 'legacy-flows/ropc' },
					],
				},
				{
					label: 'About',
					items: [
						{ label: 'About', slug: 'about' },
						{ label: 'Contributing', slug: 'about/contributing' },
						{ label: 'Contact', slug: 'about/contact' },
						{ label: 'License', slug: 'about/license' },
					],
				},
			],
		}),
		// After Starlight, so its checks read the finished pages. The repository's
		// src/ is beside this directory, in a checkout and in the docs image's build.
		// It also writes /llms.txt and /llms-full.txt, which llms heads, and checks the
		// links into the generated API reference.
		buildChecks({
			srcDir: fileURLToPath(new URL('../src/', import.meta.url)),
			apiReferences,
			llms: {
				title: 'Goiabada',
				summary: 'An open-source OAuth2 and OpenID Connect server for simple, secure authentication.',
			},
		}),
	],
});
