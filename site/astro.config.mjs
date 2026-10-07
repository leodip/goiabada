// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import { fileURLToPath } from 'node:url';

import buildChecks from './checks/build-checks.mjs';

const googleAnalyticsId = 'G-CYZXDTHNB1'

// https://astro.build/config
export default defineConfig({
	site: 'https://goiabada.dev',
	integrations: [
		starlight({
			title: 'Goiabada',
			// Fails the build on an internal link to no page, or to a fragment no heading on
			// its target produces (#511). An http://localhost link is an example of a local
			// install, not a link to this site, so it is not checked.
			plugins: [starlightLinksValidator({ errorOnLocalLinks: false })],
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
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ label: 'Architecture overview', slug: 'getting-started/overview' },
						{ label: 'Setup wizard', slug: 'getting-started/setup-wizard' },
						{ label: 'Quick local test', slug: 'getting-started/quick-local-test' },
						{ label: 'First login', slug: 'getting-started/first-login' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Overview', slug: 'concepts' },
						{ label: 'Clients', slug: 'concepts/clients' },
						{ label: 'PKCE', slug: 'concepts/pkce' },
						{ label: 'Resources and permissions', slug: 'concepts/resources-permissions' },
						{ label: 'OpenID Connect scopes', slug: 'concepts/openid-connect' },
						{ label: 'User sessions', slug: 'concepts/user-sessions' },
						{ label: 'Prompt parameter', slug: 'concepts/prompt-parameter' },
						{ label: 'ID Token Hint', slug: 'concepts/id-token-hint' },
						{ label: 'ACR and AMR', slug: 'concepts/acr-amr' },
						{ label: 'Authorization lifecycle', slug: 'concepts/authorization-lifecycle' },
						{ label: 'Tokens', slug: 'concepts/tokens' },
						{ label: 'Users and groups', slug: 'concepts/users-groups' },
						{ label: 'Localization', slug: 'concepts/localization' },
						{ label: 'Audit log', slug: 'concepts/audit-log' },
					],
				},
				{
					label: 'OAuth2 flows',
					items: [
						{ label: 'Overview', slug: 'oauth2-flows' },
						{ label: 'Authorization Code', slug: 'oauth2-flows/authorization-code' },
						{ label: 'Client Credentials', slug: 'oauth2-flows/client-credentials' },
						{ label: 'Implicit (Legacy)', slug: 'oauth2-flows/implicit' },
						{ label: 'ROPC (Legacy)', slug: 'oauth2-flows/resource-owner-password' },
					],
				},
				{
					label: 'Integration',
					items: [
						{ label: 'Overview', slug: 'integration' },
						{ label: 'Endpoints', slug: 'integration/endpoints' },
						{ label: 'REST API', slug: 'integration/rest-api' },
					],
				},
				{
					label: 'Production deployment',
					items: [
						{ label: 'Overview', slug: 'production-deployment' },
						{ label: 'Database setup', slug: 'production-deployment/database' },
						{ label: 'Cloudflare Tunnel', slug: 'production-deployment/cloudflare-tunnel' },
						{ label: 'Cloudflare + Nginx', slug: 'production-deployment/cloudflare-nginx' },
						{ label: 'Reverse proxy (no Cloudflare)', slug: 'production-deployment/reverse-proxy' },
						{ label: 'Kubernetes', slug: 'production-deployment/kubernetes' },
						{ label: 'Native binaries', slug: 'production-deployment/native-binaries' },
						{ label: 'Monitoring', slug: 'production-deployment/monitoring' },
						{ label: 'Production checklist', slug: 'production-deployment/production-checklist' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Environment variables', slug: 'reference/environment-variables' },
						{ label: 'Customizations', slug: 'reference/customizations' },
						{ label: 'Security', slug: 'reference/security' },
					],
				},
				{
					label: 'Development',
					items: [
						{ label: 'Contributing', slug: 'development' },
					],
				},
				{
					label: 'About',
					items: [
						{ label: 'About', slug: 'about' },
						{ label: 'Contact', slug: 'about/contact' },
						{ label: 'License', slug: 'about/license' },
					],
				},
			],
		}),
		// After Starlight, so its checks read the finished pages. The repository's
		// src/ is beside this directory, in a checkout and in the docs image's build.
		buildChecks({ srcDir: fileURLToPath(new URL('../src/', import.meta.url)) }),
	],
});
