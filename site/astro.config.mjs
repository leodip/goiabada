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
						{ label: 'Authorization code', slug: 'guides/authorization-code' },
						{ label: 'Client credentials', slug: 'guides/client-credentials' },
						{ label: 'Localization', slug: 'guides/localization' },
						{ label: 'Customizations', slug: 'guides/customizations' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Clients', slug: 'concepts/clients' },
						{ label: 'Users and groups', slug: 'concepts/users-and-groups' },
						{ label: 'Resources and permissions', slug: 'concepts/resources-and-permissions' },
						{ label: 'Scopes', slug: 'concepts/scopes' },
						{ label: 'Tokens', slug: 'concepts/tokens' },
						{ label: 'Sessions', slug: 'concepts/sessions' },
						{ label: 'ACR and AMR', slug: 'concepts/acr-and-amr' },
						{ label: 'prompt', slug: 'concepts/prompt' },
						{ label: 'id_token_hint', slug: 'concepts/id-token-hint' },
						{ label: 'PKCE', slug: 'concepts/pkce' },
						{ label: 'Authorization lifecycle', slug: 'concepts/authorization-lifecycle' },
						{ label: 'Audit log', slug: 'concepts/audit-log' },
						{ label: 'Glossary', slug: 'concepts/glossary' },
					],
				},
				{
					label: 'Deploy',
					items: [
						{ label: 'Docker Compose', slug: 'deploy/docker-compose' },
						{ label: 'Cloudflare Tunnel', slug: 'deploy/cloudflare-tunnel' },
						{ label: 'Cloudflare + Nginx', slug: 'deploy/cloudflare-nginx' },
						{ label: 'Reverse proxy', slug: 'deploy/reverse-proxy' },
						{ label: 'Kubernetes', slug: 'deploy/kubernetes' },
						{ label: 'Native binaries', slug: 'deploy/native-binaries' },
						{ label: 'Database', slug: 'deploy/database' },
						{ label: 'Monitoring', slug: 'deploy/monitoring' },
						{ label: 'Production checklist', slug: 'deploy/production-checklist' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Endpoints', slug: 'reference/endpoints' },
						{ label: 'REST API', slug: 'reference/rest-api' },
						{ label: 'Environment variables', slug: 'reference/environment-variables' },
						{ label: 'Security', slug: 'reference/security' },
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
		// It also writes /llms.txt and /llms-full.txt, which llms heads.
		buildChecks({
			srcDir: fileURLToPath(new URL('../src/', import.meta.url)),
			llms: {
				title: 'Goiabada',
				summary: 'An open-source OAuth2 and OpenID Connect server for simple, secure authentication.',
			},
		}),
	],
});
