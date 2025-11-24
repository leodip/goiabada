// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const googleAnalyticsId = 'G-CYZXDTHNB1'

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'Goiabada',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/leodip/goiabada' }],
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
						{ label: 'Resources and permissions', slug: 'concepts/resources-permissions' },
						{ label: 'OpenID Connect scopes', slug: 'concepts/openid-connect' },
						{ label: 'User sessions', slug: 'concepts/user-sessions' },
						{ label: 'Tokens', slug: 'concepts/tokens' },
						{ label: 'Users and groups', slug: 'concepts/users-groups' },
					],
				},
				{
					label: 'Integration',
					items: [
						{ label: 'Overview', slug: 'integration' },
						{ label: 'Endpoints', slug: 'integration/endpoints' },
					],
				},
				{
					label: 'Production deployment',
					items: [
						{ label: 'Overview', slug: 'production-deployment' },
						{ label: 'Cloudflare Tunnel', slug: 'production-deployment/cloudflare-tunnel' },
						{ label: 'Cloudflare + Nginx', slug: 'production-deployment/cloudflare-nginx' },
						{ label: 'Reverse proxy (no Cloudflare)', slug: 'production-deployment/reverse-proxy' },
						{ label: 'Kubernetes', slug: 'production-deployment/kubernetes' },
						{ label: 'Native binaries', slug: 'production-deployment/native-binaries' },
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
						{ label: 'About & License', slug: 'about' },
					],
				},
			],
		}),
	],
});
