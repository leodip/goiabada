// The site's own checks, run once `astro build` has written every page. A check
// that throws fails the build, so the docs image cannot be built past one.

import { fileURLToPath } from 'node:url';

import { assertLlmsFiles, writeLlmsFiles } from './llms.mjs';
import { assertShippedLinks } from './shipped-links.mjs';

// srcDir is the repository's src/ directory, whose code the shipped-link check
// reads. llms holds the title and one-line summary that head llms.txt.
export default function buildChecks({ srcDir, llms }) {
	let site;
	return {
		name: 'goiabada-build-checks',
		hooks: {
			'astro:config:done': ({ config }) => {
				site = config.site;
			},
			'astro:build:done': ({ dir, logger }) => {
				const distDir = fileURLToPath(dir);
				if (!site) throw new Error("the llms files need the site's URL: set site in astro.config.mjs");
				const pages = writeLlmsFiles({ distDir, site, title: llms.title, summary: llms.summary });
				assertLlmsFiles({ distDir, site });
				logger.info(`llms.txt and llms-full.txt hold all ${pages} pages`);

				const links = assertShippedLinks({ distDir, srcDir });
				logger.info(`${links.length} goiabada.dev links in shipped code name a built page`);
			},
		},
	};
}
