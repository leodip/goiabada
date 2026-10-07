// The site's own checks, run once `astro build` has written every page. A check
// that throws fails the build, so the docs image cannot be built past one.

import { fileURLToPath } from 'node:url';

import { assertShippedLinks } from './shipped-links.mjs';

// srcDir is the repository's src/ directory, whose code the shipped-link check reads.
export default function buildChecks({ srcDir }) {
	return {
		name: 'goiabada-build-checks',
		hooks: {
			'astro:build:done': ({ dir, logger }) => {
				const links = assertShippedLinks({ distDir: fileURLToPath(dir), srcDir });
				logger.info(`${links.length} goiabada.dev links in shipped code name a built page`);
			},
		},
	};
}
