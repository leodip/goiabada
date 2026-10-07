// The API reference's two documents, split from openapi.yaml before the build
// renders them: the Admin API, which holds the public client logo with the
// clients, and the Account API, split by resource. The Browser Sessions
// operations, which the spec itself calls the admin console's internal API and
// not a public surface, are in neither. An operation the split cannot place
// fails the build rather than being left out or published by accident.
//
// Only the grouping changes. Every operation, parameter, schema and description
// is the spec's own, so the reference and /openapi.yaml say the same things.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { parse } from 'yaml';

// The tag the spec gives the internal operations.
const internalTag = 'Browser Sessions';

const adminPrefixes = ['/api/v1/admin/', '/client/logo/'];
const accountPrefix = '/api/v1/account/';

// The Account API's resources, by the path segment after /api/v1/account/, with
// the sidebar label each one is listed under, in the sidebar's order. The spec
// tags every one of them Account, which would make one long list.
const accountResources = new Map([
	['profile', 'Profile'],
	['email', 'Email'],
	['phone', 'Phone'],
	['address', 'Address'],
	['password', 'Password'],
	['profile-picture', 'Profile picture'],
	['otp', 'Two-factor authentication'],
	['consents', 'Consents'],
	['sessions', 'Sessions'],
	['logout-request', 'Sign-out'],
]);

const methods = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

// Returns { admin, account }, two OpenAPI documents holding between them every
// operation of spec but the internal ones. spec is not changed.
export function splitApiReference(spec) {
	const admin = {};
	const account = {};
	const accountTags = new Set();

	for (const [path, item] of Object.entries(spec.paths ?? {})) {
		for (const method of methods) {
			const operation = item[method];
			if (!operation) continue;
			const name = `${method.toUpperCase()} ${path} (${operation.operationId})`;

			if ((operation.tags ?? []).includes(internalTag)) continue;

			if (path.startsWith(accountPrefix)) {
				const resource = path.slice(accountPrefix.length).split('/')[0];
				const label = accountResources.get(resource);
				if (!label) {
					throw new Error(
						`openapi.yaml: ${name} is an Account API resource, ${resource}, with no label in checks/api-reference.mjs`,
					);
				}
				accountTags.add(label);
				place(account, path, item, method, { ...operation, tags: [label] });
				continue;
			}

			if (adminPrefixes.some((prefix) => path.startsWith(prefix))) {
				place(admin, path, item, method, operation);
				continue;
			}

			throw new Error(
				`openapi.yaml: ${name} is in neither the Admin API nor the Account API; place it in checks/api-reference.mjs`,
			);
		}
	}

	const adminTags = new Set(Object.values(admin).flatMap((item) => operationsOf(item).flatMap((op) => op.tags ?? [])));
	return {
		admin: document(spec, 'Admin API', admin, (spec.tags ?? []).filter((tag) => adminTags.has(tag.name))),
		account: document(
			spec,
			'Account API',
			account,
			[...accountResources.values()].filter((label) => accountTags.has(label)).map((name) => ({ name })),
		),
	};
}

// Puts operation at path in paths, beside the path item's own fields, such as
// the parameters every operation on it shares.
function place(paths, path, item, method, operation) {
	if (!paths[path]) {
		paths[path] = Object.fromEntries(Object.entries(item).filter(([key]) => !methods.includes(key)));
	}
	paths[path][method] = operation;
}

function operationsOf(item) {
	return methods.map((method) => item[method]).filter(Boolean);
}

function document(spec, title, paths, tags) {
	return { ...spec, info: { ...spec.info, title }, tags, paths };
}

// Reads the YAML spec at specPath and writes the two documents into outDir as
// admin.json and account.json, returning their paths.
export function writeApiReference({ specPath, outDir }) {
	const { admin, account } = splitApiReference(parse(readFileSync(specPath, 'utf8')));
	mkdirSync(outDir, { recursive: true });
	const written = { admin: join(outDir, 'admin.json'), account: join(outDir, 'account.json') };
	writeFileSync(written.admin, JSON.stringify(admin, null, '\t'));
	writeFileSync(written.account, JSON.stringify(account, null, '\t'));
	return written;
}
