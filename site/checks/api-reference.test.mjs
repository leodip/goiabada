// The split of openapi.yaml into the two documents the API reference renders,
// driven on a small fixture spec. Each case states the operations it expects in
// each document as literals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { splitApiReference, writeApiReference } from './api-reference.mjs';

function operation(operationId, tags) {
	return { operationId, tags, summary: operationId, responses: { 200: { description: 'OK' } } };
}

function spec(paths) {
	return {
		openapi: '3.0.3',
		info: { title: 'Goiabada API', description: 'The whole API.', version: '1.0.0' },
		servers: [{ url: '{baseUrl}' }],
		security: [{ BearerAuth: [] }],
		tags: [
			{ name: 'Users', description: 'User management (Admin API)' },
			{ name: 'Clients', description: 'OAuth client management (Admin API)' },
			{ name: 'Account', description: 'Self-service account management (Account API)' },
			{ name: 'Browser Sessions', description: 'Not a public surface.' },
		],
		paths,
		components: { securitySchemes: { BearerAuth: { type: 'http', scheme: 'bearer' } } },
	};
}

// Every operation of a document, as "METHOD path operationId [tags]".
function operations(document) {
	const listed = [];
	for (const [path, item] of Object.entries(document.paths)) {
		for (const [method, op] of Object.entries(item)) {
			listed.push(`${method.toUpperCase()} ${path} ${op.operationId} [${op.tags.join(', ')}]`);
		}
	}
	return listed;
}

const fullSpec = () =>
	spec({
		'/api/v1/admin/users/{id}': { get: operation('getUser', ['Users']), delete: operation('deleteUser', ['Users']) },
		'/api/v1/admin/clients/{id}': { get: operation('getClient', ['Clients']) },
		'/client/logo/{clientIdentifier}': { get: { ...operation('getClientLogoImage', ['Clients']), security: [] } },
		'/api/v1/account/profile': { get: operation('getAccountProfile', ['Account']) },
		'/api/v1/account/profile-picture': { post: operation('uploadAccountProfilePicture', ['Account']) },
		'/api/v1/account/otp/enrollment': { get: operation('getAccountOTPEnrollment', ['Account']) },
		'/api/v1/account/logout-request': { post: operation('requestAccountLogout', ['Account']) },
		'/api/v1/sessions/load': { post: operation('loadBrowserSession', ['Browser Sessions']) },
	});

test('the Admin API holds the admin operations and the public client logo, under their own tags', () => {
	const { admin } = splitApiReference(fullSpec());
	assert.deepEqual(operations(admin), [
		'GET /api/v1/admin/users/{id} getUser [Users]',
		'DELETE /api/v1/admin/users/{id} deleteUser [Users]',
		'GET /api/v1/admin/clients/{id} getClient [Clients]',
		'GET /client/logo/{clientIdentifier} getClientLogoImage [Clients]',
	]);
	assert.equal(admin.info.title, 'Admin API');
	assert.deepEqual(
		admin.tags.map((tag) => tag.name),
		['Users', 'Clients'],
	);
	assert.deepEqual(admin.paths['/client/logo/{clientIdentifier}'].get.security, []);
});

test('the Account API holds the account operations, split by resource', () => {
	const { account } = splitApiReference(fullSpec());
	assert.deepEqual(operations(account), [
		'GET /api/v1/account/profile getAccountProfile [Profile]',
		'POST /api/v1/account/profile-picture uploadAccountProfilePicture [Profile picture]',
		'GET /api/v1/account/otp/enrollment getAccountOTPEnrollment [Two-factor authentication]',
		'POST /api/v1/account/logout-request requestAccountLogout [Sign-out]',
	]);
	assert.equal(account.info.title, 'Account API');
	assert.deepEqual(
		account.tags.map((tag) => tag.name),
		['Profile', 'Profile picture', 'Two-factor authentication', 'Sign-out'],
	);
});

test('the Browser Sessions operations are in neither document', () => {
	const { admin, account } = splitApiReference(fullSpec());
	for (const document of [admin, account]) {
		assert.ok(!('/api/v1/sessions/load' in document.paths));
		assert.ok(!document.tags.some((tag) => tag.name === 'Browser Sessions'));
	}
});

test('the split leaves the spec it was given unchanged', () => {
	const given = fullSpec();
	const before = JSON.stringify(given);
	splitApiReference(given);
	assert.equal(JSON.stringify(given), before);
});

test('an operation the reference cannot place fails the split, naming it', () => {
	const unplaced = spec({ '/api/v2/things': { get: operation('getThings', ['Things']) } });
	assert.throws(() => splitApiReference(unplaced), {
		message: /openapi\.yaml: GET \/api\/v2\/things \(getThings\) is in neither the Admin API nor the Account API/,
	});
});

test('an internal path the spec does not tag Browser Sessions fails the split rather than being published', () => {
	const untagged = spec({ '/api/v1/sessions/load': { post: operation('loadBrowserSession', ['Sessions']) } });
	assert.throws(() => splitApiReference(untagged), {
		message: /POST \/api\/v1\/sessions\/load \(loadBrowserSession\) is in neither/,
	});
});

test('an Account API resource with no sidebar label fails the split, naming it', () => {
	const unknown = spec({ '/api/v1/account/passkeys': { get: operation('getAccountPasskeys', ['Account']) } });
	assert.throws(() => splitApiReference(unknown), {
		message: /openapi\.yaml: GET \/api\/v1\/account\/passkeys \(getAccountPasskeys\) is an Account API resource, passkeys, with no label/,
	});
});

test('writeApiReference writes both documents as JSON from a YAML spec', () => {
	const dir = mkdtempSync(join(tmpdir(), 'api-reference-'));
	const specPath = join(dir, 'openapi.yaml');
	writeFileSync(
		specPath,
		[
			'openapi: 3.0.3',
			'info: { title: Goiabada API, version: 1.0.0 }',
			'paths:',
			'  /api/v1/admin/users/{id}:',
			'    get: { operationId: getUser, tags: [Users], responses: { "200": { description: OK } } }',
			'  /api/v1/account/email:',
			'    put: { operationId: updateAccountEmail, tags: [Account], responses: { "200": { description: OK } } }',
			'',
		].join('\n'),
	);
	const written = writeApiReference({ specPath, outDir: join(dir, 'out') });
	const admin = JSON.parse(readFileSync(written.admin, 'utf8'));
	const account = JSON.parse(readFileSync(written.account, 'utf8'));
	assert.deepEqual(operations(admin), ['GET /api/v1/admin/users/{id} getUser [Users]']);
	assert.deepEqual(operations(account), ['PUT /api/v1/account/email updateAccountEmail [Email]']);
});
