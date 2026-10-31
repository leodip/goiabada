# End-to-end environment

A real Goiabada deployment on the maintainer's VPS, built from a release tag, for browser tests.
It builds the environment, deploys the test app beside it, checks that both are reachable, and runs
two Playwright suites against them:

- **e2e** (`playwright/tests/`, `e2e/test.sh`): the product works. Every page, flow and protocol rule,
  eight tests at a time, with the auth server's rate limiter off.
- **rate-limits** (`playwright/rate-limits/`, `e2e/test-rate-limits.sh`): the rate limiter works. The
  limits the auth server counts by a client's address, one test at a time, with the limiter on.

| Host | What |
|---|---|
| `e2e-auth.goiabada.dev` | Auth server |
| `e2e-admin.goiabada.dev` | Admin console |
| `e2e-webtest1.goiabada.dev` | The test app (`testapp/`): the web app, the SPA, the service and the API |
| `e2e-webtest2.goiabada.dev` | The test app again, for its second web app: single sign-on across two sites |

The deployment is the docs' [Reverse proxy](https://goiabada.dev/deploy/reverse-proxy/) method, as a
user would follow it: the release's own setup wizard writes the Compose files (production, PostgreSQL),
nginx on the VPS terminates TLS with a Let's Encrypt certificate, and the DNS records are DNS only.

The suite and its scripts follow the code on `main`, not the releases before it, so they need a
release after v1.7.0: they no longer work around how v1.7.0 signed people in from one address (#564)
or started its first PostgreSQL (#551). Against v1.7.0 the suite fails, and the environment may fail
to start. Before a release, build the environment from the checkout instead (`--source`), which is
what that release will ship.

## Contribute tests

The suites run against the maintainer's VPS and require SSH access to it. External contributors
do not have that access, so you cannot run these suites against the project's environment.
The public test URLs alone are insufficient: the runner also controls the rate limiter and opens
an SSH tunnel to Mailpit.

New and improved e2e tests are welcome. Follow the [browser test conventions](#browser-tests) below,
and check the TypeScript locally, from `e2e/playwright/`:

```sh
npm ci
npm run typecheck
```

In your pull request, say that the browser suites were not run because they require the
maintainer's VPS; a maintainer can run them. The Go unit, data and integration tiers described in
the [contributing guide](../site/src/content/docs/about/contributing.mdx#run-the-tests) run in the
dev container and do not require this VPS.

## Run it

From the repository root, on a machine with an SSH key the VPS accepts:

```bash
cp e2e/.env.example e2e/.env    # once: set E2E_VPS_HOST

e2e/run.sh [tag | --source]     # reset, then the e2e suite
e2e/reset.sh [tag | --source]   # wipe the environment and build it again from a release, or this checkout
e2e/test.sh [playwright args]   # run the e2e suite against the current environment
e2e/test-rate-limits.sh [args]  # run the rate-limits suite against the current environment
e2e/wipe.sh [--all] [-y]        # remove the environment (asks first)
```

With no tag, `run.sh` and `reset.sh` take the latest GitHub release. With `--source` they build what
a release would ship from this checkout's `src/` instead, on the VPS: both servers' images from their
Dockerfiles and the setup wizard, under the version `e2e-<commit>`, with `-dirty` when `src/` has
uncommitted changes. `test.sh` and `test-rate-limits.sh` install the suites' packages and Chromium the
first time, check their types (`npm run typecheck`), and pass their arguments to Playwright:
`--headed`, `--ui`, or a folder such as `tests/admin-console`. The two never run at once: each holds
`e2e/.state/suite.lock` for its run. Each script answers `--help`.

They wrap the scripts in `infra/`, which can also be run on their own: `prepare.sh <tag | --source>`,
`verify.sh [tag]` (check the environment again at any time), `rate-limiter.sh on | off | reset` and
`teardown.sh [--all]`.

`prepare.sh`:

1. Checks the release exists (or archives `src/`, for `--source`), the VPS answers over SSH, and
   each host's DNS reaches the VPS.
2. Generates the admin password into `e2e/.state/admin-password`.
3. On the VPS (`remote-prepare.sh`): removes the previous environment and its volumes, downloads
   the release's `goiabada-setup` and checks it against the release's `checksums.txt` (or, for
   `--source`, builds it and both images, labelled `goiabada-e2e=server`), runs it, starts
   the stack, waits for both servers, and writes `/etc/nginx/conf.d/goiabada-e2e.conf` from
   `nginx.conf.template`. The certificate is requested only when it is missing or does not cover the
   four hosts.
4. Writes `e2e/.state/environment.env` (URLs, tag, admin email), and switches the rate limiter off
   (`rate-limiter.sh off`).
5. Sets up the test app with `testapp.sh` (see [Test app](#test-app)).
6. Runs `verify.sh`.

`verify.sh` checks DNS, HTTPS and its certificate's expiry, the HTTP-to-HTTPS redirect, that the VPS
runs the tag's images, the auth server's health, discovery and JWKS, the admin console's page, that its
sign-in lands on the auth server's password page, that the test app runs configured on both hosts,
and that its API refuses a request with no token.

### The rate limiter

The setup wizard turns the auth server's rate limiter on, as it does for production. The environment
rests with it off: `infra/rate-limiter.sh` sets `GOIABADA_AUTHSERVER_RATELIMITER_ENABLED` in
`ratelimiter.yml` beside the wizard's Compose files, over the wizard's value, and fails unless the
running auth server has the value it asked for.

Off, nothing counts this machine's address, so the e2e suite signs everyone in from it as fast as it
likes. The limits counted by an account or a user apply either way, since no proxy can count them. The
e2e suite does not spend them, because a successful sign-in spends nothing and the tests that fail a
password or a code do it on throwaway accounts of their own. `test.sh` switches the limiter off before
it runs, in case a run of the rate-limits suite was killed before switching it back.

The rate-limits suite tests what the limiter counts by an address: 120 requests a minute to the
authorization endpoint, and 30 wrong passwords and 120 password checks a minute at the sign-in form and
the password grant. `test-rate-limits.sh` switches the limiter on for the run, and off again when the
run ends, pass or fail. Before each test, `lib/rate-limits.ts` restarts the auth server
(`rate-limiter.sh reset`). The limiter keeps the counts of an address in memory, so every test starts
with whole budgets: what another test or an earlier run spent weighs on none of them, and no test waits
for a window to pass. Run it before a release.

## Browser tests

`playwright/` holds both suites, which share `lib/`. They read the URLs and the admin password
`prepare.sh` left in `e2e/.state/`, so they run against the environment this machine last prepared.
After a failure, `(cd e2e/playwright && npx playwright show-report)` opens the e2e suite's report with
traces, and `npx playwright show-report playwright-report-rate-limits` the rate-limits suite's.

The rate-limits suite is `playwright/rate-limits/`, run by `rate-limits.config.ts`; its tests import
`test` from `lib/rate-limits.ts`, whose restart before each test is what they rely on. Everything
below is about the e2e suite.

Tests sit under `playwright/tests/`, one folder per area: the admin console (`admin-console/sign-in`,
`admin-console/shell`, `admin-console/clients/`, `resources/`, `groups/`, `users/`, `legal-documents/`,
`account/` and `settings/`), the test app (`testapp/`: a user signing in to its web apps, its SPA and its API, single
sign-on across its two sites, signing out, the authorization parameters, and the auth server's own
pages), OAuth 2.0 and its security practice section by section (`rfc6749/`, `rfc9700/`), the protocol
itself where no page reaches it (`oauth/`), the Turnstile challenge on the auth server's forms with
Cloudflare's test keys (`turnstile/`), and accessibility (`accessibility/`: axe over every page and
state of both applications in the light and the dark scheme, the layout at phone and tablet widths,
and the main journeys by keyboard). They run eight at a time against an
environment that stays up between runs, so every test keeps to these rules, which is what lets the
suite run again and again without a reset:

- **It creates what it needs under a unique name** (`e2e-<kind>-<random>`, `lib/unique.ts`) through a
  fixture that removes it afterwards, pass or fail (`clients`, `resources`, `groups`, `legalDocuments`
  and `users` in `lib/fixtures.ts`). A legal document that was published can't be deleted, so the
  fixture retires it, and it stays in the list, retired. The setup step (`tests/admin.setup.ts`)
  sweeps anything left with that prefix by a run that crashed.
- **It changes nothing global**: no settings, and the system client and the system resource
  (`authserver`) are only read; a test reaching their save answers Cancel to the confirmation. A
  legal document it publishes applies to selected apps, clients of its own, set before it is
  published (the fixture's `apps`): one for all apps shows in every other test's sign-in. The
  exceptions are the tests whose subject is global, the settings pages, the signing keys, the
  guards around the system resource and documents for all apps. They are named `*.system.ts` and
  run in the `system` project, which `playwright.config.ts` runs after every other test, on one
  worker. Each puts back what it changes (`lib/settings.ts`), and retires what it published; the
  setup step restores the seeded settings before a run if one failed to.
- **It never depends on what another test did**, or on counts or order.
- **Users other than the administrator sign in through the browser** where the subject needs it
  (`lib/console-user.ts`, `lib/browser-sign-in.ts`), always from an empty browser state: inside a test,
  `browser.newContext()` starts from the test's options, which carry the administrator's session.
- **Each worker signs the administrator in for itself**, in a browser of its own (`lib/fixtures.ts`).
  Every browser context is a device of its own through its own cookies, so no sign-in ends another
  worker's session. A run signs the administrator in about fourteen times, and the rate-limits suite
  once, under the seeded cap of 20 sessions per user, and the sessions the cap ends are the least
  recently used, those earlier runs left.
- **It imports `test` from `lib/fixtures.ts`**, whose watcher fails a test in which a page of the auth
  server or the admin console reported a Content-Security-Policy violation, such as an inline script
  or an `eval` the servers' `script-src 'self'` refused, in any browser context the test or a helper
  opens with `browser.newContext()`. The failure names the page, the directive and what was blocked.
  Pages of the test app and Mailpit are not watched. `tests/csp-violations.spec.ts` checks the watcher
  against pages of its own and needs no environment:
  `npx playwright test tests/csp-violations.spec.ts --project chromium --no-deps`.

## The VPS

It is shared with other services, so the scripts touch only what is theirs: the Compose project in
`/root/goiabada-e2e`, the test app's image (`goiabada-e2e-testapp:local`, labelled
`goiabada-e2e=testapp`), the servers' images a `--source` build makes (labelled `goiabada-e2e=server`),
`/etc/nginx/conf.d/goiabada-e2e.conf`, and the certificate `e2e.goiabada.dev`. It needs Docker with the Compose plugin, nginx with certbot's
`options-ssl-nginx.conf`, and certbot with a registered account, and ports 9090 to 9093 and 18025 free on
127.0.0.1.

## Mail

The Compose project runs Mailpit beside the two servers (`mailpit.yml`, which the project's `.env`
adds to the wizard's files through `COMPOSE_FILE`, so the wizard's own files stay as it wrote them).
The auth server sends to it as `mailpit:1025`, which the setup step configures under Settings - Email
as part of the baseline every run starts from. Its web UI and API listen on the VPS's loopback, port
18025, and nowhere else: `e2e/test.sh` opens an SSH tunnel to it for the run and passes its address to
the tests in `E2E_MAILPIT_URL` (`lib/mailpit.ts`). To look at the mail yourself:
`ssh -L 8025:127.0.0.1:18025 root@<vps>` and open http://localhost:8025.

## Test app

`testapp/` is the Next.js app that follows the guides (see [testapp/README.md](testapp/README.md)).
`infra/testapp.sh`, which `prepare.sh` runs, puts it in the environment:

1. It sets up the app's clients and API through the admin console, as the guides tell a person to:
   `playwright/provision/testapp.provision.ts`, run with its own config (`provision.config.ts`), so the
   suite never runs it. It removes the `testapp-*` clients and the `product-api` resource first, so
   they always end up the same, and writes the secrets to `e2e/.state/testapp.env`.
2. It builds the app's image on the VPS from the source in `testapp/`, and runs it in the Compose
   project twice (`testapp.yml`, added to `COMPOSE_FILE` like `mailpit.yml`): `testapp1` for
   `e2e-webtest1` on 127.0.0.1:9092 and `testapp2` for `e2e-webtest2` on 9093, behind nginx. The
   secrets reach the containers through `testapp.env` beside the Compose files, and go nowhere else.

After changing the app, `e2e/infra/testapp.sh --deploy-only` builds and deploys it again with the
same clients; with no option it sets the clients up again too.

The tests in `playwright/tests/testapp/` drive the app's pages as its user would (`lib/testapp.ts`), with
users of their own from the `users` fixture, granted `product-api:read` where a test needs the API.
They never change the `testapp-*` clients or `product-api`: every test signs in through them at once,
and the setup step doesn't sweep them, since they aren't named with the test prefix. A test that needs
a client set up differently creates its own.
