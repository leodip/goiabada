# End-to-end environment

A real Goiabada deployment, built from a release tag on a VPS, for browser tests to run against.
It builds the environment, deploys the test app beside it, checks that both are reachable, and runs
the Playwright suite against them.

| Host | What |
|---|---|
| `e2e-auth.goiabada.dev` | Auth server |
| `e2e-admin.goiabada.dev` | Admin console |
| `e2e-webtest1.goiabada.dev` | The test app (`testapp/`): the web app, the SPA, the service and the API |
| `e2e-webtest2.goiabada.dev` | The test app again, for its second web app: single sign-on across two sites |

The deployment is the docs' [Reverse proxy](https://goiabada.dev/deploy/reverse-proxy/) method, as a
user would follow it: the release's own setup wizard writes the Compose files (production, PostgreSQL),
nginx on the VPS terminates TLS with a Let's Encrypt certificate, and the DNS records are DNS only.

## Run it

From the repository root, on a machine with an SSH key the VPS accepts:

```bash
cp e2e/.env.example e2e/.env    # once: set E2E_VPS_HOST

e2e/run.sh [tag]                # everything from scratch: reset, then the whole suite
e2e/reset.sh [tag]              # wipe the environment and build it again from a release
e2e/test.sh [playwright args]   # run the suite against the current environment
e2e/wipe.sh [--all] [-y]        # remove the environment (asks first)
```

With no tag, `run.sh` and `reset.sh` take the latest GitHub release. `test.sh` installs the suite's
packages and Chromium the first time, and passes its arguments to Playwright: `--headed`, `--ui`, or
a folder such as `tests/admin-console`. Each script answers `--help`.

They wrap the scripts in `infra/`, which can also be run on their own: `prepare.sh <tag>`,
`verify.sh [tag]` (check the environment again at any time) and `teardown.sh [--all]`.

`prepare.sh`:

1. Checks the release exists, the VPS answers over SSH, and each host's DNS reaches the VPS.
2. Generates the admin password into `e2e/.state/admin-password`.
3. On the VPS (`remote-prepare.sh`): removes the previous environment and its volumes, downloads
   the release's `goiabada-setup` and checks it against the release's `checksums.txt`, runs it, starts
   the stack, waits for both servers, and writes `/etc/nginx/conf.d/goiabada-e2e.conf` from
   `nginx.conf.template`. The certificate is requested only when it is missing or does not cover the
   four hosts.
4. Writes `e2e/.state/environment.env` (URLs, tag, admin email).
5. Sets up the test app with `testapp.sh` (see [Test app](#test-app)).
6. Runs `verify.sh`.

`verify.sh` checks DNS, HTTPS and its certificate's expiry, the HTTP-to-HTTPS redirect, that the VPS
runs the tag's images, the auth server's health, discovery and JWKS, the admin console's page, that its
sign-in lands on the auth server's password page, that the test app runs configured on both hosts,
and that its API refuses a request with no token.

## Browser tests

`playwright/` holds the Playwright suite. It reads the URLs and the admin password `prepare.sh` left in
`e2e/.state/`, so it runs against the environment this machine last prepared. `e2e/test.sh` runs it;
after a failure, `(cd e2e/playwright && npx playwright show-report)` opens the report with traces.

Tests sit under `playwright/tests/`, one folder per area (`admin-console/sign-in`,
`admin-console/clients/`, `resources/`, `groups/`, `users/`, `account/` and `settings/`). They run four at a time against an environment that stays up between
runs, so every test keeps to these rules, which is what lets the suite run again and again without a
reset:

- **It creates what it needs under a unique name** (`e2e-<kind>-<random>`, `lib/unique.ts`) through a
  fixture that removes it afterwards, pass or fail (`clients`, `resources`, `groups` and `users` in
  `lib/fixtures.ts`). The setup step (`tests/admin.setup.ts`) sweeps anything left with that prefix by
  a run that crashed.
- **It changes nothing global**: no settings, and the system client and the system resource
  (`authserver`) are only read; a test reaching their save answers No to the confirmation. The
  exceptions are the tests whose subject is global, the settings pages, the signing keys, and the
  guards around the system resource. They are named `*.system.ts` and run in the `system` project,
  which `playwright.config.ts` runs after every other test, on one worker. Each puts back what it
  changes (`lib/settings.ts`), and the setup step restores the seeded settings before a run if one
  failed to.
- **It never depends on what another test did**, or on counts or order.
- **Users other than the administrator sign in through the browser** where the subject needs it
  (`lib/console-user.ts`, `lib/browser-sign-in.ts`), always from an empty browser state: inside a test,
  `browser.newContext()` starts from the test's options, which carry the administrator's session.
- **The rate limits stay on.** The password form and the password grant each allow 30 requests a
  minute per address, and the suite can pass that; the helpers wait and retry, and mark the test in
  the report, rather than the environment turning the limits off.
- **Each worker signs the administrator in for itself, with a user agent of its own** (`lib/devices.ts`).
  Goiabada treats a sign-in from the same user agent and address as the same device and ends that
  user's earlier session there, so workers sharing one would sign each other out.

## The VPS

It is shared with other services, so the scripts touch only what is theirs: the Compose project in
`/root/goiabada-e2e`, the test app's image (`goiabada-e2e-testapp:local`, labelled
`goiabada-e2e=testapp`), `/etc/nginx/conf.d/goiabada-e2e.conf`, and the certificate `e2e.goiabada.dev`. It needs Docker with the Compose plugin, nginx with certbot's
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
same clients; with no option it sets the clients up again too. Tests must leave the `testapp-*`
clients and `product-api` as they found them: the setup step does not sweep them, since they are not
named with the test prefix.
