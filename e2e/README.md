# End-to-end environment

A real Goiabada deployment, built from a release tag on a VPS, for browser tests to run against.
This is a proof of concept: it builds the environment, checks that it is reachable, and runs a first
Playwright test. Provisioning clients and users, and the scenarios, come next.

| Host | What |
|---|---|
| `e2e-auth.goiabada.dev` | Auth server |
| `e2e-admin.goiabada.dev` | Admin console |
| `e2e-webtest1.goiabada.dev` | Test app (a placeholder page for now) |
| `e2e-webtest2.goiabada.dev` | A second test app origin, for single sign-on across sites (a placeholder page for now) |

The deployment is the docs' [Reverse proxy](https://goiabada.dev/deploy/reverse-proxy/) method, as a
user would follow it: the release's own setup wizard writes the Compose files (production, PostgreSQL),
nginx on the VPS terminates TLS with a Let's Encrypt certificate, and the DNS records are DNS only.

## Run it

From your machine, with an SSH key the VPS accepts:

```bash
cp e2e/.env.example e2e/.env      # then set E2E_VPS_HOST
e2e/infra/prepare.sh v1.7.0       # build the environment from scratch, then verify it
e2e/infra/verify.sh               # check it again at any time
e2e/infra/teardown.sh [--all]     # remove it
```

`prepare.sh`:

1. Checks the release exists, the VPS answers over SSH, and each host's DNS reaches the VPS.
2. Generates the admin password into `e2e/.state/admin-password`.
3. On the VPS (`remote-prepare.sh`): removes the previous environment and its volumes, downloads
   the release's `goiabada-setup` and checks it against the release's `checksums.txt`, runs it, starts
   the stack, waits for both servers, and writes `/etc/nginx/conf.d/goiabada-e2e.conf` from
   `nginx.conf.template`. The certificate is requested only when it is missing or does not cover the
   four hosts.
4. Writes `e2e/.state/environment.env` (URLs, tag, admin email) and runs `verify.sh`.

`verify.sh` checks DNS, HTTPS and its certificate's expiry, the HTTP-to-HTTPS redirect, that the VPS
runs the tag's images, the auth server's health, discovery and JWKS, the admin console's page, that its
sign-in lands on the auth server's password page, and the test app hosts.

## Browser tests

`playwright/` holds the Playwright suite. It reads the URLs and the admin password `prepare.sh` left in
`e2e/.state/`, so prepare the environment first.

```bash
cd e2e/playwright
npm ci && npx playwright install chromium   # once
npx playwright test                         # headless; add --headed or --ui to watch
npx playwright show-report                  # the HTML report, with traces of failures
```

Tests sit under `playwright/tests/`, one folder per area (`admin-console/` so far).

## The VPS

It is shared with other services, so the scripts touch only what is theirs: the Compose project in
`/root/goiabada-e2e`, `/etc/nginx/conf.d/goiabada-e2e.conf`, `/var/www/goiabada-e2e`, and the
certificate `e2e.goiabada.dev`. It needs Docker with the Compose plugin, nginx with certbot's
`options-ssl-nginx.conf`, and certbot with a registered account, and ports 9090 and 9091 free on
127.0.0.1.

## Test app

`testapp/` is the Next.js app that follows the guides, moved here from its own repository. See
[testapp/README.md](testapp/README.md).
