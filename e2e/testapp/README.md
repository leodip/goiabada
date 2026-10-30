# Goiabada test app

A small Next.js app that follows the Goiabada guides, one page each, against a real auth server.
It's for checking that the docs hold up, so it does exactly what each guide says and shows the raw
claims and answers.

| Page | Client | Guides |
|---|---|---|
| `/web` | `testapp-web`, confidential | Add sign-in to a web app, Sign users out, Require two-factor authentication |
| `/web2` | `testapp-web2`, confidential | Single sign-on across clients |
| `/spa` | `testapp-spa`, public | Add sign-in to a SPA or mobile app |
| `/service` | `testapp-service`, client credentials | Protect an API |
| `/api/products` | `testapp-api`, confidential, introspects | Protect an API: checks and introspects the token, answers 401 or 403 |

The e2e environment (see [../README.md](../README.md)) deploys it on its two test app hosts:
`e2e/infra/testapp.sh` sets up the clients below through the admin console, the way these steps say,
and builds and runs the app on the VPS. The second web app runs on the second host,
`https://e2e-webtest2.goiabada.dev/web2`, so single sign-on is tried across two sites.

## Set up the clients by hand

For running the app on your own machine against an auth server. Each step is the guide's own, so
doing them is part of the check. Against the e2e environment, sign in to
https://e2e-admin.goiabada.dev as `admin@goiabada.dev`, with the password in `e2e/.state/admin-password`,
which `e2e/infra/prepare.sh` wrote, and add the `http://localhost:3000/...` addresses beside the
`https://` ones `testapp.sh` registered.

1. **The API** (Protect an API, steps 1 to 3). Under **Admin**, **Resources and permissions**,
   create `product-api`, give it the permissions `read` and `write`, and give `product-api:read`
   to your user, on the user's **Permissions** tab.
2. **`testapp-web`** (Add sign-in to a web app, steps 1 and 2, and Sign users out, step 2).
   Create it, leaving **Authorization code flow with PKCE** on. Redirect URIs:
   `https://e2e-webtest1.goiabada.dev/web/callback` and
   `https://e2e-webtest1.goiabada.dev/web/signed-out`. Copy its secret to `WEB_CLIENT_SECRET`.
3. **`testapp-web2`**: the same, with `/web2/callback` and `/web2/signed-out` (on
   `https://e2e-webtest2.goiabada.dev` in the e2e environment). Its secret goes to
   `WEB2_CLIENT_SECRET`.
4. **`testapp-spa`** (Add sign-in to a SPA or mobile app, steps 1 to 4). Create it with
   **Authorization code flow with PKCE** on, choose **Public client** on **Authentication** and confirm with **Yes**, add
   the redirect URI `https://e2e-webtest1.goiabada.dev/spa`, and the web origin
   `https://e2e-webtest1.goiabada.dev`.
5. **`testapp-service`** (Protect an API, "Let a service call your API", steps 1 and 2). Create
   it with **Client credentials flow** on and **Authorization code flow with PKCE** off, grant it `product-api` `read` on **Permissions**, and
   copy its secret to `SERVICE_CLIENT_SECRET`.
6. **`testapp-api`** (Protect an API, "Ask the auth server about a token", steps 1 and 2). Create
   it with **Authorization code flow with PKCE** on, choose `product-api` on its **Introspection**
   tab, click **Add resource** and **Save**, and copy its secret to `API_CLIENT_SECRET`.

## Configure and run

```bash
cp .env.example .env.local   # then fill in the secrets
npm run dev                  # http://localhost:3000
```
