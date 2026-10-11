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
| `/api/products` | (the API) | Protect an API: checks the token, answers 401 or 403 |

It moved here from its own repository. The e2e environment (see [../README.md](../README.md)) does not
deploy it yet, so the clients below are still set up by hand.

## Set up the clients

Each step is the guide's own, so doing them is part of the check. Sign in to
https://e2e-admin.goiabada.dev as `admin@goiabada.dev`, with the password in `e2e/.state/admin-password`,
which `e2e/infra/prepare.sh` wrote.

For local runs, add the `http://localhost:3000/...` addresses beside the `https://` ones.

1. **The API** (Protect an API, steps 1 to 3). Under **Admin**, **Resources and permissions**,
   create `product-api`, give it the permissions `read` and `write`, and give `product-api:read`
   to your user, on the user's **Permissions** tab.
2. **`testapp-web`** (Add sign-in to a web app, steps 1 and 2, and Sign users out, step 2).
   Create it, leaving **Authorization code flow with PKCE** on. Redirect URIs:
   `https://e2e-webtest1.goiabada.dev/web/callback` and
   `https://e2e-webtest1.goiabada.dev/web/signed-out`. Copy its secret to `WEB_CLIENT_SECRET`.
3. **`testapp-web2`**: the same, with `/web2/callback` and `/web2/signed-out`. Its secret goes to
   `WEB2_CLIENT_SECRET`.
4. **`testapp-spa`** (Add sign-in to a SPA or mobile app, steps 1 to 4). Create it with
   **Authorization code flow with PKCE** on, choose **Public client** on **Authentication** and confirm with **Yes**, add
   the redirect URI `https://e2e-webtest1.goiabada.dev/spa`, and the web origin
   `https://e2e-webtest1.goiabada.dev`.
5. **`testapp-service`** (Protect an API, "Let a service call your API", steps 1 and 2). Create
   it with **Client credentials flow** on and **Authorization code flow with PKCE** off, grant it `product-api` `read` on **Permissions**, and
   copy its secret to `SERVICE_CLIENT_SECRET`.

## Configure and run

```bash
cp .env.example .env.local   # then fill in the secrets
npm run dev                  # http://localhost:3000
```
