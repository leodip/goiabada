# Integration

To integrate Goiabada with your app, you'll need to explore your platform for an **OAuth2/OpenID Connect client library**. Most platforms provide such libraries for integration.

## Sample Integrations

### Javascript-only

The github repository of Goiabada has a browser-based javascript [test client](https://github.com/leodip/goiabada/tree/main/test-integrations/js-only) that you can use to test Goiabada. It uses the [oauth4webapi](https://github.com/panva/oauth4webapi) library.

### Go web app

We also have a sample integration using Go. Have a look [here](https://github.com/leodip/goiabada/tree/main/test-integrations/go-webapp).

### React SPA with Vite and NodeJS server

Take a look at this [sample react application](https://github.com/leodip/goiabada/tree/main/test-integrations/react-vite) that uses authentication and role (group) based authorization, with token auto-refresh.

## Configuration Guidelines

When configuring your OAuth2/OpenID Connect client to work with Goiabada, you'll typically need:

1. **Client ID** and **Client Secret** (from Goiabada admin console)
2. **Issuer URL** (normally the auth server base URL) - Configured in the Goiabada admin console (e.g., `https://auth.example.com`)
3. **Authorization Endpoint** - `<auth-server-base-url>/auth/authorize`
4. **Token Endpoint** - `<auth-server-base-url>/auth/token`
5. **UserInfo Endpoint** - `<auth-server-base-url>/auth/userinfo`
6. **JWKS URI** - `<auth-server-base-url>/.well-known/jwks.json`
7. **End Session Endpoint** - `<auth-server-base-url>/auth/logout`

Most libraries support automatic configuration via the **OpenID Connect Discovery** endpoint at `<auth-server-base-url>/.well-known/openid-configuration`.