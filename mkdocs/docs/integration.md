# Integration

To integrate Goiabada with your app, you'll need to explore your platform for an **OAuth2/OpenID Connect client library**. Most of platforms provide such libraries for integration.

## Javascript-only

The github repository of Goiabada has a browser-based javascript [test client](https://github.com/leodip/goiabada/tree/main/test-integrations/js-only) that you can use to test Goiabada. It uses the [oauth4webapi](https://github.com/panva/oauth4webapi) library.

## Go web app

We also have a sample integration using Go. Have a look [here](https://github.com/leodip/goiabada/tree/main/test-integrations/go-webapp).

## React SPA with Vite and NodeJS server

Take a look at this [sample react application](https://github.com/leodip/goiabada/tree/main/test-integrations/react-vite) that uses authentication and role (group) based authorization, with token auto-refresh.