// The test app (e2e/testapp) as e2e/infra/testapp.sh deploys it: one container per test app host, and
// the clients and API it signs in with, set up by provision/testapp.provision.ts.
import { env } from "./environment";

export const testapp = {
  // The first host serves the web app, the SPA, the service and the API; the second the second web
  // app, so single sign-on is tried across two sites.
  web: { clientId: "testapp-web", url: `${env.webtest1Url}/web` },
  web2: { clientId: "testapp-web2", url: `${env.webtest2Url}/web2` },
  spa: { clientId: "testapp-spa", url: `${env.webtest1Url}/spa`, origin: env.webtest1Url },
  service: { clientId: "testapp-service", url: `${env.webtest1Url}/service` },
  api: { resource: "product-api", permissions: ["read", "write"], scope: "product-api:read", url: `${env.webtest1Url}/api/products` },
};
