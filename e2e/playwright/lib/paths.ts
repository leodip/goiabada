import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));

// A signed-in administrator's browser state, one file per parallel worker (lib/fixtures.ts). Under
// e2e/.state, which is gitignored, beside the password it was made with.
export function adminStorageState(worker: number | "setup"): string {
  return path.resolve(here, `../../.state/admin-storage-state-${worker}.json`);
}

// The test app's client secrets, as e2e/infra/testapp.sh hands them to the test app on the VPS.
export const testappEnvFile = path.resolve(here, "../../.state/testapp.env");

// Switches the auth server's rate limiter, and restarts the auth server for the rate-limits suite
// (lib/rate-limits.ts).
export const rateLimiterScript = path.resolve(here, "../../infra/rate-limiter.sh");

// Switches the auth server's brand safe mode, GOIABADA_AUTHSERVER_BRAND_SAFE_MODE, for the system test
// of the switch (tests/admin-console/branding/safe-mode-switch.system.ts).
export const safeModeScript = path.resolve(here, "../../infra/safe-mode.sh");
