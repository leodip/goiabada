import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));

// A signed-in administrator's browser state, one file per parallel worker (lib/fixtures.ts). Under
// e2e/.state, which is gitignored, beside the password it was made with.
export function adminStorageState(worker: number | "setup"): string {
  return path.resolve(here, `../../.state/admin-storage-state-${worker}.json`);
}
