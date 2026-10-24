// The rate-limits suite's test object: the suite's fixtures, and before every test a restart of the
// auth server (e2e/infra/rate-limiter.sh reset). The limiter keeps the counts of an address in memory,
// so the restart empties them: each test starts from whole budgets, whatever another test or an
// earlier run spent, and no test waits for a window to pass.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { test as base } from "./fixtures";
import { rateLimiterScript } from "./paths";

export { expect, type TestUser } from "./fixtures";

const run = promisify(execFile);

export const test = base.extend<{ wholeBudgets: void }>({
  // After the worker's administrator has signed in, whose sign-in would spend from the budgets.
  wholeBudgets: [
    async ({ adminSession }, use) => {
      void adminSession;
      await run(rateLimiterScript, ["reset"], { timeout: 90_000 });
      await use();
    },
    { auto: true },
  ],
});
