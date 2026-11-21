// The environment the helpers drive. For the suites it is the one prepare.sh built:
// e2e/.state/environment.env and e2e/.state/admin-password. The screenshot command
// (e2e/screenshots.sh) starts servers of its own and never reads e2e/.state: it sets
// E2E_ENVIRONMENT=process and gives the same names in the process's environment, the admin password
// as E2E_ADMIN_PASSWORD.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const stateDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../.state");
const fromProcess = process.env.E2E_ENVIRONMENT === "process";

function readState(file: string): string {
  try {
    return readFileSync(path.join(stateDir, file), "utf8");
  } catch {
    throw new Error(`no e2e/.state/${file}: run e2e/infra/prepare.sh <tag> first`);
  }
}

const values: Record<string, string | undefined> = fromProcess
  ? process.env
  : Object.fromEntries(
      readState("environment.env")
        .split("\n")
        .filter((line) => line.includes("="))
        .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
    );

function value(name: string): string {
  const v = values[name];
  if (!v) throw new Error(fromProcess ? `E2E_ENVIRONMENT=process, and the process has no ${name}` : `e2e/.state/environment.env has no ${name}`);
  return v;
}

export const env = {
  tag: value("E2E_TAG"),
  authUrl: value("E2E_AUTH_URL"),
  adminUrl: value("E2E_ADMIN_URL"),
  webtest1Url: value("E2E_WEBTEST1_URL"),
  webtest2Url: value("E2E_WEBTEST2_URL"),
  adminEmail: value("E2E_ADMIN_EMAIL"),
  adminPassword: fromProcess ? value("E2E_ADMIN_PASSWORD") : readState("admin-password").trim(),
};
