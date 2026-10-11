// The environment prepare.sh built: e2e/.state/environment.env and e2e/.state/admin-password.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const stateDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../.state");

function readState(file: string): string {
  try {
    return readFileSync(path.join(stateDir, file), "utf8");
  } catch {
    throw new Error(`no e2e/.state/${file}: run e2e/infra/prepare.sh <tag> first`);
  }
}

const values = Object.fromEntries(
  readState("environment.env")
    .split("\n")
    .filter((line) => line.includes("="))
    .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
);

function value(name: string): string {
  const v = values[name];
  if (!v) throw new Error(`e2e/.state/environment.env has no ${name}`);
  return v;
}

export const env = {
  tag: value("E2E_TAG"),
  authUrl: value("E2E_AUTH_URL"),
  adminUrl: value("E2E_ADMIN_URL"),
  webtest1Url: value("E2E_WEBTEST1_URL"),
  webtest2Url: value("E2E_WEBTEST2_URL"),
  adminEmail: value("E2E_ADMIN_EMAIL"),
  // Whether the wizard switched the rate limiter on, as it is unless e2e/.env says otherwise.
  rateLimiter: values.E2E_RATE_LIMITER !== "false",
  adminPassword: readState("admin-password").trim(),
};
