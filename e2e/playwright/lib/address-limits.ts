// The two budgets counted by this machine's address that the rate-limit tests spend to the end
// (tests/oauth/*.system.ts): 120 requests a minute to the authorization endpoint, and 120 password
// grants a minute. Every other test spends them too, so whatever spends one again after such a test, a
// later test or the next run, needs it back whole. Rather than each of those tests waiting its window
// out before it ends, it records here when it spent the budget, and whatever needs it next waits only
// for what is left, so the wait overlaps the tests between. Kept in e2e/.state, so a worker started
// again after a failure, and the next run's setup step, read it too.
import { readFileSync, writeFileSync } from "node:fs";
import { test } from "@playwright/test";
import { addressLimitsFile } from "./paths";

export type AddressLimit = "authorization endpoint" | "password grant";

// The limiter weighs the previous minute's count into the current one, so a request weighs on the
// address for up to two minutes; past that and a margin, none of it is left.
const clearedAfterMs = 125_000;

function recorded(): Partial<Record<AddressLimit, number>> {
  try {
    return JSON.parse(readFileSync(addressLimitsFile, "utf8"));
  } catch {
    return {};
  }
}

// Records that a request spending this budget was just answered, admitted or refused.
export function spent(limit: AddressLimit) {
  writeFileSync(addressLimitsFile, JSON.stringify({ ...recorded(), [limit]: Date.now() }));
}

// Waits until no spending recorded against these budgets weighs on the address any more. The running
// test's timeout grows by that wait.
export async function untilCleared(...limits: AddressLimit[]) {
  const last = recorded();
  const waitMs = Math.max(0, ...limits.map((limit) => (last[limit] ?? 0) + clearedAfterMs - Date.now()));
  if (waitMs === 0) return;
  const info = test.info();
  info.setTimeout(info.timeout + waitMs);
  info.annotations.push({ type: "address limits", description: `waited ${Math.round(waitMs / 1000)}s for ${limits.join(" and ")} to clear` });
  await new Promise((resolve) => setTimeout(resolve, waitMs));
}
