import { randomBytes } from "node:crypto";

// Every name a test creates starts with this, so a run's leftovers can be told from anything else
// on the instance, and swept (see tests/admin.setup.ts).
export const testPrefix = "e2e-";

// A fresh identifier that passes Goiabada's identifier rule: a letter first, letters, digits and
// dashes, at most 38 characters.
export function uniqueIdentifier(kind: string): string {
  const suffix = randomBytes(6).toString("hex");
  return `${testPrefix}${kind}-${suffix}`;
}
