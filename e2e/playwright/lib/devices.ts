import { devices } from "@playwright/test";

// A user agent of its own for each browser that signs the administrator in. Goiabada treats a sign-in
// from the same user agent and address as the same device and ends that user's earlier session there,
// so parallel workers sharing Chrome's user agent from one machine would end each other's sessions.
export function userAgentFor(tag: string): string {
  return `${devices["Desktop Chrome"].userAgent} goiabada-e2e/${tag}`;
}
