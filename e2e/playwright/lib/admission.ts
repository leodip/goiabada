// The authorization endpoint's admission budget (#504): one client address may make 120 requests a
// minute to /auth/authorize, and the whole suite signs in from one address, four tests at a time, so a
// busy minute can spend it. A request the budget refuses is answered 429 with Retry-After and spends
// nothing, and the limiter's window slides, so the address is admitted again within that wait: the
// helpers that send a request there ask again until it is admitted, as a person would, rather than
// failing a test over what the tests beside it spent. The test that measures the budget sends its own
// requests and reads its 429s itself (tests/oauth/authorize-admission.system.ts).
import { test } from "@playwright/test";

// How often a refused request is sent again.
const pollMs = 5_000;
// Past the Retry-After the refusal carries, the margin before giving up.
const marginMs = 30_000;

// Sends one request to the authorization endpoint with send, and sends it again while it is answered
// 429, until the Retry-After it carries, and a margin, have passed. The test's timeout grows by that
// wait, so a test that met the budget is not ended by it. The last answer is returned, a 429 included,
// for the caller's assertions to report.
export async function admitted<T>(send: () => Promise<T>, read: (answer: T) => { status: number; retryAfter?: string }): Promise<T> {
  let answer = await send();
  const first = read(answer);
  if (first.status !== 429) return answer;

  const waitMs = (Number(first.retryAfter) || 60) * 1000 + marginMs;
  const info = test.info();
  info.setTimeout(info.timeout + waitMs);
  info.annotations.push({ type: "authorize budget", description: `refused with 429, asked again for up to ${waitMs / 1000}s` });
  const deadline = Date.now() + waitMs;
  let status = first.status;
  while (status === 429 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    answer = await send();
    status = read(answer).status;
  }
  return answer;
}

// What admitted reads from a Playwright answer, an API request's or a page navigation's.
export function answerOf(response: { status(): number; headers(): Record<string, string> } | null) {
  return { status: response?.status() ?? 0, retryAfter: response?.headers()["retry-after"] };
}
