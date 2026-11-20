// The mail the auth server sends, as Mailpit caught it on the VPS. e2e/test.sh keeps an SSH tunnel to
// Mailpit's API open for the run and passes its address in E2E_MAILPIT_URL.
import type { APIRequestContext } from "@playwright/test";

export interface Mail {
  id: string;
  subject: string;
  text: string;
  html: string;
}

// A message as Mailpit's search lists it.
export interface MailSummary {
  ID: string;
  Subject: string;
}

// How long one read of Mailpit may take. A tunnel whose connection has died still accepts a request and
// never answers it, so an unbounded read would take the whole wait with it. Mailpit answers through a
// working tunnel in well under a second.
const readTimeout = 5_000;
// How long a wait for mail goes on reading. The auth server sends some mail after it has answered the
// request, so a message can take a moment.
const mailWait = 30_000;

function mailpitUrl(): string {
  const url = process.env.E2E_MAILPIT_URL;
  if (!url) throw new Error("E2E_MAILPIT_URL is not set: run the suite with e2e/test.sh, which opens the tunnel to Mailpit");
  return url;
}

// One read of Mailpit's API, as JSON, given readTimeout. A read Mailpit does not answer, or answers
// with an error, throws an error that says so.
async function readMailpit<T>(request: APIRequestContext, path: string, params: Record<string, string> = {}): Promise<T> {
  const url = mailpitUrl();
  let response;
  try {
    response = await request.get(`${url}${path}`, { params, timeout: readTimeout });
  } catch (error) {
    // Playwright's message goes on with the call log, line by line.
    const reason = (error as Error).message.split("\n")[0];
    throw new Error(`Mailpit at ${url} did not answer ${path}: ${reason}`, { cause: error });
  }
  if (!response.ok()) throw new Error(`Mailpit at ${url} answered ${path} with ${response.status()}: ${await response.text()}`);
  return (await response.json()) as T;
}

// The messages sent to an address, newest first, from one read of Mailpit, which throws when the read
// fails. To wait for a message, use waitForMail or waitForSubject: they try a failed read again.
export async function mailTo(request: APIRequestContext, address: string): Promise<MailSummary[]> {
  return (await readMailpit<{ messages: MailSummary[] }>(request, "/api/v1/search", { query: `to:"${address}"` })).messages;
}

// Waits for the count-th message to an address (the first by default) and returns it.
export async function waitForMail(request: APIRequestContext, address: string, count = 1): Promise<Mail> {
  const wanted = count === 1 ? `mail to ${address}` : `message ${count} to ${address}`;
  // Newest first: the count-th message sent is at this index.
  return waitFor(request, address, wanted, (messages) => (messages.length >= count ? messages[messages.length - count] : undefined));
}

// Waits for a message to an address with this subject and returns it, the newest if there are several.
export async function waitForSubject(request: APIRequestContext, address: string, subject: string): Promise<Mail> {
  return waitFor(request, address, `mail "${subject}" to ${address}`, (messages) => messages.find((m) => m.Subject === subject));
}

// Reads Mailpit until pick finds the message among those sent to the address, newest first, and
// returns it whole. A read that fails is tried again rather than ending the wait, so a tunnel that
// dropped and was opened again (e2e/test.sh) costs the wait only the time it was down. No read starts
// once the wait is over, and one already started gets its full time, so a wait that ends says what its
// last read found: that Mailpit did not answer, what Mailpit held for the address, or that the search
// listing the message answered only after the wait was over.
async function waitFor(
  request: APIRequestContext,
  address: string,
  wanted: string,
  pick: (messages: MailSummary[]) => MailSummary | undefined,
): Promise<Mail> {
  const deadline = Date.now() + mailWait;
  const waited = `${wanted}: not found within ${mailWait / 1000}s`;
  let subjects: string[] = [];
  let failure: Error | undefined;
  for (let pause = 100; Date.now() < deadline; pause = Math.min(pause * 2, 1_000)) {
    let summary: MailSummary | undefined;
    try {
      const messages = await mailTo(request, address);
      subjects = messages.map((m) => m.Subject);
      failure = undefined;
      summary = pick(messages);
    } catch (error) {
      failure = error as Error;
    }
    if (summary) {
      if (Date.now() >= deadline) throw new Error(`${waited}. The search that listed it answered after the wait was over`);
      try {
        const message = await readMailpit<{ Subject: string; Text: string; HTML: string }>(request, `/api/v1/message/${summary.ID}`);
        return { id: summary.ID, subject: message.Subject, text: message.Text, html: message.HTML };
      } catch (error) {
        failure = error as Error;
      }
    }
    const remaining = deadline - Date.now();
    if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, Math.min(pause, remaining)));
  }
  if (failure) throw new Error(`${waited}. The last read failed: ${failure.message}`, { cause: failure });
  const held = subjects.length === 0 ? "no message" : `${subjects.length} (${subjects.map((s) => JSON.stringify(s)).join(", ")})`;
  throw new Error(`${waited}. Mailpit answered, holding ${held} for the address`);
}

// The links in a message's text, in order.
export function linksIn(mail: Mail): string[] {
  return [...(mail.text + "\n" + mail.html).matchAll(/https?:\/\/[^\s"'<>]+/g)].map((m) => m[0].replace(/&amp;/g, "&"));
}
