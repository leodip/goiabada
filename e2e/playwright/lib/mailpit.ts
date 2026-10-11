// The mail the auth server sends, as Mailpit caught it on the VPS. e2e/test.sh opens the SSH tunnel
// to Mailpit's API and passes its address in E2E_MAILPIT_URL.
import { expect, type APIRequestContext } from "@playwright/test";

export interface Mail {
  id: string;
  subject: string;
  text: string;
  html: string;
}

function mailpitUrl(): string {
  const url = process.env.E2E_MAILPIT_URL;
  if (!url) throw new Error("E2E_MAILPIT_URL is not set: run the suite with e2e/test.sh, which opens the tunnel to Mailpit");
  return url;
}

// The messages sent to an address, newest first.
export async function mailTo(request: APIRequestContext, address: string): Promise<{ ID: string; Subject: string }[]> {
  const response = await request.get(`${mailpitUrl()}/api/v1/search`, { params: { query: `to:"${address}"` } });
  expect(response.ok(), await response.text()).toBe(true);
  return ((await response.json()) as { messages: { ID: string; Subject: string }[] }).messages;
}

// Waits for the count-th message to an address (the first by default) and returns it. The auth
// server sends some mail after it has answered the request, so the message can take a moment.
export async function waitForMail(request: APIRequestContext, address: string, count = 1): Promise<Mail> {
  let messages: { ID: string; Subject: string }[] = [];
  await expect
    .poll(async () => (messages = await mailTo(request, address)).length, { message: `mail to ${address}`, timeout: 30_000 })
    .toBeGreaterThanOrEqual(count);
  // Newest first: the count-th message sent is at this index.
  const summary = messages[messages.length - count];
  const message = (await (await request.get(`${mailpitUrl()}/api/v1/message/${summary.ID}`)).json()) as {
    Subject: string;
    Text: string;
    HTML: string;
  };
  return { id: summary.ID, subject: message.Subject, text: message.Text, html: message.HTML };
}

// The links in a message's text, in order.
export function linksIn(mail: Mail): string[] {
  return [...(mail.text + "\n" + mail.html).matchAll(/https?:\/\/[^\s"'<>]+/g)].map((m) => m[0].replace(/&amp;/g, "&"));
}
