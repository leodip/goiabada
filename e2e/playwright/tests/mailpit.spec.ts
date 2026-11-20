// The suite's mail wait (lib/mailpit.ts), against a Mailpit of its own: a server on this machine whose
// every read answers, hangs or drops the connection as the test scripts it, as reads through a tunnel
// whose connection died do. Needs no environment.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { expect, test as base } from "@playwright/test";
import { mailTo, waitForMail, waitForSubject } from "../lib/mailpit";

// One read's answer: JSON with a status, given after a delay of after milliseconds if set, no answer at
// all, or the connection closed under it.
type Reply = { status: number; body: unknown; after?: number };
type Answer = Reply | "hang" | "drop";

// What the stub was asked: each search's query and each message's ID, in order.
interface Asked {
  searches: string[];
  messages: string[];
}

const address = "someone@example.com";
const found = (...messages: { ID: string; Subject: string }[]): Reply => ({ status: 200, body: { messages } });
const message = (subject: string): Reply => ({ status: 200, body: { Subject: subject, Text: `${subject} text`, HTML: "" } });

// Starts a stub Mailpit and points the mail wait at it, for the test. Each read takes the next answer
// of its kind, and the last answer repeats.
const test = base.extend<{ mailpit: (searches: Answer[], messages?: Answer[]) => Promise<Asked> }>({
  mailpit: async ({}, use) => {
    const servers: http.Server[] = [];
    // A worker runs one test at a time, so the address e2e/test.sh set is put back before the next.
    const before = process.env.E2E_MAILPIT_URL;
    await use(async (searches, messages = [message("unused")]) => {
      const asked: Asked = { searches: [], messages: [] };
      const next = (queue: Answer[]) => (queue.length > 1 ? queue.shift()! : queue[0]);
      const server = http.createServer((req, res) => {
        const url = new URL(req.url ?? "/", "http://stub");
        let answer: Answer = { status: 404, body: {} };
        if (url.pathname === "/api/v1/search") {
          asked.searches.push(url.searchParams.get("query") ?? "");
          answer = next(searches);
        } else if (url.pathname.startsWith("/api/v1/message/")) {
          asked.messages.push(url.pathname.slice("/api/v1/message/".length));
          answer = next(messages);
        }
        if (answer === "hang") return;
        if (answer === "drop") {
          req.socket.destroy();
          return;
        }
        const reply = answer;
        setTimeout(() => {
          res.writeHead(reply.status, { "Content-Type": "application/json" });
          res.end(JSON.stringify(reply.body));
        }, reply.after ?? 0);
      });
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      servers.push(server);
      process.env.E2E_MAILPIT_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      return asked;
    });
    if (before === undefined) delete process.env.E2E_MAILPIT_URL;
    else process.env.E2E_MAILPIT_URL = before;
    for (const server of servers) {
      // A hung read holds its connection open, and close waits for every connection.
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
});

test("a search and a message read that get no answer, or lose their connection, are read again, and the wait returns the message", async ({
  mailpit,
  request,
}) => {
  const asked = await mailpit(["hang", "drop", found(), found({ ID: "m1", Subject: "Welcome" })], ["hang", message("Welcome")]);
  const started = Date.now();

  const mail = await waitForMail(request, address);

  expect(mail).toEqual({ id: "m1", subject: "Welcome", text: "Welcome text", html: "" });
  // The four scripted searches, and one more after the message's first read went unanswered: each try
  // starts from the search.
  expect(asked.searches).toEqual(Array(5).fill(`to:"${address}"`));
  expect(asked.messages).toEqual(["m1", "m1"]);
  // Two reads of five seconds went unanswered; neither took the whole 30-second wait with it.
  expect(Date.now() - started).toBeLessThan(20_000);
});

test("a wait whose reads Mailpit never answers ends after 30 seconds, saying its last read failed", async ({ mailpit, request }) => {
  await mailpit(["hang"]);
  const started = Date.now();

  const error = await waitForMail(request, address).catch((e: Error) => e);

  expect(error).toBeInstanceOf(Error);
  expect((error as Error).message).toMatch(
    /^mail to someone@example\.com: not found within 30s\. The last read failed: Mailpit at http:\/\/127\.0\.0\.1:\d+ did not answer \/api\/v1\/search: .*Timeout 5000ms exceeded/,
  );
  // At most the last read, started before 30 seconds were up, runs past them.
  const elapsed = Date.now() - started;
  expect(elapsed).toBeGreaterThanOrEqual(30_000);
  expect(elapsed).toBeLessThan(36_000);
});

test("a wait that Mailpit answers without the message ends after 30 seconds, naming what Mailpit holds for the address", async ({
  mailpit,
  request,
}) => {
  await mailpit(["drop", found({ ID: "m1", Subject: "Welcome" })]);

  const error = await waitForMail(request, address, 2).catch((e: Error) => e);

  expect((error as Error).message).toBe(
    'message 2 to someone@example.com: not found within 30s. Mailpit answered, holding 1 ("Welcome") for the address',
  );
});

// Five searches Mailpit does not answer, and the pauses after them, take a wait some 27.5 seconds in.
const fiveUnanswered: Answer[] = ["hang", "hang", "hang", "hang", "hang"];

test("no search starts once the 30 seconds are up, even when the one before answered with less than a pause left", async ({
  mailpit,
  request,
}) => {
  // The sixth search answers some 29.5 seconds in, and the pause before a seventh would be a second.
  const asked = await mailpit([...fiveUnanswered, { ...found(), after: 2_000 }]);

  const error = await waitForMail(request, address).catch((e: Error) => e);

  expect((error as Error).message).toBe("mail to someone@example.com: not found within 30s. Mailpit answered, holding no message for the address");
  expect(asked.searches).toHaveLength(6);
});

test("a search that lists the message only after the 30 seconds are up ends the wait without reading the message, saying so", async ({
  mailpit,
  request,
}) => {
  // The sixth search starts some 27.5 seconds in and answers four seconds later.
  const asked = await mailpit([...fiveUnanswered, { ...found({ ID: "m1", Subject: "Welcome" }), after: 4_000 }], [message("Welcome")]);

  const error = await waitForMail(request, address).catch((e: Error) => e);

  expect((error as Error).message).toBe(
    "mail to someone@example.com: not found within 30s. The search that listed it answered after the wait was over",
  );
  expect(asked.searches).toHaveLength(6);
  expect(asked.messages).toEqual([]);
});

test("waitForMail counts from the oldest message, and waitForSubject takes the newest with the subject", async ({ mailpit, request }) => {
  // Newest first, as Mailpit lists them.
  const listed = found({ ID: "m3", Subject: "Reset" }, { ID: "m2", Subject: "Welcome" }, { ID: "m1", Subject: "Welcome" });
  const asked = await mailpit([listed], [message("Welcome"), message("Welcome"), message("Reset")]);

  expect((await waitForMail(request, address)).id).toBe("m1");
  expect((await waitForSubject(request, address, "Welcome")).id).toBe("m2");
  expect((await waitForMail(request, address, 3)).id).toBe("m3");
  expect(asked.messages).toEqual(["m1", "m2", "m3"]);
});

test("mailTo reads once: a read Mailpit does not answer fails within five seconds, saying so", async ({ mailpit, request }) => {
  await mailpit(["hang"]);
  const started = Date.now();

  await expect(mailTo(request, address)).rejects.toThrow(/^Mailpit at http:\/\/127\.0\.0\.1:\d+ did not answer \/api\/v1\/search: /);
  expect(Date.now() - started).toBeLessThan(7_000);
});
