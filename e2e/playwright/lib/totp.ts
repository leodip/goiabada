// Time-based one-time passwords (RFC 6238) as an authenticator app computes them: HMAC-SHA1 over the
// 30-second step count, 6 digits, from the base32 secret the enrolment page shows.
import { createHmac } from "node:crypto";

function base32Decode(secret: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of secret.replace(/[\s=]/g, "").toUpperCase()) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error(`not base32: ${char}`);
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const hmac = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, "0");
}

// The last 30-second step a code was used in, per secret: Goiabada refuses a code used once already,
// so the next code a test sends must come from a later step.
const lastStep = new Map<string, number>();

// The seconds kept clear at each end of a 30-second step. The last ones can turn before the server
// checks a code. The first ones would send the next step's code from a runner whose clock runs a
// little ahead of the server's, and the server refuses that code as a clock running ahead (#142).
const stepMargin = 5;

// Waits until the runner's clock is at least stepMargin seconds from either end of a step, and
// returns that step.
async function untilMidStep(): Promise<number> {
  for (;;) {
    const now = Date.now() / 1000;
    const intoStep = now % 30;
    if (intoStep >= stepMargin && intoStep <= 30 - stepMargin) return Math.floor(now / 30);
    const wait = intoStep < stepMargin ? stepMargin - intoStep : 30 - intoStep + stepMargin;
    await new Promise((resolve) => setTimeout(resolve, (wait + 0.5) * 1000));
  }
}

// A code that will be accepted: from a step after the last one this secret's code was used in, and
// from the middle of a step (untilMidStep).
export async function freshTotp(secret: string): Promise<string> {
  for (;;) {
    const step = await untilMidStep();
    if (step > (lastStep.get(secret) ?? -1)) {
      lastStep.set(secret, step);
      return totp(secret);
    }
    // This step's code is spent: wait for the next step to begin.
    await new Promise((resolve) => setTimeout(resolve, (30 - (Date.now() / 1000) % 30 + 0.5) * 1000));
  }
}

// The code a device whose clock runs a step ahead shows now: the next step's, which the server
// refuses with a message to check the device's time (#142). From the middle of a step, so it is the
// server's next step too.
export async function nextStepTotp(secret: string): Promise<string> {
  await untilMidStep();
  return totp(secret, Date.now() + 30_000);
}
