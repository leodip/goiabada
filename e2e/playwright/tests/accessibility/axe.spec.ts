// axe-core over every page and state of both applications, in the light and the dark scheme: no
// violation of the WCAG 2.2 A and AA rules (axe-check.ts). Each test walks one area's pages through
// their states, with what the fixtures create: a field refused, a notice saying a save worked, each
// kind of confirmation open, lists empty and full. The states only a settings change reaches, the
// settings pages' own saves among them, are in axe.system.ts.
import { randomBytes } from "node:crypto";
import type { Page } from "@playwright/test";
import {
  addGroupAttribute,
  addGroupMember,
  addIntrospectionResource,
  addPermissionRow,
  addRedirectUri,
  clientIdFromList,
  clientUrl,
  confirmDialog,
  expectPasswordRules,
  grantUserPermission,
  groupUrl,
  idFromListLink,
  resourceUrl,
  userUrl,
  type ClientTab,
  type GroupTab,
  type ResourceTab,
  type UserTab,
} from "../../lib/admin-console";
import { signInThroughClient, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { signInToConsole } from "../../lib/console-user";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { solidPng } from "../../lib/images";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";
import { uniqueIdentifier } from "../../lib/unique";
import { asks, at, checkStates, refused, saved, says, titled, type State } from "../../lib/axe";

// Every state is checked twice, and a test walks a whole area.
test.describe.configure({ timeout: 300_000 });

// A browser with nobody signed in, for the pages reached without a session.
const signedOut = { storageState: { cookies: [], origins: [] } };

// A page that sets a password, checked with the stored policy's rule drawn under the field (#550).
function withPasswordRules(page: Page, field: string, state: State): State {
  return {
    ...state,
    reach: async () => {
      await state.reach();
      await expectPasswordRules(page, field);
    },
  };
}

// A user search (Add members, Grant to a user) answered with the user, and with no one.
function searchFinds(page: Page, name: string, url: () => Promise<unknown>, email: string): State[] {
  return [
    {
      name: `${name}, the search finding the user`,
      reach: async () => {
        await url();
        await page.locator("#search").fill(email.split("@")[0]);
        await expect(page.locator("[data-results-rows]").getByRole("link", { name: email, exact: true })).toBeVisible();
      },
    },
    {
      name: `${name}, the search finding no one`,
      reach: async () => {
        await url();
        await page.locator("#search").fill(`e2e-nobody-${randomBytes(4).toString("hex")}`);
        const none = (await page.locator("#userSearchForm").getAttribute("data-none"))!;
        await expect(page.locator("[data-results-note]")).toHaveText(none);
      },
    },
  ];
}

// An authorization request through the client, as an application sends one. The code it ends in is
// never redeemed, so the challenge is RFC 7636's example.
function authorizeUrl(clientId: string, params: Record<string, string> = {}) {
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: testRedirectUri,
    response_type: "code",
    scope: "openid",
    state: "axe",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
    ...params,
  });
  return `${env.authUrl}/auth/authorize?${query}`;
}

// The groups-with-permission tab lists every group, ten to a page: goes to the page holding this one.
async function groupsWithPermissionPageOf(page: Page, resourceId: number, groupId: number) {
  for (let n = 1; n <= 50; n++) {
    await page.goto(`${resourceUrl(resourceId, "groups-with-permission")}?page=${n}`);
    if ((await page.locator(`#grant-${groupId}, #remove-${groupId}`).count()) > 0) return;
    if ((await page.locator("#groupsTable tbody tr").count()) < 10) break;
  }
  throw new Error(`group ${groupId} is on no page of the groups with permission`);
}

test("the auth server's sign-in, two-factor, consent and sign-out pages", async ({ page, browser, clients, users }) => {
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const user = await users.create();
  const context = await browser.newContext(signedOut);
  const own = await context.newPage();
  const signIn = own.getByRole("button", { name: "Sign in", exact: true });
  const verify = own.getByRole("button", { name: "Verify", exact: true });

  await checkStates(own, [
    // Level 3, so the user, who has no authenticator, is asked to set one up.
    titled(own, "sign-in", "Sign in", () => own.goto(authorizeUrl(client.identifier, { acr_values: "urn:goiabada:level2_mandatory" }))),
    refused(own, "sign-in, the email missing", "email", async () => {
      await own.locator("#password").fill(user.password);
      await signIn.click();
    }),
    {
      name: "sign-in refused",
      reach: async () => {
        await own.locator("#email").fill(user.email);
        await own.locator("#password").fill("not-the-password");
        await signIn.click();
        // A refusal of the pair marks neither field.
        await expect(own.locator("#email")).not.toHaveAttribute("aria-invalid", "true");
        await expect(own.locator("#pwd-error")).toBeVisible();
      },
    },
    titled(own, "two-factor setup", "Set up two-factor authentication", async () => {
      await own.locator("#email").fill(user.email);
      await own.locator("#password").fill(user.password);
      await signIn.click();
    }),
    refused(own, "two-factor setup, the code refused", "otp", async () => {
      await own.locator("#otp").fill("000000");
      await verify.click();
    }),
    titled(own, "two-factor setup, its recovery codes", "Save your recovery codes", async () => {
      await own.locator("#otp").fill(await freshTotp((await own.locator("#otp-secret").innerText()).trim()));
      await verify.click();
    }),
    titled(own, "two-factor setup, its recovery codes already shown", "Your recovery codes were already shown", () => own.reload()),
    titled(own, "consent", "Allow access", () => own.getByRole("button", { name: "Continue" }).click()),
    {
      // The redirect URI removed while the user was at the consent screen: the code is sent nowhere.
      name: "a sign-in stopped, its redirect URI gone",
      reach: async () => {
        await page.goto(clientUrl(client.id, "redirect-uris"));
        await page.getByRole("button", { name: `Remove ${testRedirectUri}`, exact: true }).click();
        await page.locator("#btnSave").click();
        await expect(page.getByText("Redirect URIs saved.")).toBeVisible();
        await own.getByRole("button", { name: "Allow", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1, name: "You have not been sent anywhere" })).toBeVisible();
      },
      leave: () => addRedirectUri(page, client.id, testRedirectUri),
    },
    {
      // As a browser without JavaScript shows it: its script never loads, so the page stays.
      name: "the form post back to the application",
      reach: async () => {
        await own.route("**/static/form-post.js*", (route) => route.abort());
        await own.goto(authorizeUrl(client.identifier, { response_mode: "form_post" }));
        await expect(own.getByRole("heading", { level: 1, name: "Returning you to the application" })).toBeVisible();
      },
      leave: () => own.unroute("**/static/form-post.js*"),
    },
    titled(own, "two-factor", "Two-factor authentication", async () => {
      await own.goto(authorizeUrl(client.identifier, { prompt: "login" }));
      await submitPassword(own, user.email, user.password);
    }),
    refused(own, "two-factor, the code refused", "otp", async () => {
      await own.locator("#otp").fill("000000");
      await verify.click();
    }),
    titled(own, "a recovery code", "Use a recovery code", () =>
      own.getByRole("link", { name: "Use a recovery code instead", exact: true }).click()),
    refused(own, "a recovery code, refused", "recoveryCode", async () => {
      await own.locator("#recoveryCode").fill("0000-0000-0000-0000-0000-0000");
      await verify.click();
    }),
    titled(own, "the sign-out question", "Sign out", () => own.goto(`${env.authUrl}/auth/logout`)),
    titled(own, "signed out", "Signed out", () => own.getByRole("button", { name: "Sign out", exact: true }).click()),
    titled(own, "still signed in, having declined to sign out", "Still signed in", () => own.goto(`${env.authUrl}/auth/logout/declined`)),
  ]);
  await context.close();
});

test("the auth server's forgot password and reset pages", async ({ browser, request, users }) => {
  // Verified: a reset link is only ever mailed to a verified address.
  const user = await users.create({ emailVerified: true });
  const context = await browser.newContext(signedOut);
  const own = await context.newPage();
  const newPassword = `${randomBytes(12).toString("base64url")}-Aa1`;

  await checkStates(own, [
    titled(own, "forgot password", "Reset your password", () => own.goto(`${env.authUrl}/forgot-password`)),
    refused(own, "forgot password, the address refused", "email", async () => {
      await own.locator("#email").fill("not-an-address");
      await own.getByRole("button", { name: "Send reset link" }).click();
    }),
    titled(own, "forgot password, the link sent", "Check your email", async () => {
      await own.locator("#email").fill(user.email);
      await own.getByRole("button", { name: "Send reset link" }).click();
    }),
    titled(own, "reset password", "Set your password", async () => {
      const mail = await waitForMail(request, user.email);
      await own.goto(linksIn(mail).find((link) => link.includes("/reset-password"))!);
    }),
    {
      name: "reset password, the passwords not matching",
      reach: async () => {
        await own.locator("#password").fill(newPassword);
        await own.locator("#passwordConfirmation").fill(`${newPassword}-not`);
        await own.getByRole("button", { name: "Set password" }).click();
        await expect(own.locator("#reset-error")).toBeVisible();
      },
    },
    titled(own, "reset password, the password set", "Password set", async () => {
      await own.locator("#password").fill(newPassword);
      await own.locator("#passwordConfirmation").fill(newPassword);
      await own.getByRole("button", { name: "Set password" }).click();
    }),
    titled(own, "a reset link that can't be used", "This link can't be used", () => own.goto(`${env.authUrl}/reset-password?code=not-a-code`)),
  ]);
  await context.close();
});

test("the pages reached with no session: errors, not found, and the console signed out", async ({ browser, users }) => {
  const context = await browser.newContext(signedOut);
  const own = await context.newPage();
  const user = await users.create();

  await checkStates(own, [
    at(own, "the console's home, signed out", `${env.adminUrl}/`),
    {
      // Only a console session can end: a browser with none holds no cookie to carry the notice home
      // (#620). So the user signs in first, and the cookies go after, for the states below, which
      // need no session at the console or the auth server.
      name: "the console's home, the session ended",
      reach: async () => {
        await own.goto(`${env.adminUrl}/account/profile`);
        await submitPassword(own, user.email, user.password);
        await own.waitForURL((url) => url.origin === env.adminUrl);
        await own.goto(`${env.adminUrl}/auth/session-ended`);
        await expect(own).toHaveURL(`${env.adminUrl}/`);
        await expect(own.locator(".notice-caution[role=status]")).toBeVisible();
      },
      leave: () => context.clearCookies(),
    },
    {
      // The console's callback takes the form_post response mode, so a refusal is posted to it.
      name: "the console's sign-in error",
      reach: async () => {
        await own.goto(`${env.adminUrl}/`);
        await own.evaluate(() => {
          const form = document.createElement("form");
          form.id = "e2e-callback";
          form.method = "post";
          form.action = "/auth/callback";
          for (const [name, value] of [
            ["error", "access_denied"],
            ["error_description", "The user declined."],
            ["state", "not-the-one"],
          ]) {
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = name;
            input.value = value;
            form.appendChild(input);
          }
          const button = document.createElement("button");
          button.textContent = "Post";
          form.appendChild(button);
          document.body.appendChild(form);
        });
        await own.locator("#e2e-callback button").click();
        await expect(own).toHaveURL(`${env.adminUrl}/auth/callback`);
        await expect(own.locator("h1")).toBeVisible();
      },
    },
    // The callback's address opened on its own, as from a bookmark: the same page, at 405.
    at(own, "the console's sign-in error, its address opened on its own", `${env.adminUrl}/auth/callback`, 405),
    titled(own, "a sign-in request no longer active", "This request is no longer active", async () => {
      // The console sends the browser to sign in, which starts a request; this page names another.
      await own.goto(`${env.adminUrl}/account/profile`);
      await expect(own).toHaveURL(/\/auth\/pwd/);
      await own.goto(`${env.authUrl}/auth/pwd?ceremony=not-the-one-in-progress`);
    }),
    {
      name: "an authorization request refused",
      reach: async () => {
        await own.goto(authorizeUrl(uniqueIdentifier("c")));
        await expect(own.getByText(/The application does not exist\./)).toBeVisible();
      },
    },
    at(own, "the auth server's page not found", `${env.authUrl}/e2e-no-such-page`, 404),
  ]);
  await context.close();
});

test("the console's home, page not found and menus", async ({ page }) => {
  const desktop = page.viewportSize()!;
  await checkStates(page, [
    at(page, "home", `${env.adminUrl}/`),
    at(page, "page not found", `${env.adminUrl}/e2e-no-such-page`, 404),
    {
      name: "the user menu open",
      reach: async () => {
        await page.goto(`${env.adminUrl}/admin/clients`);
        await page.locator("button[data-user-menu-button]").click();
        await expect(page.locator("#user-menu-panel")).toBeVisible();
      },
    },
    {
      name: "the menu open on a phone",
      reach: async () => {
        await page.setViewportSize({ width: 390, height: 844 });
        await page.goto(`${env.adminUrl}/admin/clients`);
        await page.locator("button[data-app-menu-open]").click();
        await expect(page.locator("#app-sidebar")).toBeVisible();
      },
      leave: () => page.setViewportSize(desktop),
    },
  ]);
});

test("a user's account pages", async ({ page, browser, clients, users }) => {
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const user = await users.create();
  const { context, page: own } = await signInToConsole(browser, user);
  const account = (path: string) => `${env.adminUrl}/account/${path}`;
  const submit = () => own.locator('main form[method="post"] button[type="submit"]').click();
  const picture = { name: "picture.png", mimeType: "image/png", buffer: solidPng(320, 320, [36, 86, 196]) };

  await checkStates(own, [
    at(own, "home, signed in as a user", `${env.adminUrl}/`),
    titled(own, "an administrator's page, to a user", "Administrators only", () => own.goto(`${env.adminUrl}/admin/clients`)),
    at(own, "profile", account("profile")),
    {
      name: "profile, the time zone list open",
      reach: async () => {
        await own.goto(account("profile"));
        await own.locator("#zoneInfo").pressSequentially("paris");
        await expect(own.locator("#zoneInfo-options")).toBeVisible();
      },
      leave: () => own.keyboard.press("Escape"),
    },
    refused(own, "profile, the website refused", "website", async () => {
      await own.goto(account("profile"));
      await own.locator("#website").fill("not a website");
      await submit();
    }),
    saved(own, "profile saved", async () => {
      await own.goto(account("profile"));
      await own.locator("#nickname").fill("Checked");
      await submit();
    }),
    at(own, "email", account("email")),
    refused(own, "email, the addresses not matching", "emailConfirmation", async () => {
      await own.goto(account("email"));
      await own.locator("#email").fill(`${uniqueIdentifier("u")}@example.com`);
      await own.locator("#emailConfirmation").fill(`${uniqueIdentifier("u")}@example.com`);
      await own.locator("#currentPassword").fill(user.password);
      await submit();
    }),
    at(own, "email verification", account("email-verification")),
    says(own, "email verification, the code sent", "verification-status", () => own.locator("button[data-send-verification]").click()),
    refused(own, "email verification, the code refused", "verificationCode", async () => {
      await own.locator("#verificationCode").fill("WRONG123");
      await submit();
    }),
    at(own, "address", account("address")),
    at(own, "phone", account("phone")),
    refused(own, "phone, the number refused", "phoneNumber", async () => {
      await own.goto(account("phone"));
      await own.locator("#phoneNumber").fill("12");
      await submit();
    }),
    at(own, "picture", account("picture")),
    {
      name: "picture, a file that is no image refused",
      reach: async () => {
        await own.locator("#imageUploadInput").setInputFiles({ name: "picture.png", mimeType: "image/png", buffer: Buffer.from("not an image") });
        await expect(own.locator("#imageUploadStatus .notice-danger")).toBeVisible();
      },
    },
    {
      name: "picture, the crop dialog",
      reach: async () => {
        await own.locator("#imageUploadInput").setInputFiles(picture);
        await expect(own.locator("#cropDialog")).toBeVisible();
        await expect(own.locator("#confirmCropBtn")).toBeEnabled();
      },
    },
    {
      name: "picture saved",
      reach: async () => {
        await own.locator("#confirmCropBtn").click();
        await expect(own.locator("#imagePreview img")).toBeVisible();
        await expect(own.locator("#imageUploadStatus .notice")).toBeVisible();
      },
    },
    asks(own, "picture, deleting it asking first", () => own.locator("#deleteImageBtn").click()),
    withPasswordRules(own, "newPassword", at(own, "change password", account("change-password"))),
    withPasswordRules(
      own,
      "newPassword",
      refused(own, "change password, the new password refused", "newPassword", async () => {
        await own.goto(account("change-password"));
        await own.locator("#currentPassword").fill(user.password);
        await own.locator("#newPassword").fill("abc");
        await own.locator("#newPasswordConfirmation").fill("abc");
        await submit();
      }),
    ),
    refused(own, "change password, the passwords not matching", "newPasswordConfirmation", async () => {
      await own.goto(account("change-password"));
      await own.locator("#currentPassword").fill(user.password);
      await own.locator("#newPassword").fill(`${user.password}-new`);
      await own.locator("#newPasswordConfirmation").fill(`${user.password}-other`);
      await submit();
    }),
    {
      name: "consents, none yet",
      reach: async () => {
        await own.goto(account("manage-consents"));
        await expect(own.locator(".empty-state")).toBeVisible();
      },
    },
    {
      // Signed in already, the user goes straight to the client's consent screen.
      name: "consents",
      reach: async () => {
        await own.goto(authorizeUrl(client.identifier));
        await own.getByRole("button", { name: "Allow", exact: true }).click();
        await own.waitForURL((url) => url.href.startsWith(testRedirectUri));
        await own.goto(account("manage-consents"));
        await expect(own.locator("button[data-action-url]")).toBeVisible();
      },
    },
    asks(own, "consents, revoking one asking first", () => own.locator("button[data-action-url]").click()),
    at(own, "sessions", account("sessions")),
    asks(own, "sessions, ending this device's asking first", () => own.locator('button[data-dialog="endCurrentSession"]').click()),
    at(own, "two-factor authentication, setting it up", account("otp")),
    refused(own, "two-factor authentication, the code refused", "otp", async () => {
      await own.locator("#password").fill(user.password);
      await own.locator("#otp").fill("000000");
      await own.locator('button[name="otpAction"]').click();
    }),
    {
      name: "two-factor authentication on",
      reach: async () => {
        // The key the page shows is the pending enrolment's, which the refusals above kept.
        const secret = (await own.locator("#otp-secret").innerText()).trim();
        await own.locator("#password").fill(user.password);
        await own.locator("#otp").fill(await freshTotp(secret));
        await own.locator('button[name="otpAction"]').click();
        await expect(own.locator('button[name="otpAction"][value="disable"]')).toBeVisible();
        await expect(own.locator(".panel-body > .notice-positive")).toBeVisible();
      },
    },
    at(own, "two-factor authentication on, the count of recovery codes", account("otp")),
    asks(own, "two-factor authentication, a new set of recovery codes asking first", async () => {
      await own.locator("#recovery-codes-password").fill(user.password);
      await own.locator('button[name="otpAction"][value="recovery-codes"]').click();
    }),
    refused(own, "two-factor authentication, a new set of recovery codes refused", "recovery-codes-password", async () => {
      await own.locator("#recovery-codes-password").fill("not-the-password");
      await own.locator('button[name="otpAction"][value="recovery-codes"]').click();
      await confirmDialog(own);
    }),
    {
      name: "two-factor authentication, a new set of recovery codes",
      reach: async () => {
        await own.locator("#recovery-codes-password").fill(user.password);
        await own.locator('button[name="otpAction"][value="recovery-codes"]').click();
        await confirmDialog(own);
        await expect(own.locator("#recovery-codes")).toBeVisible();
      },
    },
    titled(own, "the sign-out question", "Sign out", () => own.goto(`${env.adminUrl}/auth/logout`)),
    {
      // As a browser without JavaScript shows it: its script never loads, so the page stays.
      name: "signing out, on the way to the auth server",
      reach: async () => {
        await own.route("**/static/form-post.js*", (route) => route.abort());
        await own.getByRole("button", { name: "Sign out", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1, name: "Signing you out" })).toBeVisible();
      },
    },
  ]);
  await context.close();
});

test("the clients' pages", async ({ page, clients, resources }) => {
  const client = await clients.create();
  // The client credentials flow alone: its permissions tab holds a list, its redirect URIs tab a note.
  const machine = await clients.create({ authorizationCode: false, clientCredentials: true });
  const resource = await resources.create({ permissions: ["read"] });
  const system = await clientIdFromList(page, "admin-console-client");
  const tab = (name: ClientTab) => clientUrl(client.id, name);

  await checkStates(page, [
    at(page, "the clients list", `${env.adminUrl}/admin/clients`),
    at(page, "a new client", `${env.adminUrl}/admin/clients/new`),
    refused(page, "a new client with no identifier", "clientIdentifier", async () => {
      await page.goto(`${env.adminUrl}/admin/clients/new`);
      await page.locator("#btnCreate").click();
    }),
    at(page, "deleting a client", tab("delete")),
    refused(page, "deleting a client, the identifier mistyped", "clientIdentifier", async () => {
      await page.goto(tab("delete"));
      await page.locator("#clientIdentifier").fill("not-this-client");
      await page.locator("#btnDelete").click();
    }),
    at(page, "the admin console's client, which can't be deleted", clientUrl(system, "delete")),
    at(page, "a client's settings", tab("settings")),
    asks(page, "a client's settings, a rename asking first", async () => {
      await page.goto(tab("settings"));
      await page.locator("#clientIdentifier").fill(`${client.identifier}-renamed`);
      await page.locator("#btnSave").click();
    }),
    refused(page, "a client's settings, the description refused", "description", async () => {
      await page.goto(tab("settings"));
      await page.locator("#description").fill("<b>not allowed</b>");
      await page.locator("#btnSave").click();
    }),
    saved(page, "a client's settings saved", async () => {
      await page.goto(tab("settings"));
      await page.locator("#description").fill("Checked for accessibility");
      await page.locator("#btnSave").click();
    }),
    asks(page, "the admin console's client's settings, whose every save asks first", async () => {
      await page.goto(clientUrl(system, "settings"));
      await page.locator("#btnSave").click();
    }),
    at(page, "a client's logo", tab("logo")),
    at(page, "a client's tokens", tab("tokens")),
    refused(page, "a client's tokens, a lifetime refused", "refreshTokenOfflineIdleTimeoutInSeconds", async () => {
      await page.goto(tab("tokens"));
      await page.locator("#refreshTokenOfflineIdleTimeoutInSeconds").fill("two hours");
      await page.locator("#btnSave").click();
    }),
    at(page, "a client's authentication", tab("authentication")),
    says(page, "a client's secret shown, and a new one generated", "secret-status", async () => {
      await page.locator("#showSecretBtn").click();
      await page.locator("#generateSecretBtn").click();
    }),
    asks(page, "a client made public, asking first", async () => {
      await page.goto(tab("authentication"));
      await page.locator("#publicClientRadio").check();
      await page.locator("#btnSave").click();
    }),
    at(page, "a client's OAuth2 flows", tab("oauth2-flows")),
    {
      name: "a client's OAuth2 flows, every caution showing",
      reach: async () => {
        await page.locator('input[name="pkceRequired"][value="off"]').check();
        await page.locator('input[name="implicitGrantEnabled"][value="on"]').check();
        await page.locator('input[name="ropcEnabled"][value="on"]').check();
        for (const caution of ["#pkceWarning", "#implicitWarning", "#ropcWarning"]) await expect(page.locator(caution)).toBeVisible();
      },
    },
    at(page, "a client's redirect URIs, none yet", tab("redirect-uris")),
    refused(page, "a client's redirect URIs, an entry refused", "redirectURI", async () => {
      await page.locator("#redirectURI").fill("not a url");
      await page.locator("#addURIBtn").click();
    }),
    saved(page, "a client's redirect URIs saved", async () => {
      await page.goto(tab("redirect-uris"));
      await page.locator("#redirectURI").fill(testRedirectUri);
      await page.locator("#addURIBtn").click();
      await page.locator("#btnSave").click();
    }),
    at(page, "the redirect URIs of a client with no flow that redirects", clientUrl(machine.id, "redirect-uris")),
    at(page, "a client's sign-out redirect URIs, none yet", tab("sign-out-redirect-uris")),
    refused(page, "a client's sign-out redirect URIs, an entry refused", "signOutRedirectURI", async () => {
      await page.locator("#signOutRedirectURI").fill("not a url");
      await page.locator("#addURIBtn").click();
    }),
    saved(page, "a client's sign-out redirect URIs saved", async () => {
      await page.goto(tab("sign-out-redirect-uris"));
      await page.locator("#signOutRedirectURI").fill(`${env.webtest1Url}/signed-out`);
      await page.locator("#addURIBtn").click();
      await page.locator("#btnSave").click();
    }),
    at(page, "the sign-out redirect URIs of a client with no flow that redirects", clientUrl(machine.id, "sign-out-redirect-uris")),
    at(page, "a client's web origins, none yet", tab("web-origins")),
    saved(page, "a client's web origins saved", async () => {
      await page.locator("#webOrigin").fill(env.webtest1Url);
      await page.locator("#addOriginBtn").click();
      await page.locator("#btnSave").click();
    }),
    at(page, "a client's sessions, none yet", tab("user-sessions")),
    at(page, "the permissions of a client without the client credentials flow", tab("permissions")),
    at(page, "a client's permissions, none yet", clientUrl(machine.id, "permissions")),
    refused(page, "a client's permissions, Grant with nothing chosen", "permissionsSelect", () => page.locator("#grantPermissionBtn").click()),
    saved(page, "a client's permissions saved", async () => {
      await page.goto(clientUrl(machine.id, "permissions"));
      await addPermissionRow(page, resource.identifier, "read");
      await page.locator("#btnSave").click();
    }),
    at(page, "a client's introspection resources, none yet", tab("introspection")),
    refused(page, "a client's introspection resources, Add with nothing chosen", "introspectionResourcesSelect", () =>
      page.locator("#addIntrospectionResourceBtn").click(),
    ),
    saved(page, "a client's introspection resources saved", async () => {
      await page.goto(tab("introspection"));
      await addIntrospectionResource(page, resource.identifier);
      await page.locator("#btnSave").click();
    }),
  ]);
});

test("a signed-in user's sessions and consent, as the administrator sees them", async ({ page, browser, clients, users }) => {
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const user = await users.create();
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  await checkStates(page, [
    at(page, "a client's sessions", clientUrl(client.id, "user-sessions")),
    asks(page, "a client's session, ending it asking first", () => page.locator("button[data-end-session]").click()),
    at(page, "a user's sessions", userUrl(user.id, "sessions")),
    asks(page, "a user's session, ending it asking first", () => page.locator("button[data-end-session]").click()),
    at(page, "a user's consents", userUrl(user.id, "consents")),
    asks(page, "a user's consent, revoking it asking first", () => page.locator("button[data-action-url]").click()),
  ]);
  await signIn.context.close();
});

test("the resources' pages", async ({ page, resources, groups, users }) => {
  const resource = await resources.create({ description: "Checked for accessibility", permissions: ["read", "write"] });
  const bare = await resources.create();
  const group = await groups.create();
  const user = await users.create();
  const system = await idFromListLink(page, `${env.adminUrl}/admin/resources`, "authserver");
  const tab = (name: ResourceTab) => resourceUrl(resource.id, name);

  await checkStates(page, [
    at(page, "the resources list", `${env.adminUrl}/admin/resources`),
    at(page, "a new resource", `${env.adminUrl}/admin/resources/new`),
    refused(page, "a new resource with no identifier", "resourceIdentifier", () => page.locator("#btnCreate").click()),
    at(page, "deleting a resource", tab("delete")),
    refused(page, "deleting a resource, the identifier mistyped", "resourceIdentifier", async () => {
      await page.locator("#resourceIdentifier").fill("not-this-resource");
      await page.locator("#btnDelete").click();
    }),
    at(page, "the auth server's resource, which can't be deleted", resourceUrl(system, "delete")),
    at(page, "a resource's settings", tab("settings")),
    asks(page, "a resource's settings, a rename asking first", async () => {
      await page.locator("#resourceIdentifier").fill(`${resource.identifier}-renamed`);
      await page.locator("#btnSave").click();
    }),
    refused(page, "a resource's settings, the description refused", "description", async () => {
      await page.goto(tab("settings"));
      await page.locator("#description").fill("<b>not allowed</b>");
      await page.locator("#btnSave").click();
    }),
    asks(page, "the auth server's resource's settings, whose every save asks first", async () => {
      await page.goto(resourceUrl(system, "settings"));
      await page.locator("#btnSave").click();
    }),
    at(page, "a resource's permissions", tab("permissions")),
    {
      name: "a resource's permission being edited",
      reach: async () => {
        await page.locator("[data-entry-edit]").first().click();
        await expect(page.locator("#permissionsTable tr[data-editing]")).toBeVisible();
      },
    },
    refused(page, "a resource's permissions, an identifier refused", "permissionIdentifier", async () => {
      await page.goto(tab("permissions"));
      await page.locator("#permissionIdentifier").fill("9 not valid");
      await page.locator("#addPermissionBtn").click();
    }),
    at(page, "a resource's permissions, none yet", resourceUrl(bare.id, "permissions")),
    at(page, "the auth server's resource's permissions", resourceUrl(system, "permissions")),
    at(page, "the users holding a permission, none yet", tab("users-with-permission")),
    ...searchFinds(
      page,
      "granting a permission to a user",
      async () => {
        await page.goto(tab("users-with-permission"));
        await page.getByRole("link", { name: "Grant to a user" }).click();
      },
      user.email,
    ),
    {
      name: "the users holding a permission",
      reach: async () => {
        await grantUserPermission(page, user.id, resource.identifier, "read");
        await page.goto(tab("users-with-permission"));
        await expect(page.locator("#usersTable").getByRole("link", { name: user.email, exact: true })).toBeVisible();
      },
    },
    asks(page, "the users holding a permission, removing one asking first", () => page.locator("#usersTable button[data-action-url]").click()),
    at(page, "the users holding a permission of a resource with none", resourceUrl(bare.id, "users-with-permission")),
    says(page, "the groups holding a permission, one granted", "row-actions-status", async () => {
      await groupsWithPermissionPageOf(page, resource.id, group.id);
      await page.locator(`#grant-${group.id}`).click();
    }),
    asks(page, "the groups holding a permission, removing one asking first", () => page.locator(`#remove-${group.id}`).click()),
  ]);
});

test("the groups' pages", async ({ page, groups, users, resources }) => {
  const group = await groups.create({ description: "Checked for accessibility" });
  const user = await users.create();
  const resource = await resources.create({ permissions: ["read"] });
  const tab = (name: GroupTab) => groupUrl(group.id, name);

  await checkStates(page, [
    at(page, "the groups list", `${env.adminUrl}/admin/groups`),
    at(page, "a new group", `${env.adminUrl}/admin/groups/new`),
    refused(page, "a new group with no identifier", "groupIdentifier", () => page.locator("#btnCreate").click()),
    at(page, "deleting a group", tab("delete")),
    refused(page, "deleting a group, the identifier mistyped", "groupIdentifier", async () => {
      await page.locator("#groupIdentifier").fill("not-this-group");
      await page.locator("#btnDelete").click();
    }),
    at(page, "a group's settings", tab("settings")),
    asks(page, "a group's settings, a rename asking first", async () => {
      await page.locator("#groupIdentifier").fill(`${group.identifier}-renamed`);
      await page.locator("#btnSave").click();
    }),
    refused(page, "a group's settings, the description refused", "description", async () => {
      await page.goto(tab("settings"));
      await page.locator("#description").fill("<b>not allowed</b>");
      await page.locator("#btnSave").click();
    }),
    at(page, "a group's attributes, none yet", tab("attributes")),
    at(page, "a new group attribute", `${tab("attributes")}/add`),
    refused(page, "a new group attribute, the key refused", "attributeKey", async () => {
      await page.locator("#attributeKey").fill("9 not valid");
      await page.locator("#btnSave").click();
    }),
    {
      name: "a group's attributes",
      reach: async () => {
        await addGroupAttribute(page, group.id, { key: "department", value: "Accessibility" });
        await expect(page.locator("#attributesTable")).toBeVisible();
      },
    },
    {
      name: "a group attribute being edited",
      reach: async () => {
        await page.locator("#attributesTable").getByRole("link", { name: "department", exact: true }).click();
        await expect(page).toHaveURL(/\/attributes\/edit\/\d+(\?|$)/);
      },
    },
    asks(page, "a group's attribute, removing it asking first", async () => {
      await page.goto(tab("attributes"));
      await page.locator("#attributesTable button[data-action-url]").click();
    }),
    at(page, "a group's members, none yet", tab("members")),
    at(page, "adding members to a group", `${tab("members")}/add`),
    ...searchFinds(page, "adding members to a group", () => page.goto(`${tab("members")}/add`), user.email),
    {
      name: "a group's members",
      reach: async () => {
        await addGroupMember(page, group.id, user.email);
        await page.goto(tab("members"));
        await expect(page.locator("#usersTable").getByRole("link", { name: user.email, exact: true })).toBeVisible();
      },
    },
    asks(page, "a group's member, removing them asking first", () => page.locator("#usersTable button[data-action-url]").click()),
    at(page, "a group's permissions, none yet", tab("permissions")),
    refused(page, "a group's permissions, Grant with nothing chosen", "permissionsSelect", () => page.locator("#grantPermissionBtn").click()),
    saved(page, "a group's permissions saved", async () => {
      await page.goto(tab("permissions"));
      await addPermissionRow(page, resource.identifier, "read");
      await page.locator("#btnSave").click();
    }),
  ]);
});

test("the users' list, new and delete pages, and a user's details, profile and contact", async ({ page, users }) => {
  const user = await users.create();
  const list = `${env.adminUrl}/admin/users`;
  const tab = (name: UserTab) => userUrl(user.id, name);

  await checkStates(page, [
    at(page, "the users list", list),
    {
      name: "the users list, searched",
      reach: async () => {
        await page.goto(`${list}?${new URLSearchParams({ query: user.email })}`);
        await expect(page.locator("#usersTable").getByRole("link", { name: user.email, exact: true })).toBeVisible();
      },
    },
    {
      name: "the users list, a search finding no one",
      reach: async () => {
        await page.goto(`${list}?${new URLSearchParams({ query: `e2e-nobody-${randomBytes(4).toString("hex")}` })}`);
        await expect(page.locator(".empty-state")).toBeVisible();
      },
    },
    withPasswordRules(page, "password", at(page, "a new user", `${list}/new`)),
    refused(page, "a new user with no email", "email", () => page.locator("#btnCreate").click()),
    withPasswordRules(
      page,
      "password",
      refused(page, "a new user, the password refused", "password", async () => {
        await page.goto(`${list}/new`);
        await page.locator("#email").fill(`${uniqueIdentifier("u")}@example.com`);
        await page.locator("#password").fill("abc");
        await page.locator("#btnCreate").click();
      }),
    ),
    {
      // Offered while email is set up, as it is in the baseline.
      name: "a new user, the password link to be emailed",
      reach: async () => {
        await page.goto(`${list}/new`);
        await page.locator("#setPasswordTypeEmail").check();
        await expect(page.locator("#password")).toBeHidden();
      },
    },
    at(page, "deleting a user", tab("delete")),
    refused(page, "deleting a user, the email mistyped", "email", async () => {
      await page.locator("#email").fill("someone-else@example.com");
      await page.locator("#btnDelete").click();
    }),
    at(page, "a user's details", tab("details")),
    asks(page, "a user's details, disabling them asking first", async () => {
      await page.locator("#enabledDisabled").uncheck();
      await page.locator("#btnSave").click();
    }),
    at(page, "a user's profile", tab("profile")),
    refused(page, "a user's profile, the birth date refused", "dateOfBirth", async () => {
      await page.locator("#dateOfBirth").fill("22/12/1980");
      await page.locator("#btnSave").click();
    }),
    saved(page, "a user's profile saved", async () => {
      await page.goto(tab("profile"));
      await page.locator("#nickname").fill("Checked");
      await page.locator("#btnSave").click();
    }),
    at(page, "a user's email", tab("email")),
    refused(page, "a user's email refused", "email", async () => {
      await page.locator("#email").fill("not an email");
      await page.locator("#btnSave").click();
    }),
    at(page, "a user's phone", tab("phone")),
    refused(page, "a user's phone, the number refused", "phoneNumber", async () => {
      await page.locator("#phoneNumber").fill("12");
      await page.locator("#btnSave").click();
    }),
    at(page, "a user's address", tab("address")),
    refused(page, "a user's address, the postal code refused", "addressPostalCode", async () => {
      await page.locator("#addressPostalCode").fill("x".repeat(40));
      await page.locator("#btnSave").click();
    }),
    at(page, "a user's picture", tab("picture")),
    withPasswordRules(page, "newPassword", at(page, "a user's authentication, without two-factor authentication", tab("authentication"))),
    withPasswordRules(
      page,
      "newPassword",
      refused(page, "a user's authentication, the new password refused", "newPassword", async () => {
        await page.locator("#newPassword").fill("abc");
        await page.locator("#btnSave").click();
      }),
    ),
  ]);
});

test("a user's attributes, groups, permissions, sessions and consents, empty and full", async ({ page, users, groups, resources }) => {
  const user = await users.create();
  const group = await groups.create();
  const resource = await resources.create({ permissions: ["read"] });
  const tab = (name: UserTab) => userUrl(user.id, name);

  await checkStates(page, [
    at(page, "a user's attributes, none yet", tab("attributes")),
    at(page, "a new user attribute", `${tab("attributes")}/add`),
    refused(page, "a new user attribute, the key refused", "attributeKey", async () => {
      await page.locator("#attributeKey").fill("9 not valid");
      await page.locator("#btnSave").click();
    }),
    {
      name: "a user's attributes",
      reach: async () => {
        await page.goto(`${tab("attributes")}/add`);
        await page.locator("#attributeKey").fill("department");
        await page.locator("#attributeValue").fill("Accessibility");
        await page.locator("#btnSave").click();
        await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(\\?|$)`));
        await expect(page.locator("#attributesTable")).toBeVisible();
      },
    },
    {
      name: "a user attribute being edited",
      reach: async () => {
        await page.locator("#attributesTable").getByRole("link", { name: "department", exact: true }).click();
        await expect(page).toHaveURL(/\/attributes\/edit\/\d+(\?|$)/);
      },
    },
    asks(page, "a user's attribute, removing it asking first", async () => {
      await page.goto(tab("attributes"));
      await page.locator("#attributesTable button[data-action-url]").click();
    }),
    at(page, "a user's sessions, none yet", tab("sessions")),
    at(page, "a user's consents, none yet", tab("consents")),
    at(page, "a user's groups, none yet", tab("groups")),
    refused(page, "a user's groups, Add with nothing chosen", "groupsSelect", () => page.locator("#addGroupBtn").click()),
    saved(page, "a user's groups saved", async () => {
      await page.goto(tab("groups"));
      await page.locator("#groupsSelect").selectOption(String(group.id));
      await page.locator("#addGroupBtn").click();
      await page.locator("#btnSave").click();
    }),
    at(page, "a user's permissions, none yet", tab("permissions")),
    refused(page, "a user's permissions, Grant with nothing chosen", "permissionsSelect", () => page.locator("#grantPermissionBtn").click()),
    saved(page, "a user's permissions saved", async () => {
      await page.goto(tab("permissions"));
      await addPermissionRow(page, resource.identifier, "read");
      await page.locator("#btnSave").click();
    }),
  ]);
});

// The settings pages as they are, and what can be done on them without saving: the saves, and the
// confirmations a save asks, are in axe.system.ts.
test("the settings pages and the audit log", async ({ page }) => {
  const settings = (path: string) => `${env.adminUrl}/admin/settings/${path}`;

  await checkStates(page, [
    at(page, "general settings", settings("general")),
    {
      // Switched in the page, never saved.
      name: "general settings, every caution showing",
      reach: async () => {
        await page.locator("#selfRegistrationEnabled").setChecked(true);
        await page.locator("#pkceRequired").setChecked(false);
        await page.locator("#implicitFlowEnabled").setChecked(true);
        await page.locator("#ropcFlowEnabled").setChecked(true);
        for (const shown of ["#emailVerificationRow", "#pkceWarning", "#implicitFlowWarning", "#ropcFlowWarning"]) {
          await expect(page.locator(shown)).toBeVisible();
        }
      },
    },
    at(page, "theme settings", settings("ui-theme")),
    at(page, "session settings", settings("sessions")),
    at(page, "token settings", settings("tokens")),
    at(page, "signing keys", settings("keys")),
    {
      name: "signing keys, a public key shown",
      reach: async () => {
        await page.locator('button[data-format="pem"]').first().click();
        await expect(page.locator("#publicKeyDialog")).toBeVisible();
        await expect(page.locator("#publicKeyContent")).toContainText("PUBLIC KEY");
      },
      leave: async () => {
        await page.keyboard.press("Escape");
        await expect(page.locator("#publicKeyDialog")).toBeHidden();
      },
    },
    at(page, "email settings", settings("email")),
    at(page, "sending a test email", settings("email/send-test-email")),
    saved(page, "a test email sent", async () => {
      await page.locator("#destinationEmail").fill(`${uniqueIdentifier("u")}@example.com`);
      await page.locator("#btnSend").click();
    }),
    refused(page, "a test email, the address refused", "destinationEmail", async () => {
      await page.goto(settings("email/send-test-email"));
      await page.locator("#destinationEmail").fill("not-an-address");
      await page.locator("#btnSend").click();
    }),
    at(page, "audit logging settings", settings("audit-logs")),
    at(page, "the audit log", settings("audit-log-viewer")),
    {
      name: "the audit log, one request's events",
      reach: async () => {
        await page.locator('#auditLogsTable a[href*="requestId="]').first().click();
        await expect(page).toHaveURL(/requestId=/);
        await expect(page.locator("#requestIdFilter")).not.toHaveValue("");
      },
    },
    {
      name: "the audit log, the filters matching nothing",
      reach: async () => {
        await page.goto(`${settings("audit-log-viewer")}?requestId=e2e-no-such-request`);
        await expect(page.locator(".empty-state")).toBeVisible();
      },
    },
    {
      name: "the audit log, the event list open",
      reach: async () => {
        await page.goto(settings("audit-log-viewer"));
        await page.locator("#auditEventFilter").fill("user");
        await expect(page.locator("#auditEventFilter-options")).toBeVisible();
      },
      leave: () => page.keyboard.press("Escape"),
    },
  ]);
});
