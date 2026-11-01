// The user's own profile, email, phone and address pages, which the administrator sees the same way.
import { expectRefusal, userUrl } from "../../../lib/admin-console";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

test("the user edits their own profile, and the administrator sees it", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user);
  const save = own.page.getByRole("button", { name: "Save", exact: true });
  await own.page.locator("#givenName").fill("Katherine");
  await own.page.locator("#familyName").fill("Johnson");
  await own.page.locator("#nickname").fill("kat");
  await save.click();
  await expect(own.page.getByText("Profile saved.", { exact: true })).toBeVisible();

  // Refused like on the admin's page.
  await own.page.locator("#givenName").fill("K4therine");
  await save.click();
  await expectRefusal(own.page, "profile-error", "givenName", "Please enter a valid given name.");
  await own.context.close();

  await page.goto(userUrl(user.id, "profile"));
  await expect(page.locator("#givenName")).toHaveValue("Katherine");
  await expect(page.locator("#nickname")).toHaveValue("kat");
});

test("the user's refused date of birth is kept as typed, and their stored one stays", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user);
  const save = own.page.getByRole("button", { name: "Save", exact: true });
  const dateOfBirth = own.page.locator("#dateOfBirth");
  await dateOfBirth.fill("1990-05-17");
  await save.click();
  await expect(own.page.getByText("Profile saved.", { exact: true })).toBeVisible();

  await dateOfBirth.fill("17/05/1991");
  await save.click();
  await expectRefusal(own.page, "profile-error", "dateOfBirth", "The date of birth is invalid. Please use the format YYYY-MM-DD.");
  await expect(dateOfBirth).toHaveValue("17/05/1991");
  await own.page.goto(`${env.adminUrl}/account/profile`);
  await expect(dateOfBirth).toHaveValue("1990-05-17");
  await own.context.close();
});

// The time zone and the language are long lists, searched by typing: the field filters the options
// by any part of their text, and Enter takes the first match. The select that posts the choice is
// hidden behind the field.
test("the user picks a time zone and a language by searching their lists, and the administrator sees them", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user);
  const zone = own.page.getByRole("combobox", { name: "Time zone" });
  const language = own.page.getByRole("combobox", { name: "Language and region" });
  const lisbon = "Portugal - Europe/Lisbon - Portugal (mainland)";

  await zone.fill("lisbon");
  await expect(own.page.locator("#zoneInfo-options").getByRole("option", { name: lisbon })).toBeVisible();
  await zone.press("Enter");
  await expect(zone).toHaveValue(lisbon);
  await language.fill("en-GB");
  await language.press("Enter");
  await expect(language).toHaveValue(/^en-GB – /);
  await own.page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(own.page.getByText("Profile saved.", { exact: true })).toBeVisible();
  await expect(zone).toHaveValue(lisbon);
  await expect(language).toHaveValue(/^en-GB – /);
  await own.context.close();

  await page.goto(userUrl(user.id, "profile"));
  await expect(page.locator('select[name="zoneInfo"]')).toHaveValue("Portugal___Europe/Lisbon");
  await expect(page.locator('select[name="locale"]')).toHaveValue("en-GB");
});

// The Page language is the language Goiabada's own pages use for the user, chosen in My Account's
// Profile form. The next page is marked and written in it, over a ui_locales in the address and the
// browser's English; Automatic gives the request's language back, the address's and then the
// browser's (#631).
test("the user chooses a page language, which wins over ui_locales, and Automatic gives the request's language back", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user);
  const html = own.page.locator("html");
  const phoneHint = (text: string) => own.page.getByText(text, { exact: true });
  await expect(own.page.getByText("The language of these pages, of the sign-in pages once you have entered your password, and of the emails sent to you. Automatic uses the language the application or your browser asks for, and your language and region for emails.", { exact: true })).toBeVisible();
  const pageLanguage = own.page.getByLabel("Page language", { exact: true });
  await expect(pageLanguage).toHaveValue("");
  await expect(pageLanguage.locator("option").first()).toHaveText("Automatic");
  await pageLanguage.selectOption("pt-BR");
  await own.page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(own.page.getByText("Perfil salvo.", { exact: true })).toBeVisible();
  await expect(html).toHaveAttribute("lang", "pt-BR");
  await expect(own.page.getByLabel("Idioma das páginas", { exact: true })).toHaveValue("pt-BR");

  await own.page.goto(`${env.adminUrl}/account/phone?ui_locales=es`);
  await expect(html).toHaveAttribute("lang", "pt-BR");
  await expect(phoneHint("Digite o número como é discado de outro país, depois do código do país.")).toBeVisible();

  await own.page.goto(`${env.adminUrl}/account/profile`);
  await own.page.getByLabel("Idioma das páginas", { exact: true }).selectOption("");
  await own.page.getByRole("button", { name: "Salvar", exact: true }).click();
  await expect(own.page.getByText("Profile saved.", { exact: true })).toBeVisible();
  await expect(html).toHaveAttribute("lang", "en");
  await expect(pageLanguage).toHaveValue("");

  await own.page.goto(`${env.adminUrl}/account/phone?ui_locales=es`);
  await expect(html).toHaveAttribute("lang", "es");
  await expect(phoneHint("Escribe el número tal como se marca desde otro país, sin el prefijo de país.")).toBeVisible();
  await own.context.close();
});

// The console's own sentence for the auth server's 429, as password-and-otp.spec.ts reads it.
const tooManyAttempts = "Too many requests have come from this browser, or for this account, in a short time. Please wait a few minutes and try again.";

test("the user changes their email with their password, which must be right and confirmed, five times an hour", async ({ page, browser, users }) => {
  const user = await users.create();
  const other = await users.create();
  const newEmail = `${uniqueIdentifier("u")}@example.com`;
  const own = await signInToConsole(browser, user, "/account/email");
  const submit = async (email: string, confirmation: string, password: string) => {
    await own.page.locator("#email").fill(email);
    await own.page.locator("#emailConfirmation").fill(confirmation);
    await own.page.locator("#currentPassword").fill(password);
    await own.page.getByRole("button", { name: "Change email" }).click();
  };

  await submit(newEmail, `x${newEmail}`, user.password);
  await expectRefusal(own.page, "email-error", "emailConfirmation", "The email addresses don't match.");
  await submit(newEmail, newEmail, "");
  await expectRefusal(own.page, "email-error", "currentPassword", "Current password is required.");
  await submit(newEmail, newEmail, "not-the-password");
  await expectRefusal(own.page, "email-error", "currentPassword", "That password isn't right. Try again.");
  // Whether another account has the address is said only once the password is right.
  await submit(other.email, other.email, user.password);
  await expectRefusal(own.page, "email-error", "email", "Apologies, but this email address is already registered.");
  await submit(newEmail, newEmail, user.password);
  await expect(own.page.getByText("Email changed.", { exact: true })).toBeVisible();

  // Every change counts against the account, five an hour, whatever the address and whether the
  // password was right, since past the password the answer says whether an address is taken (#683).
  // Counted by the user whatever the rate limiter switch says: the four above that reached the auth
  // server (the mismatch is the console's own) and this idle re-save of the address it now has, which
  // changes nothing and is answered as a change, are five.
  const currentPassword = own.page.locator("#currentPassword");
  await submit(newEmail, newEmail, user.password);
  await expect(currentPassword).toHaveValue("");
  await expect(own.page.getByText("Email changed.", { exact: true })).toBeVisible();
  // The sixth is refused with the right password and a free address, on the form, not the error page.
  const freeEmail = `${uniqueIdentifier("u")}@example.com`;
  await submit(freeEmail, freeEmail, user.password);
  await expect(own.page.locator("#email-error")).toContainText(tooManyAttempts);
  await expect(own.page.locator("#email")).toHaveValue(freeEmail);
  await expect(currentPassword).toHaveValue("");
  await expect(own.page.getByRole("heading", { name: "Something went wrong" })).toHaveCount(0);
  await expect(own.page.getByRole("button", { name: "Change email" })).toBeVisible();

  // A new address starts unverified, and the one refused above was not stored; verifying it with the
  // mailed code is in email.spec.ts.
  await own.page.goto(`${env.adminUrl}/account/email-verification`);
  await expect(own.page.locator("main").getByText(newEmail, { exact: true })).toBeVisible();
  await expect(own.page.getByText("Not verified", { exact: true })).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "email"));
  await expect(page.locator("#email")).toHaveValue(newEmail);
  await expect(page.locator("#emailVerified")).not.toBeChecked();
});

test("a verified address is said to be verified, with no code to ask for", async ({ browser, users }) => {
  const user = await users.create({ emailVerified: true });
  const own = await signInToConsole(browser, user, "/account/email-verification");
  await expect(own.page.locator("main").getByText(user.email, { exact: true })).toBeVisible();
  await expect(own.page.getByText("Verified", { exact: true })).toBeVisible();
  await expect(own.page.getByRole("button", { name: "Send code" })).toHaveCount(0);
  await expect(own.page.locator("#verificationCode")).toHaveCount(0);
  await own.context.close();
});

test("a second verification code asked for at once is refused, saying how long to wait", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/email-verification");
  const send = own.page.getByRole("button", { name: "Send code" });
  const status = own.page.locator("#verification-status");
  await send.click();
  await expect(status).toHaveText(`We sent a code to ${user.email}. Check your inbox and spam folder.`);
  // One code per address for as long as a code lasts, the wait written as a duration of at most
  // five minutes, in minutes and seconds.
  await send.click();
  await expect(status).toHaveText(/^Wait (\d+ minutes?(, \d+ seconds?)?|\d+ seconds?) before asking for another code\.$/);
  await own.context.close();
});

test("on a page in Portuguese, the wait for a second verification code is said in Portuguese", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/email-verification");
  await own.page.goto(`${env.adminUrl}/account/email-verification?ui_locales=pt-BR`);
  await expect(own.page.locator("html")).toHaveAttribute("data-catalog-lang", "pt-BR");
  const send = own.page.getByRole("button", { name: "Enviar código" });
  const status = own.page.locator("#verification-status");
  await send.click();
  await expect(status).toHaveText(`Enviamos um código para ${user.email}. Verifique sua caixa de entrada e a pasta de spam.`);
  await send.click();
  await expect(status).toHaveText(/^Aguarde (\d+ minutos?( e \d+ segundos?)?|\d+ segundos?) antes de pedir outro código\.$/);
  await own.context.close();
});

test("the user saves their phone, and the administrator sees it", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/phone");
  const save = own.page.getByRole("button", { name: "Save", exact: true });
  const country = own.page.getByRole("combobox", { name: "Country" });
  const countrySelect = own.page.locator('select[name="phoneCountryUniqueId"]');
  await expect(own.page.getByText("Enter the number as it's dialled from another country, after the country code.")).toBeVisible();
  // The page loads its country list for a user who is not an administrator too.
  await country.fill("Portugal");
  await expect(own.page.locator("#phoneCountryUniqueId-options").getByRole("option", { name: /Portugal \(\+351\)/ })).toBeVisible();
  await country.press("Enter");
  const portugal = await countrySelect.inputValue();
  expect(portugal).not.toBe("");
  // A refused number draws the page again, country list and all, with the refusal on it.
  await own.page.locator("#phoneNumber").fill("91x 345 678");
  await save.click();
  await expectRefusal(own.page, "phone-error", "phoneNumber", "Please enter a valid number.");
  await expect(countrySelect).toHaveValue(portugal);
  await expect(country).toHaveValue(/Portugal \(\+351\)/);
  await own.page.locator("#phoneNumber").fill("912 345 678");
  await save.click();
  await expect(own.page.getByText("Phone number saved.", { exact: true })).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "phone"));
  await expect(page.locator('select[name="phoneCountryUniqueId"]')).toHaveValue(portugal);
  await expect(page.locator("#phoneNumber")).toHaveValue("912 345 678");
});

test("the user saves their address, and the administrator sees it", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/address");
  await own.page.locator("#addressLine1").fill("Rua Augusta 100");
  await own.page.locator("#addressLocality").fill("Lisboa");
  await own.page.locator("#addressPostalCode").fill("1100-053");
  const country = own.page.getByRole("combobox", { name: "Country" });
  await country.fill("portugal");
  await country.press("Enter");
  await expect(country).toHaveValue(/Portugal$/);
  await own.page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(own.page.getByText("Address saved.", { exact: true })).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "address"));
  await expect(page.locator("#addressLine1")).toHaveValue("Rua Augusta 100");
  await expect(page.locator("#addressPostalCode")).toHaveValue("1100-053");
  await expect(page.locator('select[name="addressCountry"]')).toHaveValue("PT");
});
