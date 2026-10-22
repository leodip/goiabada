// What a group means outside the Groups pages: its members' tokens carry the group, its attributes and
// its permissions, each as the include switches say, and a change on the Groups pages shows in the
// next token. The tokens come from the password grant, on a client of the test's own that allows it.
import { addGroupAttribute, addGroupMember, confirmDialog, grantGroupPermission, groupUrl, rowWithCell } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken, userTokens, userinfo } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

test("the groups claim follows each group's include switches, in each token and at userinfo", async ({
  page,
  request,
  clients,
  groups,
  users,
}) => {
  const both = await groups.create();
  const accessOnly = await groups.create({ includeInIdToken: false });
  const idOnly = await groups.create({ includeInAccessToken: false });
  const user = await users.create();
  for (const group of [both, accessOnly, idOnly]) await addGroupMember(page, group.id, user.email);
  const { client, secret } = await passwordGrantClient(page, clients);

  const tokens = await userTokens(request, client.identifier, secret, user, "openid groups");
  expect((tokens.access.groups as string[]).sort()).toEqual([both.identifier, accessOnly.identifier].sort());
  expect((tokens.id.groups as string[]).sort()).toEqual([both.identifier, idOnly.identifier].sort());
  // Userinfo filters by the ID token's switch.
  const info = await userinfo(request, tokens.body.access_token as string);
  expect(info.status, JSON.stringify(info.body)).toBe(200);
  expect((info.body.groups as string[]).sort()).toEqual([both.identifier, idOnly.identifier].sort());

  // Without the groups scope there is no groups claim at all.
  const withoutScope = await userTokens(request, client.identifier, secret, user, "openid");
  expect(withoutScope.access.groups).toBeUndefined();
  expect(withoutScope.id.groups).toBeUndefined();
});

test("a change to a group shows in the next token: switches, rename, removal", async ({
  page,
  request,
  clients,
  groups,
  users,
}) => {
  const group = await groups.create();
  const user = await users.create();
  await addGroupMember(page, group.id, user.email);
  const { client, secret } = await passwordGrantClient(page, clients);
  expect((await userTokens(request, client.identifier, secret, user, "openid groups")).access.groups).toEqual([group.identifier]);

  await page.goto(groupUrl(group.id, "settings"));
  await page.locator('input[name="includeInAccessToken"]').uncheck();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Settings saved.")).toBeVisible();
  let tokens = await userTokens(request, client.identifier, secret, user, "openid groups");
  expect(tokens.access.groups).toBeUndefined();
  expect(tokens.id.groups).toEqual([group.identifier]);

  const renamed = `${group.identifier}-r`;
  await page.locator("#groupIdentifier").fill(renamed);
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're changing the group identifier");
  // The page the save before left says "Settings saved." too, so the rename's answer is the heading
  // naming the group as renamed.
  await expect(page.getByRole("heading", { level: 1, name: renamed, exact: true })).toBeVisible();
  await expect(page.getByText("Settings saved.")).toBeVisible();
  expect((await userTokens(request, client.identifier, secret, user, "openid groups")).id.groups).toEqual([renamed]);

  await page.goto(groupUrl(group.id, "members"));
  await rowWithCell(page, user.email).getByRole("button", { name: `Remove ${user.email}`, exact: true }).click();
  await confirmDialog(page, `Remove ${user.email} from the group?`);
  await expect(rowWithCell(page, user.email).getByText("Removed", { exact: true })).toBeVisible();
  tokens = await userTokens(request, client.identifier, secret, user, "openid groups");
  expect(tokens.id.groups).toBeUndefined();
});

test("group attributes reach the attributes claim as their switches say", async ({ page, request, clients, groups, users }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales" });
  await addGroupAttribute(page, group.id, { key: "cost_center", value: "CC-42", includeInIdToken: false });
  await addGroupAttribute(page, group.id, { key: "badge", value: "blue", includeInAccessToken: false });
  const user = await users.create();
  await addGroupMember(page, group.id, user.email);
  const { client, secret } = await passwordGrantClient(page, clients);

  const tokens = await userTokens(request, client.identifier, secret, user, "openid attributes");
  expect(tokens.access.attributes).toEqual({ department: "Sales", cost_center: "CC-42" });
  expect(tokens.id.attributes).toEqual({ department: "Sales", badge: "blue" });
  const info = await userinfo(request, tokens.body.access_token as string);
  expect(info.body.attributes).toEqual({ department: "Sales", badge: "blue" });

  const withoutScope = await userTokens(request, client.identifier, secret, user, "openid");
  expect(withoutScope.access.attributes).toBeUndefined();
});

test("a member holds the group's permissions, and loses them when removed", async ({
  page,
  request,
  clients,
  groups,
  resources,
  users,
}) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const group = await groups.create();
  await grantGroupPermission(page, group.id, resource.identifier, "read");
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const scope = `openid ${resource.identifier}:read`;

  // Not a member yet.
  let answer = await passwordToken(request, client.identifier, secret, user.email, user.password, scope);
  expect(answer.body.error, JSON.stringify(answer.body)).toBe("invalid_scope");

  await addGroupMember(page, group.id, user.email);
  const tokens = await userTokens(request, client.identifier, secret, user, scope);
  expect(String(tokens.access.scope).split(" ")).toContain(`${resource.identifier}:read`);
  expect(tokens.access.aud).toContain(resource.identifier);
  // The group holds read, not write.
  answer = await passwordToken(request, client.identifier, secret, user.email, user.password, `openid ${resource.identifier}:write`);
  expect(answer.body.error).toBe("invalid_scope");

  await page.goto(groupUrl(group.id, "members"));
  await rowWithCell(page, user.email).getByRole("button", { name: `Remove ${user.email}`, exact: true }).click();
  await confirmDialog(page, `Remove ${user.email} from the group?`);
  await expect(rowWithCell(page, user.email).getByText("Removed", { exact: true })).toBeVisible();
  answer = await passwordToken(request, client.identifier, secret, user.email, user.password, scope);
  expect(answer.body.error).toBe("invalid_scope");
});
