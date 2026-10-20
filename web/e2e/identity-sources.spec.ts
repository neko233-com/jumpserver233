import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";

test.use({ locale: "en-US", trace: "off" });
test("isolates named LDAP identities and applies complete directory mappings with bilingual UI", async ({
  page,
  browser,
}, testInfo) => {
  test.setTimeout(90_000);
  const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  let login = await page.request.post("/api/v1/authentication/auth/", { data: credentials });
  if (login.status() !== 200) {
    const bootstrap = await page.request.post("/api/v1/authentication/bootstrap", {
      data: credentials,
    });
    expect([201, 409]).toContain(bootstrap.status());
    login = await page.request.post("/api/v1/authentication/auth/", { data: credentials });
  }
  expect(login.status()).toBe(200);
  const { access_token } = await login.json();
  const origin = new URL(testInfo.project.use.baseURL as string).origin;
  await page
    .context()
    .addCookies([
      { name: "jms_sessionid", value: access_token, url: origin, httpOnly: true, sameSite: "Lax" },
    ]);
  const api = page.request;
  const uid = randomUUID();
  const sourceIDs: string[] = [];
  let group = "";
  let organization = "";
  let child: Awaited<ReturnType<typeof browser.newContext>> | undefined;
  try {
    await page.goto("/console/identity-sources");
    await expect(
      page.getByRole("heading", { name: "Identity sources", exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Add source", exact: true }).click();
    await page.getByLabel("Name", { exact: true }).fill("Directory " + uid);
    await page.getByRole("checkbox", { name: "Enabled", exact: true }).check();
    const created = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/identity-sources") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const source = await (await created).json();
    expect(source.id).toMatch(/^idp-[a-f0-9]{32}$/);
    sourceIDs.push(source.id);
    const fixture = await (await api.get("http://127.0.0.1:12230/health")).json();
    const base = "/api/v1/identity-sources/" + source.id;
    const config = {
      url: fixture.url,
      ca_pem: fixture.ca_pem,
      base_dn: "dc=example,dc=test",
      bind_dn: "cn=reader,dc=example,dc=test",
      filter: "(uid={username})",
      identity_attribute: "entryUUID",
      enabled: true,
      provision_new: false,
      revision: 0,
      bind_password: "synthetic-directory-reader-password",
    };
    expect(
      (await api.put(base + "/api/v1/settings/security/ldap", { data: config })).status(),
    ).toBe(200);
    const g = await api.post("/api/v1/system/user-groups", {
      data: { name: "Directory group " + uid },
    });
    expect(g.status()).toBe(201);
    group = (await g.json()).id;
    const o = await api.post("/api/v1/organizations", {
      data: { name: "Directory org " + uid, enabled: true, revision: 0 },
    });
    expect(o.status()).toBe(201);
    organization = (await o.json()).id;
    await page.goto("/console/directory-sync?source_id=" + source.id);
    await expect(
      page.getByRole("heading", { name: "Directory synchronization", exact: true }),
    ).toBeVisible();
    await page.getByLabel("Group base DN", { exact: true }).fill("ou=groups,dc=example,dc=test");
    await page
      .getByLabel("Group search filter", { exact: true })
      .fill("(objectClass=groupOfNames)");
    await page.getByRole("button", { name: "Add mapping", exact: true }).click();
    await page
      .getByLabel("Directory group DN", { exact: true })
      .fill("cn=operators,ou=groups,dc=example,dc=test");
    await page.getByLabel("Platform groups", { exact: true }).selectOption(group);
    await page.getByLabel("Organization", { exact: true }).selectOption(organization);
    const saved = page.waitForResponse(
      (r) => r.url().endsWith("/sync") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save", exact: true }).click();
    expect((await saved).status()).toBe(200);
    await page.getByRole("button", { name: "Collect preview", exact: true }).click();
    await expect(page.getByText("1 users and 1 groups collected.", { exact: true })).toBeVisible();
    const applying = page.waitForResponse(
      (r) => r.url().endsWith("/sync/apply") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Apply complete snapshot", exact: true }).click();
    const applyResponse = await applying;
    expect(applyResponse.status()).toBe(200);
    const original = applyResponse.request().postDataJSON();
    const run = await applyResponse.json();
    const replay = await api.post(base + "/sync/apply", { data: original });
    expect(await replay.json()).toEqual(run);
    await expect(page.getByText("directory.user", { exact: true })).toBeVisible();
    const entries = (await (await api.get(base + "/sync/entries")).json()).items;
    expect(entries).toHaveLength(1);
    const user = entries[0].user_id;
    const members = await (await api.get(`/api/v1/organizations/${organization}/members`)).json();
    expect(
      members.some(
        (m: { user_id: string; source_id: string }) =>
          m.user_id === user && m.source_id === source.id,
      ),
    ).toBe(true);
    // The same directory subject in a different source creates a distinct user.
    const second = await api.post("/api/v1/identity-sources", {
      data: {
        name: "Second directory " + uid,
        kind: "ldap",
        enabled: true,
        archived: false,
        revision: 0,
        request_id: "source-" + randomUUID(),
      },
    });
    expect(second.status()).toBe(201);
    const other = await second.json();
    sourceIDs.push(other.id);
    const otherBase = "/api/v1/identity-sources/" + other.id;
    expect(
      (
        await api.put(otherBase + "/api/v1/settings/security/ldap", {
          data: { ...config, provision_new: true },
        })
      ).status(),
    ).toBe(200);
    child = await browser.newContext({ baseURL: origin, locale: "en-US" });
    const userPage = await child.newPage();
    await userPage.goto("/login");
    await userPage.getByLabel("Sign-in source", { exact: true }).selectOption(source.id);
    await userPage.getByLabel("Username", { exact: true }).fill("directory.user");
    await userPage
      .getByLabel("Password", { exact: true })
      .fill("synthetic-directory-user-password");
    await userPage.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(userPage).toHaveURL(/\/console$/);
    const me = await (await userPage.request.get("/api/v1/users/me")).json();
    expect(me.source_id).toBe(source.id);
    const alternate = await api.post(otherBase + "/api/v1/settings/security/ldap/users", {
      data: { directory_username: "directory.user", username: "" },
    });
    expect(alternate.status()).toBe(201);
    expect((await alternate.json()).id).not.toBe(user);
    const current = await (await api.get(base)).json();
    expect(
      (
        await api.put(base, {
          data: {
            name: current.name,
            kind: "ldap",
            enabled: false,
            archived: false,
            revision: current.revision,
            request_id: "disable-" + randomUUID(),
          },
        })
      ).status(),
    ).toBe(200);
    expect((await userPage.request.get("/api/v1/users/me")).status()).toBe(401);
    await page.goto("/console/identity-sources");
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(
      page.getByRole("heading", { name: "Identity sources", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.screenshot({ path: testInfo.outputPath("identity-sources-en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "身份源", exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("identity-sources-zh.png"), fullPage: true });
  } finally {
    await child?.close();
    for (const id of sourceIDs) {
      const base = "/api/v1/identity-sources/" + id;
      const r = await api.get(base);
      if (r.ok()) {
        const value = await r.json();
        if (!value.archived)
          expect(
            (
              await api.put(base, {
                data: {
                  name: value.name,
                  kind: value.kind,
                  enabled: false,
                  archived: true,
                  revision: value.revision,
                  request_id: "cleanup-" + randomUUID(),
                },
              })
            ).status(),
          ).toBe(200);
      }
    }
    if (group)
      expect([204, 404]).toContain(
        (await api.delete("/api/v1/system/user-groups/" + group)).status(),
      );
    if (organization) {
      const all = await (await api.get("/api/v1/organizations")).json();
      const value = all.results.find((v: { id: string }) => v.id === organization);
      if (value)
        expect(
          (
            await api.delete(
              "/api/v1/organizations/" + organization + "?revision=" + value.revision,
            )
          ).status(),
        ).toBe(204);
    }
  }
});
