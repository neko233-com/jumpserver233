import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";
test.use({ locale: "en-US", trace: "off", screenshot: "off" });

test("global organization counts retain scope, disabled stores and revocation across bilingual views", async ({
  page,
  browser,
}, info) => {
  test.setTimeout(120000);
  const api = page.request;
  const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  if (!login.ok()) {
    await api.post("/api/v1/authentication/bootstrap", { data: credentials });
    login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  }
  expect(login.status()).toBe(200);
  const origin = new URL(info.project.use.baseURL as string).origin;
  await page
    .context()
    .addCookies([
      {
        name: "jms_sessionid",
        value: (await login.json()).access_token,
        url: origin,
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);
  const stamp = randomUUID();
  let org = "",
    disabled = "",
    asset = "",
    user = "",
    role = "";
  const other = await browser.newContext({ locale: "en-US" });
  const operator = await other.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  operator.on("pageerror", (e) => errors.push(e.message));
  try {
    const created = await api.post("/api/v1/organizations", {
      data: { name: "Overview " + stamp, enabled: true },
    });
    expect(created.status()).toBe(201);
    const organization = await created.json();
    org = organization.id;
    const inactive = await api.post("/api/v1/organizations", {
      data: { name: "Disabled " + stamp, enabled: false },
    });
    expect(inactive.status()).toBe(201);
    disabled = (await inactive.json()).id;
    const host = await (await api.get("http://127.0.0.1:12242/health")).json();
    const remote = await api.post("/api/v1/assets", {
      headers: { "X-JMS-ORG": org },
      data: {
        name: "Private host " + stamp,
        host: "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: host.fingerprint,
      },
    });
    expect(remote.status()).toBe(201);
    asset = (await remote.json()).id;
    const probe = await api.post(`/api/v1/assets/${asset}/probe`, {
      headers: { "X-JMS-ORG": org },
    });
    expect(probe.status()).toBe(200);
    expect((await probe.json()).monitor.state).toBe("online");
    const account = {
      username: "overview." + stamp.replaceAll("-", "").slice(0, 20),
      password: "synthetic-overview-operator-password",
    };
    const person = await api.post("/api/v1/users", { data: { ...account, role: "operator" } });
    expect(person.status()).toBe(201);
    user = (await person.json()).id;
    const signIn = await other.request.post(origin + "/api/v1/authentication/auth/", {
      data: account,
    });
    expect(signIn.status()).toBe(200);
    await other.addCookies([
      {
        name: "jms_sessionid",
        value: (await signIn.json()).access_token,
        url: origin,
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);
    expect((await other.request.get(origin + "/api/v1/organizations/overview")).status()).toBe(403);
    const reader = await api.post("/api/v1/rbac/roles", {
      data: { name: "Overview reader " + stamp, permissions: ["organizations.overview"] },
    });
    expect(reader.status()).toBe(201);
    role = (await reader.json()).id;
    const binding = await api.put("/api/v1/rbac/bindings", {
      data: { subject_type: "user", subject_id: user, role_ids: [role], revision: 0 },
    });
    expect(binding.status()).toBe(200);
    const summary = await api.get("/api/v1/organizations/overview", {
      headers: { "X-JMS-ORG": org },
    });
    expect(summary.status()).toBe(200);
    const result = await summary.json();
    const row = result.results.find((v: { id: string }) => v.id === org);
    expect(row.counts.assets).toBe(1);
    expect(row.counts.online).toBe(1);
    expect(row.counts.protocols).toEqual({ ssh: 1 });
    const dormant = result.results.find((v: { id: string }) => v.id === disabled);
    expect(dormant.state).toBe("disabled");
    expect(dormant.counts).toBeNull();
    expect(JSON.stringify(result)).not.toContain("synthetic-keyhost-password-233");
    expect(JSON.stringify(result)).not.toContain("Private host " + stamp);
    await operator.goto(origin + "/console/organization-overview");
    await expect(
      operator.getByRole("heading", { name: "Global organization overview", exact: true }),
    ).toBeVisible();
    await operator.getByLabel("Filter organizations", { exact: true }).fill("Overview " + stamp);
    await expect(
      operator.getByRole("rowheader", { name: "Overview " + stamp, exact: true }),
    ).toBeVisible();
    await page.goto("/console/organization-overview");
    await page.getByLabel("Filter organizations", { exact: true }).fill("Overview " + stamp);
    await expect(
      page.getByRole("rowheader", { name: "Overview " + stamp, exact: true }),
    ).toBeVisible();
    await page.screenshot({
      path: info.outputPath("organization-overview.en.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("heading", { name: "全局组织汇总", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await page.screenshot({
      path: info.outputPath("organization-overview.zh.narrow.png"),
      fullPage: true,
    });
    const roles = await (await api.get("/api/v1/rbac/roles")).json();
    const current = roles.find((v: { id: string }) => v.id === role);
    expect(
      (
        await api.put("/api/v1/rbac/roles/" + role, {
          data: { name: current.name, revision: current.revision, permissions: [] },
        })
      ).status(),
    ).toBe(200);
    await operator
      .getByRole("button", { name: "Refresh organization overview", exact: true })
      .click();
    await expect(operator.getByRole("alert")).toBeVisible();
    await expect(
      operator.getByRole("rowheader", { name: "Overview " + stamp, exact: true }),
    ).toHaveCount(0);
    expect((await other.request.get(origin + "/api/v1/organizations/overview")).status()).toBe(403);
    expect(errors).toEqual([]);
  } finally {
    try {
      for (let round = 0; round < 2; round++) {
        if (asset && org)
          expect([200, 204, 404]).toContain(
            (
              await api.delete("/api/v1/assets/" + asset, { headers: { "X-JMS-ORG": org } })
            ).status(),
          );
        for (const id of [org, disabled].filter(Boolean)) {
          const organizations = await (
            await api.get("/api/v1/organizations?include_archived=true")
          ).json();
          const current = organizations.results.find((v: { id: string }) => v.id === id);
          if (current && !current.archived_at)
            expect(
              (
                await api.delete(`/api/v1/organizations/${id}?revision=${current.revision}`)
              ).status(),
            ).toBe(204);
        }
        if (user) {
          const bindings = await (await api.get("/api/v1/rbac/bindings")).json();
          const binding = bindings.find(
            (v: { subject_type: string; subject_id: string }) =>
              v.subject_type === "user" && v.subject_id === user,
          );
          if (binding?.role_ids.length)
            expect(
              (
                await api.put("/api/v1/rbac/bindings", {
                  data: {
                    subject_type: "user",
                    subject_id: user,
                    role_ids: [],
                    revision: binding.revision,
                  },
                })
              ).status(),
            ).toBe(200);
          const current = await (await api.get("/api/v1/users/" + user)).json();
          if (!current.archived_at)
            expect(
              (await api.delete(`/api/v1/users/${user}?revision=${current.revision}`)).status(),
            ).toBe(200);
        }
        if (role) {
          const roles = await (await api.get("/api/v1/rbac/roles")).json();
          const current = roles.find((v: { id: string }) => v.id === role);
          if (current)
            expect([200, 204]).toContain(
              (
                await api.delete(`/api/v1/rbac/roles/${role}?revision=${current.revision}`)
              ).status(),
            );
        }
      }
    } finally {
      await other.close();
    }
  }
});
