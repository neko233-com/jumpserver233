import { expect, test } from "@playwright/test";

test.use({ baseURL: "http://127.0.0.1:15180", locale: "en-US" });

test("runtime logs rotate and replay safely without secure-context randomUUID", async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.addInitScript(() => {
    Object.defineProperty(Crypto.prototype, "randomUUID", { value: undefined, configurable: true });
  });
  await page.goto("/login");
  await page.getByLabel("Username", { exact: true }).fill("root");
  await page.getByLabel("Password", { exact: true }).fill("root");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/console/);
  await page.goto("/console/settings");
  await page.getByRole("tab", { name: "Security", exact: true }).click();
  const section = page.getByRole("region", { name: "Runtime logs", exact: true });
  await expect(section.getByText("Disk usage", { exact: true })).toBeVisible();
  const before = await (await page.request.get("/api/v1/settings/security/runtime-logs")).json();
  expect(before.enabled).toBe(true);
  const sending = page.waitForRequest(
    (r) => r.method() === "POST" && r.url().endsWith("/runtime-logs/rotate"),
  );
  await section.getByRole("button", { name: "Rotate now", exact: true }).click();
  const input = (await sending).postDataJSON();
  expect(input.request_id).toMatch(
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
  );
  await expect(section.getByRole("status")).toContainText("Rotation completed");
  const replay = await page.request.post("/api/v1/settings/security/runtime-logs/rotate", {
    data: input,
  });
  expect(replay.status()).toBe(200);
  const after = (await replay.json()).status;
  expect(after.revision).toBeGreaterThanOrEqual(before.status.revision);
  const conflict = await page.request.post("/api/v1/settings/security/runtime-logs/rotate", {
    data: { ...input, revision: -1, request_id: input.request_id + "-stale" },
  });
  expect(conflict.status()).toBe(409);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(section.getByRole("button", { name: "Refresh status", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
