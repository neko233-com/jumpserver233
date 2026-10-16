import { expect, test } from "@playwright/test";
import { normalizeDateTimeLocal } from "./date-time.js";

test("scheduled input values match browser normalization at zero seconds", async ({ page }) => {
  await page.setContent('<label>Schedule<input type="datetime-local" step="1"></label>');
  const field = page.getByLabel("Schedule", { exact: true });
  for (const [input, expected] of [
    ["2026-10-16T08:17:00", "2026-10-16T08:17"],
    ["2026-10-16T08:17:01", "2026-10-16T08:17:01"],
    ["2026-10-16T08:00", "2026-10-16T08:00"],
    ["2026-10-16T00:00:00", "2026-10-16T00:00"],
  ]) {
    const value = normalizeDateTimeLocal(input);
    expect(value).toBe(expected);
    await field.fill(value);
    await expect(field).toHaveValue(expected);
  }
});
