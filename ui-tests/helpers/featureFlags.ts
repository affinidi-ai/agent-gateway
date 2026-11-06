/**
 * Feature flags for a spec, set on the dashboard's own copy of the settings
 * (the `GET /api/v1/user-settings` answer) so the appliance's stored settings
 * are never changed by a test.
 */

import type { Page } from "@playwright/test";

export async function withFeatureFlag(
  page: Page,
  flag: string,
  enabled = true,
): Promise<void> {
  await page.route("**/api/v1/user-settings", async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const response = await route.fetch();
    const body = await response.json();
    await route.fulfill({
      response,
      json: {
        ...body,
        feature_flags: { ...(body?.feature_flags ?? {}), [flag]: enabled },
      },
    });
  });
}
