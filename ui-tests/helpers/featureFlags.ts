/**
 * Feature flags for a spec. `withFeatureFlag` sets one on the dashboard's own
 * copy of the settings (the `GET /api/v1/user-settings` answer) so the
 * appliance's stored settings are never changed by a test. `setSystemFeatureFlag`
 * is for the few specs whose behaviour the gateway itself checks against the
 * flag: it changes the stored settings and returns the function that restores
 * them.
 */

import type { APIRequestContext, Page } from "@playwright/test";
import { authenticateTestUser } from "./test-auth";

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

/**
 * Sets `flag` in the appliance's stored system settings and returns a function
 * that puts the stored flags back as they were. `POST /api/v1/settings`
 * replaces the whole flag map, so every other flag is sent unchanged, except
 * `terms`, which the API reports from the network configuration rather than
 * storing.
 */
export async function setSystemFeatureFlag(
  request: APIRequestContext,
  baseUrl: string,
  flag: string,
  enabled = true,
): Promise<() => Promise<void>> {
  const auth = await authenticateTestUser(request, baseUrl);
  if (!auth.success || !auth.sessionToken) {
    throw new Error(`Could not sign in to set ${flag}: ${auth.error}`);
  }
  const headers = { Authorization: `Bearer ${auth.sessionToken}` };
  const read = await request.get(`${baseUrl}/api/v1/settings`, { headers });
  if (!read.ok()) {
    throw new Error(`Could not read the settings to set ${flag}: ${read.status()}`);
  }
  const previous: Record<string, boolean> = {
    ...((await read.json())?.feature_flags ?? {}),
  };
  delete previous.terms;
  const save = async (flags: Record<string, boolean>) => {
    const saved = await request.post(`${baseUrl}/api/v1/settings`, {
      headers,
      data: { feature_flags: flags },
    });
    if (!saved.ok()) {
      throw new Error(`Could not save the feature flags: ${saved.status()}`);
    }
  };
  await save({ ...previous, [flag]: enabled });
  return () => save(previous);
}
