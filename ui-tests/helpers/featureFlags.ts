/**
 * Feature flags for a spec. `withFeatureFlag` sets one on the dashboard's own
 * copy of the settings (the `GET /api/v1/user-settings` answer) so the
 * appliance's stored settings are never changed by a test. `setSystemFeatureFlag`
 * is for the few specs whose behaviour the gateway itself checks against the
 * flag: it changes the stored flag and returns the function that restores it.
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

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Sets `flag` in the appliance's stored system settings and returns a function
 * that puts that one flag back as it was, leaving every other flag as it is
 * then. `POST /api/v1/settings` replaces the whole flag map, so each write
 * reads the current flags first and sends them all, except `terms`, which the
 * API reports from the network configuration rather than storing. It refuses
 * a gateway that is not on this machine unless `AG_ALLOW_REMOTE_FLAG_WRITES=1`.
 */
export async function setSystemFeatureFlag(
  request: APIRequestContext,
  baseUrl: string,
  flag: string,
  enabled = true,
): Promise<() => Promise<void>> {
  if (
    !LOCAL_HOSTS.has(new URL(baseUrl).hostname) &&
    process.env.AG_ALLOW_REMOTE_FLAG_WRITES !== "1"
  ) {
    throw new Error(
      `Refusing to set ${flag} on ${baseUrl}: set AG_ALLOW_REMOTE_FLAG_WRITES=1 to change a gateway that is not on this machine`,
    );
  }
  const auth = await authenticateTestUser(request, baseUrl);
  if (!auth.success || !auth.sessionToken) {
    throw new Error(`Could not sign in to set ${flag}: ${auth.error}`);
  }
  const headers = { Authorization: `Bearer ${auth.sessionToken}` };
  const readFlags = async (): Promise<Record<string, boolean>> => {
    const read = await request.get(`${baseUrl}/api/v1/settings`, { headers });
    if (!read.ok()) {
      throw new Error(`Could not read the feature flags: ${read.status()}`);
    }
    const flags: Record<string, boolean> = {
      ...((await read.json())?.feature_flags ?? {}),
    };
    delete flags.terms;
    return flags;
  };
  const save = async (flags: Record<string, boolean>) => {
    const saved = await request.post(`${baseUrl}/api/v1/settings`, {
      headers,
      data: { feature_flags: flags },
    });
    if (!saved.ok()) {
      throw new Error(`Could not save the feature flags: ${saved.status()}`);
    }
  };
  const current = await readFlags();
  const previous = Object.hasOwn(current, flag) ? current[flag] : undefined;
  await save({ ...current, [flag]: enabled });
  return async () => {
    const flags = await readFlags();
    delete flags[flag];
    if (previous !== undefined) flags[flag] = previous;
    await save(flags);
  };
}
