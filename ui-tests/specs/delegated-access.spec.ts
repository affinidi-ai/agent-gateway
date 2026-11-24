import { expect, test } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const fromNow = (ms: number) => new Date(Date.now() + ms).toISOString();

const AGENT_DID = "did:web:agent.example.com";
const ALICE = `sha256:${"a".repeat(64)}`;
const BOB = `sha256:${"b".repeat(64)}`;

const token = (
  id: string,
  user: string,
  consentExpiresAt?: string,
): Record<string, unknown> => ({
  id,
  agent_did: AGENT_DID,
  user_identity_hash: user,
  credential_provider_id: "cp-github",
  provider_id: "github",
  token_type: "Bearer",
  scopes: ["repo"],
  expires_at: fromNow(HOUR),
  consent_granted_at: fromNow(-HOUR),
  last_used_at: null,
  created_at: fromNow(-HOUR),
  updated_at: fromNow(-HOUR),
  is_expired: false,
  can_refresh: true,
  ...(consentExpiresAt ? { consent_expires_at: consentExpiresAt } : {}),
});

const row = (page: Page, id: string) =>
  page.getByTestId(`credential-token-row-${id}`);

const accessRow = (page: Page, id: string) =>
  page.getByTestId(`delegated-access-row-${id}`);

/** Answers the vault list with `tokens` and returns the paths of the revokes the page sends. */
async function serveVault(
  page: Page,
  tokens: Record<string, unknown>[],
): Promise<string[]> {
  const revoked: string[] = [];
  await page.route("**/api/v1/delegation-vault**", async (route) => {
    if (route.request().method() === "DELETE") {
      revoked.push(new URL(route.request().url()).pathname);
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({ json: tokens });
  });
  return revoked;
}

/** Answers the provider list with the GitHub provider the tokens belong to. */
async function serveProviders(page: Page): Promise<void> {
  await page.route("**/api/v1/credential-providers", async (route) => {
    await route.fulfill({
      json: [
        {
          id: "cp-github",
          name: "GitHub",
          provider_id: "github",
          provider_type: "oauth2_authorization_code",
          default_scopes: [],
          token_refresh_enabled: true,
        },
      ],
    });
  });
}

/** Opens the Credential Tokens tab over `tokens`. */
async function openCredentialTokens(
  page: Page,
  tokens: Record<string, unknown>[],
): Promise<string[]> {
  await serveProviders(page);
  const revoked = await serveVault(page, tokens);
  await page.goto(`${BASE_URL}/credentials?tab=credential-tokens`);
  await expect(row(page, tokens[0].id as string)).toBeVisible();
  return revoked;
}

test.describe("Credentials page tabs", () => {
  test("keeps Credential Tokens and adds Delegated Access beside it", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/credentials`);

    await expect(
      page.getByTestId("credentials-credential-tokens-tab-trigger"),
    ).toContainText("Credential Tokens");
    await expect(
      page.getByTestId("credentials-delegated-access-tab-trigger"),
    ).toContainText("Delegated Access");
  });

  test("has no audit tab, and a stored address of one opens the first tab", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/credentials?tab=credential-audit`);

    await expect(
      page.getByTestId("credentials-jwt-verification-tab-trigger"),
    ).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tab", { name: /Audit/ })).toHaveCount(0);
    await expect(page.getByTestId("page-audit")).toHaveCount(0);
  });

  test("drops a delegation revoked on Delegated Access from Credential Tokens too, from one read", async ({
    page,
  }) => {
    let reads = 0;
    page.on("request", (request) => {
      if (
        request.method() === "GET" &&
        new URL(request.url()).pathname === "/api/v1/delegation-vault"
      ) {
        reads += 1;
      }
    });
    await serveProviders(page);
    const revoked = await serveVault(page, [
      token("t1", ALICE, fromNow(5 * HOUR)),
      token("t2", BOB),
    ]);
    await page.goto(`${BASE_URL}/credentials?tab=delegated-access`);
    await expect(accessRow(page, "t1")).toBeVisible();

    const revoke = page.getByTestId("delegated-access-revoke-button-t1");
    await revoke.click();
    await revoke.click();
    await expect(accessRow(page, "t1")).toHaveCount(0);

    await page.getByTestId("credentials-credential-tokens-tab-trigger").click();
    await expect(row(page, "t2")).toBeVisible();
    await expect(row(page, "t1")).toHaveCount(0);
    expect(revoked).toEqual(["/api/v1/delegation-vault/t1"]);
    expect(reads).toBe(1);
  });

  test("marks access on Delegated Access once its provider is deactivated on Credential Providers, with no reload", async ({
    page,
  }) => {
    const github = {
      id: "cp-github",
      name: "GitHub",
      provider_id: "github",
      provider_type: "oauth2_authorization_code",
      default_scopes: [],
      token_refresh_enabled: true,
      created_at: "2026-10-30T00:00:00Z",
      updated_at: "2026-10-30T00:00:00Z",
    };
    let deactivatedAt: string | null = null;
    await page.route("**/api/v1/credential-providers", async (route) => {
      await route.fulfill({
        json: [{ ...github, deactivated_at: deactivatedAt }],
      });
    });
    await page.route(
      "**/api/v1/credential-providers/cp-github/*",
      async (route) => {
        deactivatedAt = route.request().url().endsWith("/deactivate")
          ? "2026-11-13T10:00:00Z"
          : null;
        await route.fulfill({
          json: { ...github, deactivated_at: deactivatedAt },
        });
      },
    );
    await serveVault(page, [token("t1", ALICE)]);
    let loads = 0;
    page.on("load", () => {
      loads += 1;
    });
    await page.goto(`${BASE_URL}/credentials?tab=credential-providers`);
    const deactivate = page.getByTestId(
      "credential-provider-deactivate-button-cp-github",
    );

    await deactivate.click();
    await deactivate.click();
    await expect(
      page.getByTestId("credential-provider-deactivated-badge-cp-github"),
    ).toBeVisible();

    await page.getByTestId("credentials-delegated-access-tab-trigger").click();
    await expect(
      page.getByTestId("delegated-access-provider-deactivated-t1"),
    ).toHaveText("No new consent");
    expect(loads).toBe(1);
  });

  test("says the delegations could not be read, not that there are none, and lists them after Retry", async ({
    page,
  }) => {
    await serveProviders(page);
    let refuse = true;
    await page.route("**/api/v1/delegation-vault**", async (route) => {
      if (refuse) {
        await route.fulfill({
          status: 500,
          json: { error: "Failed to list tokens" },
        });
        return;
      }
      await route.fulfill({ json: [token("t1", ALICE)] });
    });
    await page.goto(`${BASE_URL}/credentials?tab=credential-tokens`);

    await expect(
      page.getByTestId("credential-tokens-read-error"),
    ).toContainText("Failed to load delegations: Failed to list tokens");
    await expect(page.getByText("No delegation tokens yet")).toHaveCount(0);

    refuse = false;
    await page.getByTestId("credential-tokens-read-error-retry").click();

    await expect(row(page, "t1")).toBeVisible();
    await expect(page.getByTestId("credential-tokens-read-error")).toHaveCount(
      0,
    );
  });
});

test.describe("Credentials page Delegated Access tab", () => {
  test("lists only active access and opens the Audit Log as its history", async ({
    page,
  }) => {
    await serveProviders(page);
    await serveVault(page, [
      token("soon", ALICE, fromNow(5 * HOUR)),
      token("unlimited", BOB),
      token("ended", BOB, fromNow(-HOUR)),
      { ...token("dead", ALICE), is_expired: true, can_refresh: false },
    ]);
    await page.goto(`${BASE_URL}/credentials?tab=delegated-access`);

    await expect(accessRow(page, "soon")).toBeVisible();
    await expect(accessRow(page, "soon")).toContainText("GitHub");
    await expect(accessRow(page, "soon").getByTitle(AGENT_DID)).toHaveText(
      "agent.example.com",
    );
    await expect(accessRow(page, "soon")).toContainText("Ending soon");
    await expect(page.getByTestId("delegated-access-ends-soon")).toContainText(
      "in 4 hours",
    );
    await expect(page.getByTestId("delegated-access-ends-soon")).toContainText(
      "6-hour limit",
    );
    await expect(
      page.getByTestId("delegated-access-ends-unlimited"),
    ).toHaveText("No time limit");
    await expect(accessRow(page, "ended")).toHaveCount(0);
    await expect(accessRow(page, "dead")).toHaveCount(0);

    await page.getByTestId("delegated-access-history-button").click();

    await expect(page.getByTestId("page-audit")).toBeVisible();
    expect(new URL(page.url()).searchParams.get("category")).toBe(
      "consent_expired,token_revoked,user_tokens_revoked",
    );
  });

  test("revokes one access on a second click that names it, with no dialog", async ({
    page,
  }) => {
    let dialogs = 0;
    page.on("dialog", async (dialog) => {
      dialogs += 1;
      await dialog.dismiss();
    });
    await serveProviders(page);
    const revoked = await serveVault(page, [
      token("t1", ALICE),
      token("t2", BOB),
    ]);
    await page.goto(`${BASE_URL}/credentials?tab=delegated-access`);
    const button = page.getByTestId("delegated-access-revoke-button-t1");
    await expect(button).toHaveText("Revoke");

    await button.click();
    await expect(button).toHaveText("Revoke GitHub access?");
    await expect(
      page.getByTestId("delegated-access-revoke-cancel-button-t1"),
    ).toBeVisible();
    expect(revoked).toEqual([]);
    await expect(accessRow(page, "t1")).toBeVisible();

    await button.click();
    await expect(accessRow(page, "t1")).toHaveCount(0);
    await expect(accessRow(page, "t2")).toBeVisible();
    expect(revoked).toEqual(["/api/v1/delegation-vault/t1"]);
    expect(dialogs).toBe(0);
    await expect(page.locator('[role="dialog"]')).toHaveCount(0);
  });

  test("keeps the access when the revoke is cancelled", async ({ page }) => {
    await serveProviders(page);
    const revoked = await serveVault(page, [token("t1", ALICE)]);
    await page.goto(`${BASE_URL}/credentials?tab=delegated-access`);
    const button = page.getByTestId("delegated-access-revoke-button-t1");

    await button.click();
    await page.getByTestId("delegated-access-revoke-cancel-button-t1").click();

    await expect(button).toHaveText("Revoke");
    await expect(
      page.getByTestId("delegated-access-revoke-cancel-button-t1"),
    ).toHaveCount(0);
    await expect(accessRow(page, "t1")).toBeVisible();
    expect(revoked).toEqual([]);
  });
});

test.describe("Credentials page Credential Tokens tab", () => {
  test("shows when each consent ends and marks one ending within a day or ended", async ({
    page,
  }) => {
    await openCredentialTokens(page, [
      token("soon", ALICE, fromNow(3 * HOUR + 5 * 60_000)),
      token("later", ALICE, fromNow(12 * DAY + HOUR)),
      token("unlimited", BOB),
      token("ended", BOB, fromNow(-HOUR)),
    ]);

    await expect(
      page.getByTestId("credential-token-consent-end-soon"),
    ).toHaveText(/^Ends .+ \(in 3 hours\)$/);
    await expect(row(page, "soon")).toContainText("Ending soon");
    await expect(
      page.getByTestId("credential-token-consent-end-later"),
    ).toHaveText(/^Ends .+ \(in 12 days\)$/);
    await expect(row(page, "later")).toContainText("Active");
    await expect(
      page.getByTestId("credential-token-consent-end-unlimited"),
    ).toHaveText("No time limit");
    await expect(
      page.getByTestId("credential-token-consent-end-ended"),
    ).toHaveText(/^Ended /);
    await expect(row(page, "ended")).toContainText("Consent ended");
    await expect(
      page.getByRole("columnheader", { name: "Access Token" }),
    ).toBeVisible();
    await expect(
      page.getByTestId("credential-token-access-token-later"),
    ).toContainText("Renews automatically");
    await expect(
      page.getByTestId("credential-token-access-token-ended"),
    ).not.toContainText("Renews automatically");
  });

  test("shows its title alone in its header, with no count of tokens or of statuses", async ({
    page,
  }) => {
    await openCredentialTokens(page, [
      token("active", ALICE, fromNow(5 * HOUR)),
      token("unlimited", BOB),
      token("ended", BOB, fromNow(-HOUR)),
    ]);

    await expect(
      page.getByRole("heading", { name: /Credential Delegation Tokens/ }),
    ).toHaveText(/^\s*Credential Delegation Tokens\s*$/);
  });

  test("limits one delegation in place with Limit duration beside Revoke, with no dialog", async ({
    page,
  }) => {
    let dialogs = 0;
    page.on("dialog", async (dialog) => {
      dialogs += 1;
      await dialog.dismiss();
    });
    await openCredentialTokens(page, [
      token("t1", ALICE, fromNow(5 * HOUR)),
      token("ended", BOB, fromNow(-HOUR)),
    ]);
    const limits: unknown[] = [];
    await page.route(
      "**/api/v1/delegation-vault/t1/consent-limit",
      async (route) => {
        limits.push(route.request().postDataJSON());
        await route.fulfill({ json: token("t1", ALICE, fromNow(HOUR)) });
      },
    );
    const button = page.getByTestId("credential-token-limit-button-t1");
    await expect(button).toHaveText("Limit duration");
    await expect(
      row(page, "t1").getByTestId("credential-token-revoke-button-t1"),
    ).toBeVisible();
    await expect(
      page.getByTestId("credential-token-limit-button-ended"),
    ).toHaveCount(0);

    await button.click();
    const panel = page.getByTestId("credential-token-limit-panel-t1");
    const input = page.getByTestId("credential-token-limit-input-t1");
    const save = page.getByTestId("credential-token-limit-save-t1");
    await expect(panel).toContainText("Limit duration · GitHub");
    await expect(page.locator('[role="dialog"]')).toHaveCount(0);
    await expect(input).toHaveValue("6");
    await expect(save).toBeDisabled();

    await input.fill("2");
    await expect(
      page.getByTestId("credential-token-limit-preview-t1"),
    ).toContainText("With this limit it ends");
    await save.click();

    await expect(panel).toHaveCount(0);
    expect(limits).toEqual([{ max_consent_age_secs: 7200 }]);
    await expect(
      page.getByTestId("credential-token-consent-end-t1"),
    ).toHaveText(/\(in (59 minutes|1 hour)\)$/);
    expect(dialogs).toBe(0);
  });

  test("names the agent by its host name and revokes one delegation on a second click", async ({
    page,
  }) => {
    const revoked = await openCredentialTokens(page, [
      token("t1", ALICE),
      token("t2", BOB),
    ]);
    await expect(row(page, "t1").getByTitle(AGENT_DID)).toHaveText(
      "agent.example.com",
    );
    await expect(row(page, "t1").getByRole("cell").first()).toHaveText(
      "GitHub",
    );
    const button = page.getByTestId("credential-token-revoke-button-t1");
    await expect(button).toHaveText("Revoke");

    await button.click();
    await expect(button).toHaveText("Revoke GitHub access?");
    expect(revoked).toEqual([]);

    await button.click();
    await expect(row(page, "t1")).toHaveCount(0);
    await expect(row(page, "t2")).toBeVisible();
    expect(revoked).toEqual(["/api/v1/delegation-vault/t1"]);
  });

  test("revokes every delegation of a user on a second click, with no dialog", async ({
    page,
  }) => {
    let dialogs = 0;
    page.on("dialog", async (dialog) => {
      dialogs += 1;
      await dialog.dismiss();
    });
    const revoked = await openCredentialTokens(page, [
      token("t1", ALICE),
      token("t2", ALICE),
      token("t3", BOB),
    ]);
    const button = page.getByTestId("credential-token-revoke-user-button-t1");

    await button.click();
    await expect(button).toHaveText("Revoke all 2 for this user?");
    expect(revoked).toEqual([]);

    await button.click();
    await expect(row(page, "t1")).toHaveCount(0);
    await expect(row(page, "t2")).toHaveCount(0);
    await expect(row(page, "t3")).toBeVisible();
    expect(revoked).toEqual([
      `/api/v1/delegation-vault/by-user/${encodeURIComponent(ALICE)}`,
    ]);
    expect(dialogs).toBe(0);
    await expect(page.locator('[role="dialog"]')).toHaveCount(0);
  });

  test("keeps the delegations when the first click is followed by a click elsewhere", async ({
    page,
  }) => {
    const revoked = await openCredentialTokens(page, [token("t1", ALICE)]);
    const button = page.getByTestId("credential-token-revoke-user-button-t1");

    await button.click();
    await expect(button).toHaveText("Revoke this user's only delegation?");
    // The confirmation starts listening for a click elsewhere shortly after it opens.
    await expect(async () => {
      await page.getByTestId("credentials-search-input").click();
      await expect(button).not.toContainText(
        "Revoke this user's only delegation?",
        { timeout: 200 },
      );
    }).toPass();
    await expect(row(page, "t1")).toBeVisible();
    expect(revoked).toEqual([]);
  });

  test("opens the details and the limit panel, and cancels a confirm, from the keyboard", async ({
    page,
  }) => {
    const revoked = await openCredentialTokens(page, [
      token("t1", ALICE, fromNow(5 * HOUR)),
    ]);

    const expand = page.getByTestId("credential-token-expand-button-t1");
    await expand.focus();
    await page.keyboard.press("Enter");
    await expect(expand).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator("#credential-token-detail-t1")).toContainText(
      "Consent Ends",
    );

    const limit = page.getByTestId("credential-token-limit-button-t1");
    await limit.focus();
    await page.keyboard.press("Enter");
    await expect(
      page.getByTestId("credential-token-limit-input-t1"),
    ).toBeFocused();
    await page.getByTestId("credential-token-limit-cancel-t1").focus();
    await page.keyboard.press("Enter");
    await expect(
      page.getByTestId("credential-token-limit-panel-t1"),
    ).toHaveCount(0);
    await expect(limit).toBeFocused();

    const revoke = page.getByTestId("credential-token-revoke-button-t1");
    await revoke.focus();
    await page.keyboard.press("Enter");
    await expect(revoke).toHaveText("Revoke GitHub access?");
    await page.keyboard.press("Escape");
    await expect(revoke).toHaveText("Revoke");
    expect(revoked).toEqual([]);
  });

  test("offers no way to change a delegation without delegation_vault.delete", async ({
    page,
  }) => {
    await page.route("**/api/v1/permissions", async (route) => {
      const response = await route.fetch();
      await route.fulfill({
        response,
        json: { ...(await response.json()), "delegation_vault.delete": false },
      });
    });
    await openCredentialTokens(page, [token("t1", ALICE, fromNow(5 * HOUR))]);

    await expect(
      page.getByRole("columnheader", { name: "Actions" }),
    ).toHaveCount(0);
    for (const control of [
      "limit-button",
      "revoke-button",
      "revoke-user-button",
    ]) {
      await expect(
        page.getByTestId(`credential-token-${control}-t1`),
      ).toHaveCount(0);
    }

    await page.getByTestId("credentials-delegated-access-tab-trigger").click();
    await expect(accessRow(page, "t1")).toBeVisible();
    await expect(
      page.getByTestId("delegated-access-revoke-button-t1"),
    ).toHaveCount(0);
  });

  test("says in the gateway's words why a revoke was refused, and drops a delegation it no longer holds", async ({
    page,
  }) => {
    await serveProviders(page);
    let held = [token("t1", ALICE), token("t2", BOB)];
    await page.route("**/api/v1/delegation-vault**", async (route) => {
      if (route.request().method() === "DELETE") {
        held = held.slice(1);
        await route.fulfill({
          status: 404,
          json: { error: "Delegation token not found" },
        });
        return;
      }
      await route.fulfill({ json: held });
    });
    await page.goto(`${BASE_URL}/credentials?tab=credential-tokens`);
    const revoke = page.getByTestId("credential-token-revoke-button-t1");

    await revoke.click();
    await revoke.click();

    await expect(
      page.getByText("Not revoked: Delegation token not found"),
    ).toBeVisible();
    await expect(row(page, "t1")).toHaveCount(0);
    await expect(row(page, "t2")).toBeVisible();
  });

  test("opens a user's delegation records in the Audit Log from the expanded row", async ({
    page,
  }) => {
    const filters: (string | null)[] = [];
    await page.route("**/api/v1/audit?**", async (route) => {
      filters.push(new URL(route.request().url()).searchParams.get("filter"));
      await route.fulfill({
        json: { events: [], total: 0, page: 1, limit: 50, category_counts: {} },
      });
    });
    await openCredentialTokens(page, [token("t1", ALICE)]);

    await row(page, "t1").click();
    await page.getByTestId("credential-token-view-activity-button-t1").click();

    await expect(page.getByTestId("page-audit")).toBeVisible();
    await expect(page.getByTestId("audit-search")).toHaveValue(ALICE);
    expect(new URL(page.url()).searchParams.get("category")).toContain(
      "consent_expired",
    );
    await expect.poll(() => filters).toContain(ALICE);
  });
});

test.describe("Audit Log delegation records", () => {
  test("says when a limited consent now ends and ended before, and when a granted one ends", async ({
    page,
  }) => {
    const record = (event: string, detail: string) => ({
      id: `audit-${event}`,
      occurred_at: fromNow(-HOUR),
      event,
      provider_id: "github",
      provider_name: "GitHub",
      agent_did: AGENT_DID,
      detail,
    });
    await page.route("**/api/v1/audit?**", async (route) => {
      await route.fulfill({
        json: {
          events: [
            record(
              "consent_limited",
              "consent_granted_at:2026-11-17T10:00:00Z,consent_expires_at:2026-11-17T12:00:00Z,previous_end:2026-11-17T16:00:00Z",
            ),
            record(
              "consent_granted",
              "consent_expires_at:2026-11-17T16:00:00Z",
            ),
          ],
          total: 2,
          page: 1,
          limit: 50,
          category_counts: {},
        },
      });
    });
    await page.goto(
      `${BASE_URL}/audit?category=consent_limited,consent_granted`,
    );

    const limited = page.getByTestId("audit-item-0");
    await expect(limited).toContainText("Consent limited");
    await expect(limited).toContainText(
      "An operator made the consent for GitHub end sooner.",
    );
    await expect(limited).toContainText(
      /It now ends .+, not .+\. The credential is used until then\. It was not revoked\./,
    );
    const granted = page.getByTestId("audit-item-1");
    await expect(granted).toContainText("The user granted consent for GitHub.");
    await expect(granted).toContainText(/It ends .+\./);
  });
});

test.describe("Credential Providers tab deactivation", () => {
  test("deactivates a consent provider on a second click, keeps it listed and activates it again", async ({
    page,
  }) => {
    const provider = {
      id: "p1",
      name: "GitHub",
      provider_id: "github",
      provider_type: "oauth2_authorization_code",
      token_endpoint: "https://github.com/login/oauth/access_token",
      default_scopes: ["repo"],
      token_refresh_enabled: true,
      created_at: "2026-10-30T00:00:00Z",
      updated_at: "2026-10-30T00:00:00Z",
    };
    const calls: string[] = [];
    let dialogs = 0;
    page.on("dialog", async (dialog) => {
      dialogs += 1;
      await dialog.dismiss();
    });
    await page.route("**/api/v1/credential-providers", async (route) => {
      await route.fulfill({ json: [provider] });
    });
    await page.route("**/api/v1/credential-providers/p1/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      calls.push(path);
      await route.fulfill({
        json: path.endsWith("/deactivate")
          ? { ...provider, deactivated_at: "2026-11-13T10:00:00Z" }
          : provider,
      });
    });
    await page.goto(`${BASE_URL}/credentials?tab=credential-providers`);
    const deactivate = page.getByTestId(
      "credential-provider-deactivate-button-p1",
    );
    await expect(
      page.getByTestId("credential-provider-delete-button-p1"),
    ).toHaveCount(0);

    await deactivate.click();
    await expect(deactivate).toContainText("Click again to deactivate");
    expect(calls).toEqual([]);

    await deactivate.click();
    await expect(
      page.getByTestId("credential-provider-deactivated-badge-p1"),
    ).toHaveText("Deactivated");
    await expect(
      page.getByTestId("credential-provider-status-p1"),
    ).toContainText("No new consent");
    await expect(page.getByTestId("credential-provider-row-p1")).toBeVisible();
    expect(calls).toEqual(["/api/v1/credential-providers/p1/deactivate"]);

    await page.getByTestId("credential-provider-activate-button-p1").click();
    await expect(
      page.getByTestId("credential-provider-deactivated-badge-p1"),
    ).toHaveCount(0);
    await expect(page.getByTestId("credential-provider-status-p1")).toHaveText(
      "Active",
    );
    await expect(deactivate).toBeVisible();
    expect(calls).toEqual([
      "/api/v1/credential-providers/p1/deactivate",
      "/api/v1/credential-providers/p1/activate",
    ]);
    expect(dialogs).toBe(0);
    await expect(page.locator('[role="dialog"]')).toHaveCount(0);
  });
});

test.describe("Credential provider editor consent time limit", () => {
  const LIMIT = "credential-provider-consent-limit-input";
  const UNIT = "credential-provider-consent-limit-unit-select";

  test("says a deactivated provider takes no new consent", async ({ page }) => {
    await page.route("**/api/v1/credential-providers/p1", async (route) => {
      await route.fulfill({
        json: {
          id: "p1",
          name: "GitHub",
          provider_id: "github",
          provider_type: "oauth2_authorization_code",
          authorization_endpoint: "https://github.com/login/oauth/authorize",
          token_endpoint: "https://github.com/login/oauth/access_token",
          client_id_secret_ref: "CLIENT_ID",
          client_secret_secret_ref: "CLIENT_SECRET",
          default_scopes: ["repo"],
          token_refresh_enabled: true,
          callback_path: "/v1/identity/oauth/callback/p1",
          deactivated_at: "2026-11-13T10:00:00Z",
        },
      });
    });
    await page.goto(`${BASE_URL}/credential-providers/p1`);

    await expect(
      page.getByTestId("credential-provider-deactivated-notice"),
    ).toContainText("nobody can consent to it again");
  });

  test("offers the limit only on an Authorization Code provider", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/credential-providers/new`);

    await expect(page.getByTestId(LIMIT)).toBeVisible();
    await expect(page.getByTestId(LIMIT)).toHaveValue("");
    await expect(page.getByTestId(UNIT)).toHaveValue("hours");
    await expect(page.getByTestId(UNIT).locator("option")).toHaveText([
      "minutes",
      "hours",
      "days",
    ]);

    await page
      .getByTestId("credential-provider-type-select")
      .selectOption("oauth2_client_credentials");

    await expect(page.getByTestId(LIMIT)).toHaveCount(0);
  });

  test("shows a stored limit in its largest unit and saves a changed one in seconds", async ({
    page,
  }) => {
    const stored = {
      id: "p1",
      name: "GitHub",
      provider_id: "github",
      provider_type: "oauth2_authorization_code",
      authorization_endpoint: "https://github.com/login/oauth/authorize",
      token_endpoint: "https://github.com/login/oauth/access_token",
      client_id_secret_ref: "CLIENT_ID",
      client_secret_secret_ref: "CLIENT_SECRET",
      default_scopes: ["repo"],
      token_refresh_enabled: true,
      callback_path: "/v1/identity/oauth/callback/p1",
      max_consent_age_secs: 21_600,
    };
    const saved: Record<string, unknown>[] = [];
    await page.route("**/api/v1/credential-providers/p1", async (route) => {
      if (route.request().method() === "PUT") {
        saved.push(route.request().postDataJSON());
      }
      await route.fulfill({ json: stored });
    });
    await page.goto(`${BASE_URL}/credential-providers/p1`);

    await expect(page.getByTestId(LIMIT)).toHaveValue("6");
    await expect(page.getByTestId(UNIT)).toHaveValue("hours");

    await page.getByTestId(LIMIT).fill("30");
    await page.getByTestId(UNIT).selectOption("days");
    await page.getByTestId("credential-provider-editor-save-button").click();

    await expect
      .poll(() => saved.map((body) => body.max_consent_age_secs))
      .toEqual([2_592_000]);
  });

  test("warns how many active consents saving a shorter limit ends", async ({
    page,
  }) => {
    const asked: (string | null)[] = [];
    await page.route("**/api/v1/credential-providers/p1", async (route) => {
      await route.fulfill({
        json: {
          id: "p1",
          name: "GitHub",
          provider_id: "github",
          provider_type: "oauth2_authorization_code",
          token_endpoint: "https://github.com/login/oauth/access_token",
          client_id_secret_ref: "CLIENT_ID",
          client_secret_secret_ref: "CLIENT_SECRET",
          default_scopes: ["repo"],
          token_refresh_enabled: true,
          callback_path: "/v1/identity/oauth/callback/p1",
          max_consent_age_secs: 21_600,
        },
      });
    });
    await page.route(
      "**/api/v1/credential-providers/p1/consent-impact?**",
      async (route) => {
        asked.push(
          new URL(route.request().url()).searchParams.get(
            "max_consent_age_secs",
          ),
        );
        await route.fulfill({
          json: { active_consents: 5, ending_consents: 2 },
        });
      },
    );
    await page.goto(`${BASE_URL}/credential-providers/p1`);
    await expect(page.getByTestId(LIMIT)).toHaveValue("6");

    await page.getByTestId(LIMIT).fill("1");

    await expect(
      page.getByTestId("credential-provider-consent-limit-impact"),
    ).toHaveText(
      "Saving ends 2 active GitHub consents now. Those people approve again next time their agent needs GitHub.",
    );
    expect(asked).toEqual(["3600"]);

    await page.getByTestId(LIMIT).fill("12");
    await expect(
      page.getByTestId("credential-provider-consent-limit-impact"),
    ).toHaveCount(0);
  });

  test("refuses a limit under a minute under its field before saving anything", async ({
    page,
  }) => {
    const saved: unknown[] = [];
    await page.route("**/api/v1/credential-providers/p1", async (route) => {
      if (route.request().method() === "PUT") {
        saved.push(route.request().postDataJSON());
      }
      await route.fulfill({
        json: {
          id: "p1",
          name: "GitHub",
          provider_id: "github",
          provider_type: "oauth2_authorization_code",
          token_endpoint: "https://github.com/login/oauth/access_token",
          client_id_secret_ref: "CLIENT_ID",
          client_secret_secret_ref: "CLIENT_SECRET",
          default_scopes: ["repo"],
          token_refresh_enabled: true,
          callback_path: "/v1/identity/oauth/callback/p1",
        },
      });
    });
    await page.goto(`${BASE_URL}/credential-providers/p1`);

    await page.getByTestId(LIMIT).fill("0");
    await page.getByTestId(UNIT).selectOption("minutes");
    await page.getByTestId("credential-provider-editor-save-button").click();

    await expect(
      page.getByTestId("credential-provider-consent-limit-error"),
    ).toHaveText("Enter a limit from 1 minute to 365 days, or leave it empty.");
    await expect(page.getByTestId(LIMIT)).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    await expect(page.getByTestId(LIMIT)).toBeFocused();
    await expect(
      page.getByText(
        "Consent time limit must be a whole number from 1 minute to 365 days, or empty to set none.",
      ),
    ).toBeVisible();
    expect(saved).toEqual([]);
  });
});
