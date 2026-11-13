import { expect, test } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const fromNow = (ms: number) => new Date(Date.now() + ms).toISOString();

const ALICE = `sha256:${"a".repeat(64)}`;
const BOB = `sha256:${"b".repeat(64)}`;

const token = (
  id: string,
  user: string,
  consentExpiresAt?: string,
): Record<string, unknown> => ({
  id,
  agent_did: "did:web:agent.example.com",
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

/** Opens the Credential Tokens tab over `tokens`. */
async function openCredentialTokens(
  page: Page,
  tokens: Record<string, unknown>[],
): Promise<string[]> {
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
});

test.describe("Credentials page Delegated Access tab", () => {
  test("lists only active access and opens the Audit Log as its history", async ({
    page,
  }) => {
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
    await serveVault(page, [
      token("soon", ALICE, fromNow(3 * HOUR + 5 * 60_000)),
      token("unlimited", BOB),
      token("ended", BOB, fromNow(-HOUR)),
      { ...token("dead", ALICE), is_expired: true, can_refresh: false },
    ]);
    await page.goto(`${BASE_URL}/credentials?tab=delegated-access`);

    await expect(accessRow(page, "soon")).toBeVisible();
    await expect(accessRow(page, "soon")).toContainText("GitHub");
    await expect(accessRow(page, "soon")).toContainText("Ending soon");
    await expect(page.getByTestId("delegated-access-ends-soon")).toContainText(
      "in 3 hours",
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

  test("revokes one access on a second click, with no dialog", async ({
    page,
  }) => {
    let dialogs = 0;
    page.on("dialog", async (dialog) => {
      dialogs += 1;
      await dialog.dismiss();
    });
    const revoked = await serveVault(page, [
      token("t1", ALICE),
      token("t2", BOB),
    ]);
    await page.goto(`${BASE_URL}/credentials?tab=delegated-access`);
    const button = page.getByTestId("delegated-access-revoke-button-t1");

    await button.click();
    expect(revoked).toEqual([]);
    await expect(accessRow(page, "t1")).toBeVisible();

    await button.click();
    await expect(accessRow(page, "t1")).toHaveCount(0);
    await expect(accessRow(page, "t2")).toBeVisible();
    expect(revoked).toEqual(["/api/v1/delegation-vault/t1"]);
    expect(dialogs).toBe(0);
    await expect(page.locator('[role="dialog"]')).toHaveCount(0);
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
    await expect(button).toHaveText("Click again to revoke all");
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
    await expect(button).toHaveText("Click again to revoke all");
    // The confirmation starts listening for a click elsewhere 100 ms after it opens.
    await page.waitForTimeout(300);
    await page.getByTestId("credentials-search-input").click();

    await expect(button).not.toContainText("Click again to revoke all");
    await expect(row(page, "t1")).toBeVisible();
    expect(revoked).toEqual([]);
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

test.describe("Credentials page Credential Delegation Audit tab", () => {
  test("is a link to the Audit Log, filtered to credential delegation", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/credentials`);

    await page.getByTestId("credentials-credential-audit-tab-trigger").click();

    await expect(page.getByTestId("page-audit")).toBeVisible();
    const categories = new URL(page.url()).searchParams.get("category") ?? "";
    expect(categories.split(",")).toEqual(
      expect.arrayContaining([
        "token_injected",
        "consent_granted",
        "consent_expired",
        "token_revoked",
      ]),
    );
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
    await expect(page.getByTestId("credential-provider-row-p1")).toBeVisible();
    expect(calls).toEqual(["/api/v1/credential-providers/p1/deactivate"]);

    await page.getByTestId("credential-provider-activate-button-p1").click();
    await expect(
      page.getByTestId("credential-provider-deactivated-badge-p1"),
    ).toHaveCount(0);
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

  test("offers the limit only on an Authorization Code provider", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/credential-providers/new`);

    await expect(page.getByTestId(LIMIT)).toBeVisible();
    await expect(page.getByTestId(LIMIT)).toHaveValue("");
    await expect(page.getByTestId(UNIT)).toHaveValue("hours");

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

  test("refuses a limit under a minute before saving anything", async ({
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

    await page.getByTestId(LIMIT).fill("30");
    await page.getByTestId(UNIT).selectOption("seconds");
    await page.getByTestId("credential-provider-editor-save-button").click();

    await expect(
      page.getByText(
        "Consent time limit must be a whole number from 1 minute to 365 days, or empty for no limit.",
      ),
    ).toBeVisible();
    expect(saved).toEqual([]);
  });
});
