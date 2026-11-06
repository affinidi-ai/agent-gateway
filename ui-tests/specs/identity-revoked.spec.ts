import { expect, test } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const revokedKeyDid = {
  did: "did:key:ui-revoked-key",
  identity_hash: "hash-ui-revoked-key",
  created_at: "2026-01-01T00:00:00Z",
  is_local: true,
  origin: "managed",
  surface_id: "ui-revoked-live",
  surface_name: "ui_revoked_live",
  managed_surfaces: [
    { surface_id: "ui-revoked-live", surface_name: "ui_revoked_live" },
  ],
  revoked: true,
};

const deletedSurfaceDid = {
  did: "did:key:ui-deleted-surface",
  identity_hash: "hash-ui-deleted-surface",
  created_at: "2026-01-01T00:00:00Z",
  is_local: true,
  origin: "managed",
  surface_id: "ui-deleted-surface",
  surface_deleted: true,
  revoked: true,
};

const liveDid = {
  did: "did:key:ui-live",
  identity_hash: "hash-ui-live",
  created_at: "2026-01-01T00:00:00Z",
  is_local: true,
  origin: "managed",
  surface_id: "ui-live",
  surface_name: "ui_live",
  managed_surfaces: [{ surface_id: "ui-live", surface_name: "ui_live" }],
};

const rowOf = (page: Page, did: string) =>
  page.getByTestId(`identities-row-${did}`);

async function openIdentities(page: Page) {
  await page.route("**/api/v1/dashboard/stats**", async (route) => {
    const response = await route.fetch();
    const stats = await response.json();
    await route.fulfill({
      response,
      json: {
        ...stats,
        identities: [revokedKeyDid, deletedSurfaceDid, liveDid],
      },
    });
  });
  await page.goto(`${BASE_URL}/identities`);
  await expect(rowOf(page, liveDid.did)).toBeVisible();
}

test.describe("Identities page revoked identity", () => {
  test("shows a solid red Revoked badge with white text, like a revoked API key", async ({
    page,
  }) => {
    await openIdentities(page);
    const badge = rowOf(page, revokedKeyDid.did).getByTestId(
      "identities-revoked-badge",
    );

    await expect(badge).toHaveText("Revoked");
    await expect(badge).toHaveCSS("color", "rgb(255, 255, 255)");
    const background = await badge.evaluate(
      (element) => getComputedStyle(element).backgroundColor,
    );
    const [red, green, blue] = (background.match(/\d+/g) ?? []).map(Number);
    expect(red).toBeGreaterThan(150);
    expect(green).toBeLessThan(100);
    expect(blue).toBeLessThan(100);
    await expect(
      rowOf(page, liveDid.did).getByTestId("identities-revoked-badge"),
    ).toHaveCount(0);
  });

  test("marks an identity whose surface was deleted Revoked and its surface Deleted", async ({
    page,
  }) => {
    await openIdentities(page);
    const row = rowOf(page, deletedSurfaceDid.did);

    await expect(row.getByTestId("identities-revoked-badge")).toBeVisible();
    const surface = row.getByTestId("identities-surface-deleted");
    await expect(surface).toContainText("ui-deleted-surface");
    await expect(
      surface.getByTestId("identities-surface-deleted-badge"),
    ).toHaveText("Deleted");
    await expect(row.getByTestId("identities-surface-link")).toHaveCount(0);
  });

  test("explains a revoked identity when it is selected", async ({ page }) => {
    await openIdentities(page);

    await rowOf(page, revokedKeyDid.did).click();

    await expect(page.getByTestId("identity-revoked-info")).toHaveText(
      "This identity is no longer in use: its API key was revoked or deleted, or its surface was deleted.",
    );
  });
});
