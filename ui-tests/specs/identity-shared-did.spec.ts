import { expect, test } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const sharedDid = {
  did: "did:key:ui-shared-managed",
  identity_hash: "hash-ui-shared-managed",
  created_at: "2026-01-01T00:00:00Z",
  is_local: true,
  origin: "managed",
  managed_surfaces: [
    { surface_id: "ui-shared-alpha", surface_name: "ui_shared_alpha" },
    { surface_id: "ui-shared-bravo", surface_name: "ui_shared_bravo" },
  ],
  trust_recorder: {
    state: "not_attempted",
    reason: null,
    last_attempt_at: null,
    entries: [],
  },
  trust_recorder_surface: {
    surface_id: "ui-shared-bravo",
    surface_name: "ui_shared_bravo",
  },
};

const namedDid = {
  did: "did:key:ui-named-managed",
  identity_hash: "hash-ui-named-managed",
  created_at: "2026-01-01T00:00:00Z",
  is_local: true,
  origin: "managed",
  display_name: "ui_named_surface",
  display_name_source: "surface_name",
  surface_id: "ui-named-surface",
  surface_name: "ui_named_surface",
  managed_surfaces: [
    { surface_id: "ui-named-surface", surface_name: "ui_named_surface" },
  ],
};

const rowOf = (page: Page, did: string) =>
  page.getByTestId(`identities-row-${did}`);

async function openIdentities(page: Page) {
  await page.route("**/api/v1/dashboard/stats**", async (route) => {
    const response = await route.fetch();
    const stats = await response.json();
    await route.fulfill({
      response,
      json: { ...stats, identities: [sharedDid, namedDid] },
    });
  });
  await page.goto(`${BASE_URL}/identities`);
  await expect(rowOf(page, sharedDid.did)).toBeVisible();
}

test.describe("Identities page shared managed DID", () => {
  test("shows Name and DID columns and no name-conflict filter", async ({
    page,
  }) => {
    await openIdentities(page);

    await expect(
      page.getByRole("columnheader", { name: "Name", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("columnheader", { name: "DID", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("columnheader", { name: "Usage Count" }),
    ).toHaveCount(0);
    await expect(
      page.getByTestId("identities-unnamed-filter-button"),
    ).toHaveCount(0);
    await expect(page.getByTestId("identities-name-conflict")).toHaveCount(0);
  });

  test("shows one Unnamed Agent row with a link per surface", async ({
    page,
  }) => {
    await openIdentities(page);
    const row = rowOf(page, sharedDid.did);

    await expect(row.getByTestId("identities-unnamed-agent")).toHaveText(
      "Unnamed Agent",
    );
    await expect(
      row.getByTestId("identities-shared-surface-count"),
    ).toHaveText("2 surfaces");
    await expect(row.getByTestId("identities-surface-link")).toHaveText([
      "ui_shared_alpha",
      "ui_shared_bravo",
    ]);
    await expect(row.getByTitle(sharedDid.did)).toBeVisible();
  });

  test("shows the named managed DID under its name", async ({ page }) => {
    await openIdentities(page);
    const row = rowOf(page, namedDid.did);

    await expect(row.getByTestId("identities-name")).toHaveText(
      "ui_named_surface",
    );
    await expect(row.getByTestId("identities-unnamed-agent")).toHaveCount(0);
    await expect(row.getByTestId("identities-surface-link")).toHaveCount(1);
  });

  test("names the surface whose recorder outcome is shown", async ({
    page,
  }) => {
    await openIdentities(page);
    const chip = rowOf(page, sharedDid.did).getByTestId(
      "identities-recorder-chip-not_attempted",
    );

    await expect(chip).toHaveAccessibleName(
      "Trust Recorder status on ui_shared_bravo: Not attempted yet",
    );
    await chip.focus();
    await expect(page.getByTestId("identities-recorder-surface")).toHaveText(
      "Recorder on ui_shared_bravo",
    );
  });
});
