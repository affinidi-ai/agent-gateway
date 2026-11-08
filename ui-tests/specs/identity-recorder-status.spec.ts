import { expect, test } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

type RecorderState =
  | "recorded"
  | "partial"
  | "failed"
  | "skipped"
  | "not_attempted";

interface RecorderStatus {
  state: RecorderState;
  reason: string | null;
  last_attempt_at: string | null;
  entries: Array<{
    trust_registry_id: string;
    state: RecorderState;
    reason: string | null;
    created: number;
    already_existed: number;
    failed: number;
  }>;
}

const identity = (did: string, trustRecorder?: RecorderStatus) => ({
  did,
  name: did,
  identity_hash: `hash-${did}`,
  created_at: "2026-01-01T00:00:00Z",
  is_local: true,
  ...(trustRecorder ? { trust_recorder: trustRecorder } : {}),
});

const recordedStatus: RecorderStatus = {
  state: "recorded",
  reason: null,
  last_attempt_at: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
  entries: [
    {
      trust_registry_id: "reg-alpha",
      state: "recorded",
      reason: null,
      created: 2,
      already_existed: 1,
      failed: 0,
    },
  ],
};

const failedStatus: RecorderStatus = {
  state: "failed",
  reason: "rejected",
  last_attempt_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
  entries: [
    {
      trust_registry_id: "reg-beta",
      state: "failed",
      reason: "rejected",
      created: 0,
      already_existed: 0,
      failed: 3,
    },
  ],
};

const identities = {
  recorded: identity("did:key:ui-recorder-recorded", recordedStatus),
  failed: identity("did:key:ui-recorder-failed", failedStatus),
  skipped: identity("did:key:ui-recorder-skipped", {
    state: "skipped",
    reason: "no_surface_issuer",
    last_attempt_at: null,
    entries: [],
  }),
  notAttempted: identity("did:key:ui-recorder-pending", {
    state: "not_attempted",
    reason: null,
    last_attempt_at: null,
    entries: [],
  }),
  plain: identity("did:key:ui-recorder-none"),
};

const rowOf = (page: Page, did: string) =>
  page.getByTestId(`identities-row-${did}`);

async function mockDashboardIdentities(page: Page) {
  await page.route("**/api/v1/dashboard/stats**", async (route) => {
    const response = await route.fetch();
    const stats = await response.json();
    await route.fulfill({
      response,
      json: { ...stats, identities: Object.values(identities) },
    });
  });
}

async function openIdentities(page: Page) {
  await mockDashboardIdentities(page);
  await page.goto(`${BASE_URL}/identities`);
  await expect(rowOf(page, identities.recorded.did)).toBeVisible();
}

test.describe("Identities page recorder status", () => {
  test("shows a labelled chip only for identities with a recorder", async ({
    page,
  }) => {
    await openIdentities(page);

    await expect(
      rowOf(page, identities.recorded.did).getByTestId(
        "identities-recorder-chip-recorded",
      ),
    ).toHaveText("Recorded");
    await expect(
      rowOf(page, identities.failed.did).getByTestId(
        "identities-recorder-chip-failed",
      ),
    ).toHaveText("Failed");
    await expect(
      rowOf(page, identities.skipped.did).getByTestId(
        "identities-recorder-chip-skipped",
      ),
    ).toHaveText("Skipped");
    await expect(
      rowOf(page, identities.notAttempted.did).getByTestId(
        "identities-recorder-chip-not_attempted",
      ),
    ).toHaveText("Not attempted yet");
    await expect(
      rowOf(page, identities.plain.did).getByTestId(
        /^identities-recorder-chip-/,
      ),
    ).toHaveCount(0);
  });

  test("shows the last attempt and per-registry counts in the tooltip", async ({
    page,
  }) => {
    await openIdentities(page);

    await rowOf(page, identities.recorded.did)
      .getByTestId("identities-recorder-chip-recorded")
      .focus();

    await expect(page.getByTestId("identities-recorder-tooltip")).toBeVisible();
    await expect(
      page.getByTestId("identities-recorder-last-attempt"),
    ).toContainText("Last attempt:");
    await expect(
      page.getByTestId("identities-recorder-entry-reg-alpha"),
    ).toContainText("created 2, already existed 1, failed 0");
  });

  test("explains a skipped identity with the reason", async ({ page }) => {
    await openIdentities(page);

    await rowOf(page, identities.skipped.did)
      .getByTestId("identities-recorder-chip-skipped")
      .hover();

    await expect(page.getByTestId("identities-recorder-reason")).toHaveText(
      "Surface has no Issuer",
    );
  });

  test("narrows the list with the Recorder filter", async ({ page }) => {
    await openIdentities(page);
    const filter = page.getByTestId("identities-recorder-filter");

    await filter.selectOption("failed");
    await expect(rowOf(page, identities.failed.did)).toBeVisible();
    await expect(rowOf(page, identities.recorded.did)).toBeHidden();
    await expect(rowOf(page, identities.plain.did)).toBeHidden();

    await filter.selectOption("none");
    await expect(rowOf(page, identities.plain.did)).toBeVisible();
    await expect(rowOf(page, identities.failed.did)).toBeHidden();
    await expect(rowOf(page, identities.recorded.did)).toBeHidden();

    await filter.selectOption("all");
    await expect(rowOf(page, identities.recorded.did)).toBeVisible();
    await expect(rowOf(page, identities.failed.did)).toBeVisible();
    await expect(rowOf(page, identities.plain.did)).toBeVisible();
  });
});

const SURFACE_ID = "ui-recorder-surface";

const recorderSurface = {
  surface_id: SURFACE_ID,
  name: "ui_recorder_surface",
  description: "",
  status: "active",
  tags: [],
  access_point: {
    listen_address: "0.0.0.0:0",
    route: "/ui-recorder",
    protocol: "a2a",
    trust_recorder: {
      entries: [
        {
          trust_registry_id: "reg-alpha",
          issuer_did: "did:key:issuer",
          authority_did: "did:key:authority",
          include_owned_agent: true,
          custom_resources: [],
        },
      ],
    },
  },
  target: { endpoint: "http://127.0.0.1:9/agent" },
};

async function mockRecorderSurface(
  page: Page,
  statusResponse: { status: number; body: unknown },
) {
  await page.route(`**/api/v1/surfaces/${SURFACE_ID}`, (route) =>
    route.request().method() === "GET"
      ? route.fulfill({ status: 200, json: recorderSurface })
      : route.continue(),
  );
  await page.route(
    `**/api/v1/surfaces/${SURFACE_ID}/trust-recorder-status`,
    (route) =>
      route.fulfill({
        status: statusResponse.status,
        json: statusResponse.body,
      }),
  );
}

async function openTrustRecorderPanel(page: Page) {
  await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
  await page.getByRole("button", { name: /Elements/ }).click();
  await page.getByRole("row", { name: /Trust Recorder/ }).click();
}

test.describe("Trust Recorder panel last outcome", () => {
  test("shows the last outcome of a saved surface", async ({ page }) => {
    await mockRecorderSurface(page, {
      status: 200,
      body: { status: failedStatus },
    });
    await openTrustRecorderPanel(page);

    await expect(
      page.getByTestId("trust-recorder-last-outcome-state"),
    ).toHaveText("Failed");
    await expect(
      page.getByTestId("trust-recorder-last-outcome-reason"),
    ).toHaveText("Registry rejected the record");
    await expect(
      page.getByTestId("trust-recorder-last-outcome-time"),
    ).toBeVisible();
    await expect(
      page.getByTestId("trust-recorder-last-outcome-counts"),
    ).toHaveText("created 0, already existed 0, failed 3");
  });

  test("says No attempt yet when nothing has been attempted", async ({
    page,
  }) => {
    await mockRecorderSurface(page, { status: 200, body: { status: null } });
    await openTrustRecorderPanel(page);

    await expect(
      page.getByTestId("trust-recorder-last-outcome-empty"),
    ).toHaveText("No attempt yet");
  });

  test("keeps the panel usable when the status cannot be loaded", async ({
    page,
  }) => {
    await mockRecorderSurface(page, {
      status: 500,
      body: { error: "unavailable" },
    });
    await openTrustRecorderPanel(page);

    await expect(
      page.getByTestId("trust-recorder-last-outcome-unavailable"),
    ).toHaveText("Status unavailable");
    await expect(
      page.getByTestId("trust-recorder-panel-configure"),
    ).toBeEnabled();
  });
});
