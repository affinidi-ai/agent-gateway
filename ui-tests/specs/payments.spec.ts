/**
 * Payment element and Payments page.
 *
 * The surface, the connected agent-pay gateway, its payment manifests and the
 * payment ledger are all served by `page.route` mocks, so the spec needs no
 * agent-pay peer. Every control is located by test id.
 */

import type { Page, Route } from "@playwright/test";
import { expect, test } from "../helpers/fixtures";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";
const SURFACE_ID = "payments-ui-surface";
const GATEWAY_ID = "gw-pay";
const SAVED_PRICE = "0.01";
const LIVE_PRICES: Record<string, string> = {
  "pay-ch": "0.05",
  "card-ch": "2.00",
};

interface SavedSurface {
  target: { payment_policy: Record<string, unknown> };
  canvas: { nodes: Array<{ type: string; config?: Record<string, unknown> }> };
}

const manifest = (surfaceId: string, amount: string) => ({
  version: "1",
  payable: { id: surfaceId, name: "Premium tools" },
  amount: { amount, unit: "USDC" },
  payment_points: [
    {
      id: "x402:base",
      label: "USDC on Base",
      protocol: "x402",
      credential: "eip3009_signature",
      detail: {
        kind: "onChain",
        scheme: "exact",
        network: "base",
        pay_to: "0xabc",
      },
    },
  ],
});

const surface = {
  surface_id: SURFACE_ID,
  name: "payments ui surface",
  description: "",
  status: "active",
  tags: [],
  access_point: {
    listen_address: "0.0.0.0:8443",
    route: "/payments-ui",
    protocol: "mcp",
  },
  target: {
    endpoint: "https://upstream.example/mcp",
    payment_policy: {
      type: "agent_pay",
      payment_gateway_id: GATEWAY_ID,
      payment_surface_id: "pay-ch",
      mcp_payment_triggers: { mode: "match", patterns: ["^premium_"] },
      manifest_snapshot: manifest("pay-ch", SAVED_PRICE),
    },
  },
};

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

/**
 * Serves the surface, agent-pay's discovery and manifests. A save is answered
 * the way the gateway answers when agent-pay cannot be reached: the stored
 * policy, no snapshot, and a `payment_unverified` warning.
 */
async function mockSurfaceApis(
  page: Page,
  options: { refuseSave?: string } = {},
) {
  const saves: SavedSurface[] = [];
  const manifestRequests: string[] = [];

  await page.route("**/api/v1/gateways", (route) =>
    json(route, [
      {
        id: GATEWAY_ID,
        name: "Agent Pay",
        gateway_type: "remote",
        creation_type: "user",
      },
    ]),
  );
  await page.route("**/api/v1/gateways/payment-providers", (route) =>
    json(route, [{ id: GATEWAY_ID }]),
  );
  await page.route(`**/api/v1/gateways/${GATEWAY_ID}/surfaces*`, (route) =>
    json(
      route,
      Object.keys(LIVE_PRICES).map((id) => ({
        config_id: id,
        name: id,
        is_payment_surface: true,
      })),
    ),
  );
  await page.route(
    `**/api/v1/gateways/${GATEWAY_ID}/surfaces/*/payment-manifest*`,
    (route) => {
      const url = new URL(route.request().url());
      manifestRequests.push(url.pathname + url.search);
      const surfaceId = decodeURIComponent(
        url.pathname.split("/").at(-2) ?? "",
      );
      return json(route, {
        manifest: manifest(surfaceId, LIVE_PRICES[surfaceId] ?? "9.99"),
      });
    },
  );
  await page.route(`**/api/v1/surfaces/${SURFACE_ID}`, (route) => {
    if (route.request().method() !== "PUT") return json(route, surface);
    const body = route.request().postDataJSON() as SavedSurface &
      Record<string, unknown>;
    saves.push(body);
    if (options.refuseSave) {
      return json(
        route,
        {
          error: "Bad Request",
          code: "invalid_payment_policy",
          details: options.refuseSave,
        },
        400,
      );
    }
    const { target } = body;
    const policy = { ...target.payment_policy };
    delete policy.manifest_snapshot;
    return json(route, {
      ...surface,
      ...body,
      target: { ...surface.target, ...target, payment_policy: policy },
      warnings: [
        {
          code: "payment_unverified",
          message: "agent-pay could not be reached to verify it",
        },
      ],
    });
  });

  return { saves, manifestRequests };
}

async function openPaymentPanel(page: Page) {
  await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
  await page.getByTestId("surface-node-payment").click();
  await expect(page.getByTestId("payment-manifest-preview")).toBeVisible();
}

test.describe("Payment element", () => {
  test("shows the saved snapshot, flags drift after a refresh and saves the agent_pay shape", async ({
    page,
  }) => {
    const { saves, manifestRequests } = await mockSurfaceApis(page);
    await openPaymentPanel(page);

    await expect(page.getByTestId("payment-manifest-preview")).toContainText(
      "(saved snapshot)",
    );
    await expect(page.getByTestId("payment-manifest-amount")).toContainText(
      `${SAVED_PRICE} USDC`,
    );
    await expect(
      page.getByTestId("payment-share-email-toggle"),
    ).not.toBeChecked();
    expect(manifestRequests).toEqual([]);

    await page.getByTestId("payment-manifest-refresh-button").click();
    await expect(page.getByTestId("payment-manifest-drift")).toContainText(
      "Price changed from 0.01 USDC to 0.05 USDC",
    );
    expect(manifestRequests).toHaveLength(1);
    expect(manifestRequests[0]).toContain("force_refresh=true");

    await page.getByTestId("payment-timeout-input").fill("8000");
    await page.getByTestId("surface-save-button").click();

    await expect.poll(() => saves.length).toBe(1);
    expect(saves[0].target.payment_policy).toEqual({
      type: "agent_pay",
      payment_gateway_id: GATEWAY_ID,
      payment_surface_id: "pay-ch",
      mcp_payment_triggers: { mode: "match", patterns: ["^premium_"] },
      timeout_ms: 8000,
    });
  });

  test("drops the saved price when another payment surface is chosen and never stores it in the canvas", async ({
    page,
  }) => {
    const { saves } = await mockSurfaceApis(page);
    await openPaymentPanel(page);
    await expect(page.getByTestId("payment-manifest-preview")).toContainText(
      "(saved snapshot)",
    );

    await page.getByTestId("payment-surface-select").selectOption("card-ch");

    await expect(page.getByTestId("payment-manifest-preview")).toContainText(
      "(live from agent-pay)",
    );
    await expect(page.getByTestId("payment-manifest-amount")).toContainText(
      "2.00 USDC",
    );
    await expect(page.getByTestId("payment-manifest-drift")).toHaveCount(0);

    await page.getByTestId("surface-save-button").click();

    await expect.poll(() => saves.length).toBe(1);
    expect(saves[0].target.payment_policy.payment_surface_id).toBe("card-ch");
    const paymentNode = saves[0].canvas.nodes.find(
      (node) => node.type === "payment",
    );
    expect(paymentNode?.config?.payment_surface_id).toBe("card-ch");
    expect(paymentNode?.config).not.toHaveProperty("manifest_snapshot");

    // A save answered without a snapshot leaves the preview live, so the old
    // surface's price is never shown as the new surface's saved price.
    await expect(page.getByTestId("payment-manifest-preview")).toContainText(
      "(live from agent-pay)",
    );
    await expect(page.getByTestId("payment-manifest-amount")).toContainText(
      "2.00 USDC",
    );
  });

  test("an out-of-range timeout blocks Save until it is fixed", async ({
    page,
  }) => {
    const { saves } = await mockSurfaceApis(page);
    await openPaymentPanel(page);

    await page.getByTestId("payment-timeout-input").fill("500");
    await expect(page.getByTestId("payment-timeout-error")).toContainText(
      "from 1000 to 120000",
    );
    await page.getByTestId("surface-save-button").click();

    await page.getByTestId("payment-timeout-input").fill("120000");
    await expect(page.getByTestId("payment-timeout-error")).toHaveCount(0);
    await page.getByTestId("surface-save-button").click();

    await expect.poll(() => saves.length).toBe(1);
    expect(saves[0].target.payment_policy.timeout_ms).toBe(120000);
  });

  test("a pattern only the gateway can judge warns but does not block Save", async ({
    page,
  }) => {
    const { saves } = await mockSurfaceApis(page);
    await openPaymentPanel(page);

    await page.getByTestId("payment-configure-triggers-button").click();
    const pattern = page.getByTestId("payment-triggers-mcp-pattern-0");

    await pattern.fill("(?i)^premium_");
    await expect(
      page.getByTestId("payment-triggers-mcp-pattern-warning-0"),
    ).toHaveCount(0);

    await pattern.fill("(?=premium)");
    await expect(
      page.getByTestId("payment-triggers-mcp-pattern-warning-0"),
    ).toContainText("not supported by the gateway");

    await page.getByTestId("surface-save-button").click();

    await expect.poll(() => saves.length).toBe(1);
    expect(saves[0].target.payment_policy.mcp_payment_triggers).toEqual({
      mode: "match",
      patterns: ["(?=premium)"],
    });
  });
});

test.describe("Payment element save refusals", () => {
  test("the gateway has the last word on a pattern and its reason is shown", async ({
    page,
  }) => {
    const reason =
      "Surface payment policy: invalid mcp_payment_triggers regex '(?=premium)': look-around is not supported";
    const { saves } = await mockSurfaceApis(page, { refuseSave: reason });
    await openPaymentPanel(page);
    await page.getByTestId("payment-configure-triggers-button").click();

    await page
      .getByTestId("payment-triggers-mcp-pattern-0")
      .fill("(?=premium)");
    await page.getByTestId("surface-save-button").click();

    await expect(page.getByTestId("surface-error-alert")).toContainText(reason);
    expect(saves).toHaveLength(1);
  });
});

const NOW = Math.floor(Date.now() / 1000);

const ledger = [
  {
    id: "pay-1",
    created_at: NOW - 60,
    surface_id: SURFACE_ID,
    payment_gateway_id: GATEWAY_ID,
    payment_surface_id: "pay-ch",
    outcome: "paid",
    rail: "x402",
    amount: "0.01",
    currency: "USDC",
    resource: "premium_forecast",
    latency_ms: 120,
  },
  {
    id: "pay-2",
    created_at: NOW - 30,
    surface_id: SURFACE_ID,
    payment_gateway_id: GATEWAY_ID,
    payment_surface_id: "pay-ch",
    outcome: "held",
    case_id: "case-42",
    resource: "premium_forecast",
    latency_ms: 80,
  },
];

const legacyVerification = {
  type: "verification",
  id: "tx-1_verification",
  correlation_id: "tx-1",
  surface_id: "old-surface-id",
  channel_name: "old-surface",
  status: "Verified",
  amount: "10000",
  decimals: 6,
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  created_at: NOW - 3600,
};
const legacySettlement = {
  ...legacyVerification,
  type: "settlement",
  status: "Completed",
};

async function mockLedgerApis(page: Page, options: { legacy?: boolean } = {}) {
  let caseStatus = "capture_failed";
  await page.route(/\/api\/admin\/payments(\?.*)?$/, (route) => {
    const outcome = new URL(route.request().url()).searchParams.get("outcome");
    const rows = ledger.filter((row) => !outcome || row.outcome === outcome);
    return json(route, { payments: rows, total: rows.length });
  });
  await page.route(/\/api\/admin\/payments\/[^/?]+$/, (route) => {
    const id = decodeURIComponent(
      new URL(route.request().url()).pathname.split("/").at(-1) ?? "",
    );
    const row = ledger.find((r) => r.id === id);
    if (!row) return json(route, { error: "Payment not found" }, 404);
    const detail =
      row.outcome === "held"
        ? {
            ...row,
            case_status: {
              status: caseStatus,
              checked_at: new Date().toISOString(),
            },
          }
        : row;
    return json(route, detail);
  });
  await page.route("**/api/admin/x402/payments/all*", (route) =>
    json(route, {
      payments: options.legacy ? [legacyVerification, legacySettlement] : [],
    }),
  );
  await page.route("**/api/admin/mpp/transactions*", (route) =>
    json(route, { transactions: [] }),
  );
  return {
    settleCase: () => {
      caseStatus = "captured";
    },
  };
}

test.describe("Payments page", () => {
  test("the old route redirects here, and the ledger filters by outcome", async ({
    page,
  }) => {
    await mockLedgerApis(page);

    await page.goto(`${BASE_URL}/x402payments`);
    await expect(page).toHaveURL(/\/payments$/);
    await expect(page.getByTestId("page-payments")).toBeVisible();

    await expect(page.getByTestId("payments-row-pay-1")).toContainText("Paid");
    await expect(page.getByTestId("payments-held-case-pay-2")).toContainText(
      "case-42",
    );
    await expect(page.getByTestId("payments-legacy-tab")).toHaveCount(0);

    await page.getByTestId("payments-outcome-filter").selectOption("held");
    await expect(page.getByTestId("payments-row-pay-1")).toHaveCount(0);
    await expect(page.getByTestId("payments-row-pay-2")).toBeVisible();
  });

  test("the old route keeps its query string when it redirects", async ({
    page,
  }) => {
    await mockLedgerApis(page);

    await page.goto(`${BASE_URL}/x402payments?surface_id=weather`);

    await expect(page).toHaveURL(/\/payments\?surface_id=weather$/);
    await expect(page.getByTestId("payments-surface-filter")).toContainText(
      "weather",
    );
  });

  test("a held payment shows what agent-pay says now and can be asked again", async ({
    page,
  }) => {
    const { settleCase } = await mockLedgerApis(page);
    await page.goto(`${BASE_URL}/x402payments`);

    await page.getByTestId("payments-details-button-pay-2").click();

    const caseStatus = page.getByTestId("payments-detail-case-status");
    await expect(caseStatus).toContainText("Capture failed");
    await expect(caseStatus).toContainText(
      "reconcile before asking the payer to pay again",
    );

    settleCase();
    await page.getByTestId("payments-detail-refresh-button").click();
    await expect(caseStatus).toContainText("Captured");
    await expect(caseStatus).not.toContainText("reconcile");

    await page.getByTestId("payments-detail-close-button").click();
    await expect(page.getByTestId("payments-detail-modal")).toHaveCount(0);
  });

  test("a payment that was not held has no case status", async ({ page }) => {
    await mockLedgerApis(page);
    await page.goto(`${BASE_URL}/x402payments`);

    await page.getByTestId("payments-details-button-pay-1").click();

    await expect(page.getByTestId("payments-detail-modal")).toContainText(
      "premium_forecast",
    );
    await expect(page.getByTestId("payments-detail-case-status")).toHaveCount(
      0,
    );
    await page.getByTestId("payments-detail-dismiss-button").click();
    await expect(page.getByTestId("payments-detail-modal")).toHaveCount(0);
  });

  test("the legacy tab lists one row per old transaction with its amount in dollars", async ({
    page,
  }) => {
    await mockLedgerApis(page, { legacy: true });
    await page.goto(`${BASE_URL}/x402payments`);

    await expect(page.getByTestId("payments-legacy-tab")).toContainText("1");
    await page.getByTestId("payments-legacy-tab").click();

    const row = page.getByTestId("payments-legacy-row-x402-tx-1");
    await expect(row).toContainText("old-surface");
    await expect(row).toContainText("Completed");
    await expect(row).toContainText("$0.01");
    await expect(row).not.toContainText("0x8335");

    await page.getByTestId("payments-ledger-tab").click();
    await expect(page.getByTestId("payments-row-pay-1")).toBeVisible();
  });
});
