/**
 * Connections → Payment Gateways: the list, the connect wizard and its
 * resume path.
 *
 * Every `/payment-gateways` call is served by `page.route` mocks, so the spec
 * needs no agent-pay peer. Every control is located by test id.
 */

import type { Page, Route } from "@playwright/test";
import { expect, test } from "../helpers/fixtures";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

const paymentGateway = (id: string, name: string, status: string) => ({
  id,
  name,
  description: `${name} gateway`,
  did: `did:web:${id}.example`,
  gateway_type: "remote",
  creation_type: "user",
  status,
  role: "payment",
  created_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-01T00:00:00Z",
  peer_last_seen_at: null,
});

const ACTIVE = paymentGateway("gw-pay", "Agent Pay", "active");
const AWAITING = paymentGateway("gw-new", "New Pay", "awaiting-approval");

const INFO = {
  info_version: "1",
  role: "payment",
  protocols: ["x402"],
  payment_methods: [{ protocol: "x402", kind: "onChain", network: "base" }],
  payable_count: 2,
  units: ["USDC"],
};

async function mockPaymentGateways(
  page: Page,
  gateways: Array<Record<string, unknown>>,
  options: { refuseDelete?: string } = {},
) {
  const deletes: string[] = [];
  await page.route("**/api/v1/payment-gateways", (route) =>
    json(route, gateways),
  );
  await page.route("**/api/v1/payment-gateways/*/info", (route) =>
    json(route, INFO),
  );
  await page.route(/\/api\/v1\/payment-gateways\/[^/?]+$/, (route) => {
    const id = decodeURIComponent(
      new URL(route.request().url()).pathname.split("/").at(-1) ?? "",
    );
    if (route.request().method() === "DELETE") {
      deletes.push(id);
      return options.refuseDelete
        ? route.fulfill({ status: 409, body: options.refuseDelete })
        : route.fulfill({ status: 204 });
    }
    const found = gateways.find((gw) => gw.id === id);
    return found
      ? json(route, found)
      : route.fulfill({ status: 404, body: "Gateway not found" });
  });
  return { deletes };
}

test.describe("Payment Gateways tab", () => {
  test("explains agent-pay when there is no payment gateway and opens the wizard", async ({
    page,
  }) => {
    await mockPaymentGateways(page, []);
    await page.goto(`${BASE_URL}/connections?tab=payment-gateways`);

    await expect(page.getByTestId("page-payment-gateways")).toBeVisible();
    await expect(
      page.getByTestId("payment-gateways-empty-state"),
    ).toContainText("agent-pay");

    await page.getByTestId("payment-gateways-empty-connect-button").click();
    await expect(page).toHaveURL(/\/payment-gateways\/connect$/);
    await expect(page.getByTestId("wizard-add-payment-gateway")).toBeVisible();
  });

  test("lists what an active payment gateway offers and resumes a pending one", async ({
    page,
  }) => {
    await mockPaymentGateways(page, [ACTIVE, AWAITING]);
    await page.goto(`${BASE_URL}/connections`);

    await page.getByTestId("connections-tab-payment-gateways").click();
    await expect(page).toHaveURL(/tab=payment-gateways/);
    await expect(page.getByTestId("payment-gateways-row-gw-pay")).toContainText(
      "Agent Pay",
    );
    await expect(
      page.getByTestId("payment-gateways-offer-gw-pay"),
    ).toContainText("2 payment surfaces");
    await expect(page.getByTestId("gateway-status-gw-new")).toContainText(
      "AWAITING APPROVAL",
    );
    await expect(
      page.getByTestId("payment-gateways-verify-button-gw-pay"),
    ).toHaveCount(0);

    await page.getByTestId("payment-gateways-verify-button-gw-new").click();
    await expect(page).toHaveURL(/\/payment-gateways\/connect\?id=gw-new$/);
    await expect(page.getByTestId("wizard-step-approval")).toBeVisible();
    await expect(
      page.getByTestId("payment-gateway-approval-status"),
    ).toContainText("AWAITING APPROVAL");
  });

  test("shows why a payment gateway cannot be deleted", async ({ page }) => {
    const reason = "1 surface(s) take payments through this payment gateway";
    const { deletes } = await mockPaymentGateways(page, [ACTIVE], {
      refuseDelete: reason,
    });
    await page.goto(`${BASE_URL}/connections?tab=payment-gateways`);

    const deleteButton = page.getByTestId(
      "payment-gateways-delete-button-gw-pay",
    );
    await deleteButton.click();
    await deleteButton.click();

    await expect(
      page.getByTestId("payment-gateways-error-alert"),
    ).toContainText(reason);
    expect(deletes).toEqual(["gw-pay"]);
    await expect(page.getByTestId("payment-gateways-row-gw-pay")).toBeVisible();
  });
});

test.describe("Connect Payment Gateway wizard", () => {
  test("needs a name before it asks for the connection point link", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/payment-gateways/connect`);
    await expect(page.getByTestId("wizard-step-details")).toContainText(
      "Enter Payment Gateway Details",
    );

    await page.getByTestId("wizard-next").click();
    await expect(page.getByTestId("wizard-step-details")).toBeVisible();
    await expect(page.getByTestId("wizard-step-link")).toHaveCount(0);
    expect(
      await page
        .getByTestId("wizard-oob-name-input")
        .evaluate((input: HTMLInputElement) => input.validity.valueMissing),
    ).toBe(true);

    await page.getByTestId("wizard-oob-name-input").fill("Agent Pay");
    await page.getByTestId("wizard-next").click();
    await expect(page.getByTestId("wizard-step-link")).toBeVisible();

    await page.getByTestId("wizard-back").click();
    await expect(page.getByTestId("wizard-oob-name-input")).toHaveValue(
      "Agent Pay",
    );
  });

  test("goes straight to Verify for an active payment gateway", async ({
    page,
  }) => {
    await mockPaymentGateways(page, [ACTIVE]);
    await page.goto(`${BASE_URL}/payment-gateways/connect?id=gw-pay`);

    await expect(page.getByTestId("payment-gateway-verify-ok")).toBeVisible();
    await expect(
      page.getByTestId("payment-gateway-verify-offer"),
    ).toContainText("base");
    await page.getByTestId("wizard-next").click();
    await expect(page.getByTestId("wizard-step-complete")).toContainText(
      "Payment gateway ready",
    );

    await page.getByTestId("wizard-submit").click();
    await expect(page).toHaveURL(/\/connections\?tab=payment-gateways$/);
  });
});
