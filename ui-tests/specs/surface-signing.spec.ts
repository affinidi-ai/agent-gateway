/**
 * Surface Builder → Surface → Signing key source: Gateway secret or Verifiable Trust Agent, and a
 * connected agent for the latter.
 *
 * The trust agent calls are served by `page.route` mocks, so the spec needs no trust agent. Every
 * control is located by test id.
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

const agent = (overrides: Record<string, unknown> = {}) => ({
  id: "agent-1",
  name: "Production agent",
  enabled: true,
  transport: "https",
  endpoint: "https://vta.example.com",
  vta_did: "did:webvh:abc:vta.example.com",
  default_context_id: "gateway",
  status: "connected",
  pairing: { state: "connected" },
  keys: { active: { key_id: "key-1" } },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  ...overrides,
});

async function openSurfacePanel(
  page: Page,
  connections: Array<Record<string, unknown>>,
  defaultBackend = "local",
) {
  await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
    json(route, connections),
  );
  await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
    json(route, {
      enabled: false,
      tier: "local",
      custody_claim: false,
      default_resolution: {
        backend: defaultBackend,
        reason: "test",
        explicit: false,
      },
    }),
  );
  await page.goto(`${BASE_URL}/surfaces/new`);
  await page
    .locator("button:has(.fa-arrow-right), button:has(.fa-arrow-right-long)")
    .first()
    .click();
  await page.getByTestId("surface-node-surface").click();
  await expect(page.getByTestId("surface-signing-type-select")).toBeVisible();
}

test.describe("Surface signing", () => {
  test("offers Gateway secret and Verifiable Trust Agent, and follows the gateway-wide default until chosen", async ({
    page,
  }) => {
    await openSurfacePanel(page, [agent()]);

    const type = page.getByTestId("surface-signing-type-select");
    await expect(type.locator("option")).toHaveText([
      "Gateway secret",
      "Verifiable Trust Agent",
    ]);
    await expect(type).toHaveValue("local");
    await expect(page.getByTestId("surface-signing-inherited")).toContainText(
      "Following the gateway-wide default (Gateway secret)",
    );
    await expect(page.getByTestId("surface-signing-agent-select")).toHaveCount(
      0,
    );
  });

  test("Verifiable Trust Agent lists the connected agents and links to the connect wizard in a new tab", async ({
    page,
  }) => {
    await openSurfacePanel(page, [
      agent(),
      agent({ id: "agent-2", name: "No key yet", keys: {} }),
    ]);

    await page
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");

    const picker = page.getByTestId("surface-signing-agent-select");
    await expect(picker).toBeVisible();
    await expect(picker.locator("option")).toHaveText([
      "Select a Verifiable Trust Agent…",
      "Production agent",
      "No key yet — not ready: connect it and provision a key first",
    ]);
    await expect(picker.locator('option[value="agent-2"]')).toBeDisabled();
    await expect(page.getByTestId("surface-signing-pick-agent")).toBeVisible();

    const link = page.getByTestId("surface-signing-connect-link");
    await expect(link).toHaveAttribute(
      "href",
      "/connections/trust-agents/connect",
    );
    await expect(link).toHaveAttribute("target", "_blank");
  });

  test("a chosen trust agent is saved in the surface with its context and key", async ({
    page,
  }) => {
    await openSurfacePanel(page, [agent()]);
    await page
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");

    await page
      .getByTestId("surface-signing-agent-select")
      .selectOption("agent-1");

    await expect(page.getByText("Signs in context")).toBeVisible();
    await page.getByTestId("surface-view-config").click();
    const config = page.locator(".monaco-editor, textarea, pre").first();
    await expect(config).toBeVisible();
    await expect(page.locator("body")).toContainText('"connection_id"');
    await expect(page.locator("body")).toContainText("agent-1");
  });

  test("shows Verifiable Trust Agent when the gateway-wide default signs through one", async ({
    page,
  }) => {
    await openSurfacePanel(page, [agent()], "vta");

    await expect(page.getByTestId("surface-signing-type-select")).toHaveValue(
      "remote",
    );
    await expect(page.getByTestId("surface-signing-inherited")).toContainText(
      "Following the gateway-wide default (Verifiable Trust Agent)",
    );
  });

  test("a chosen agent can be handed back to the gateway-wide default", async ({
    page,
  }) => {
    await openSurfacePanel(page, [agent()]);
    await page
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");
    await page
      .getByTestId("surface-signing-agent-select")
      .selectOption("agent-1");
    await expect(page.getByText("Signs in context")).toBeVisible();

    await page.getByTestId("surface-signing-reset").click();

    await expect(page.getByTestId("surface-signing-inherited")).toBeVisible();
    await expect(page.getByText("Signs in context")).toHaveCount(0);
  });

  test("shows no agent list until a Verifiable Trust Agent is connected, and lists it after Refresh", async ({
    page,
  }) => {
    await openSurfacePanel(page, []);

    await page
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");

    await expect(page.getByTestId("surface-signing-no-agents")).toHaveText(
      "No Verifiable Trust Agent is connected yet.",
    );
    await expect(page.getByTestId("surface-signing-agent-select")).toHaveCount(
      0,
    );
    await expect(page.getByTestId("surface-signing-pick-agent")).toHaveCount(0);
    await expect(page.getByTestId("surface-signing-connect-link")).toHaveText(
      "Add VTA",
    );

    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      json(route, [agent()]),
    );
    await page.getByTestId("surface-signing-refresh").click();

    const picker = page.getByTestId("surface-signing-agent-select");
    await expect(picker).toBeVisible();
    await expect(picker.locator('option[value="agent-1"]')).toHaveText(
      "Production agent",
    );
    await expect(page.getByTestId("surface-signing-no-agents")).toHaveCount(0);
  });
});
