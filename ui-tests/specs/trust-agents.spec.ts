/**
 * Connections → Trust Agents and Key Management: the list, the full-page connect wizard, and
 * where the old pages went.
 *
 * Every `/vta` call is served by `page.route` mocks, so the spec needs no trust agent. Every
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

const GRANT_COMMAND =
  "vta acl create --did did:webvh:gw:localhost%3A8080:vta-auth:agent-1 --role initiator --contexts gateway --capabilities context-create,key-mint,sign-jws,sign-document --label agent-gateway";

const agent = (overrides: Record<string, unknown> = {}) => ({
  id: "agent-1",
  name: "Production agent",
  enabled: true,
  transport: "https",
  endpoint: "https://vta.example.com",
  vta_did: "did:webvh:abc:vta.example.com",
  default_context_id: "gateway",
  control_did: "did:webvh:gw:localhost%3A8080:vta-auth:agent-1",
  status: "connected",
  pairing: {
    state: "connected",
    granted_role: "initiator",
    granted_contexts: ["gateway"],
    last_verified_at: "2026-01-01T00:00:00Z",
  },
  keys: { active: { key_id: "key-1" } },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  ...overrides,
});

const status = (overrides: Record<string, unknown> = {}) => ({
  enabled: false,
  tier: "local",
  custody_claim: false,
  auto_provision_contexts: false,
  reserved_origins: [],
  default_resolution: {
    backend: "local",
    reason:
      "no trust agent is configured, so this gateway signs with its own key",
    explicit: false,
  },
  ...overrides,
});

async function mockTrustAgents(
  page: Page,
  connections: Array<Record<string, unknown>>,
  deployment: Record<string, unknown> = status(),
) {
  await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
    route.request().method() === "GET"
      ? json(route, connections)
      : route.fallback(),
  );
  await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
    json(route, deployment),
  );
}

test.describe("Connections: Trust Agents and Key Management tabs", () => {
  test("lists the trust agents beside the other connections", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/connections`);

    await expect(page.getByTestId("connections-tab-trust-agents")).toHaveText(
      /Trust Agents/,
    );
    await expect(page.getByTestId("connections-tab-key-management")).toHaveText(
      /Key Management/,
    );

    await page.getByTestId("connections-tab-trust-agents").click();
    await expect(page).toHaveURL(/tab=trust-agents/);
    await expect(page.getByTestId("page-trust-agents")).toBeVisible();
    await expect(page.getByText("Production agent")).toBeVisible();
  });

  test("filters the list with the Connections filter box", async ({ page }) => {
    await mockTrustAgents(page, [
      agent(),
      agent({ id: "agent-2", name: "Staging agent" }),
    ]);
    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);
    await expect(page.getByText("Staging agent")).toBeVisible();

    await page.getByTestId("connections-search-input").fill("staging");

    await expect(page.getByText("Staging agent")).toBeVisible();
    await expect(page.getByText("Production agent")).toHaveCount(0);
  });

  test("says so when there is no trust agent, and offers the wizard", async ({
    page,
  }) => {
    await mockTrustAgents(page, []);
    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    await page.getByTestId("trust-agents-empty-connect-button").click();

    await expect(page).toHaveURL(/\/trust-agents\/connect$/);
    await expect(page.getByTestId("wizard-add-trust-agent")).toBeVisible();
  });

  test("has no sidebar entry of its own for trust agents", async ({ page }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    await expect(page.getByTestId("page-trust-agents")).toBeVisible();
    await expect(page.locator('a[href="/trust-agent"]')).toHaveCount(0);
    await expect(page.getByTestId("nav-trust-agent")).toHaveCount(0);
  });

  test("shows signing in Key Management, and Settings no longer has its own card", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/connections?tab=key-management`);

    await expect(page.getByTestId("key-management-panel")).toBeVisible();
    await expect(page.getByTestId("key-management-signing-with")).toContainText(
      "local",
    );
    await expect(
      page.getByTestId("key-management-connect-button"),
    ).toBeVisible();

    await page.goto(`${BASE_URL}/settings`);
    await expect(page.getByTestId("key-management-settings")).toHaveCount(0);
  });
});

test.describe("Connect Trust Agent wizard", () => {
  test("creates the connection, shows the grant to run, verifies and completes", async ({
    page,
  }) => {
    const created: unknown[] = [];
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) => {
      if (route.request().method() === "POST") {
        created.push(route.request().postDataJSON());
        return json(
          route,
          agent({
            status: "unpaired",
            pairing: { state: "pending" },
            keys: {},
          }),
          201,
        );
      }
      return json(route, []);
    });
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      json(route, status()),
    );
    await page.route("**/api/v1/vta/connections/agent-1/pair", (route) =>
      json(route, {
        connection_id: "agent-1",
        control_did: "did:webvh:gw:localhost%3A8080:vta-auth:agent-1",
        vta_did: "did:webvh:abc:vta.example.com",
        endpoint: "https://vta.example.com",
        context_id: "gateway",
        requested_role: "initiator",
        expires_at: "2999-01-01T00:00:00Z",
        grant_command: GRANT_COMMAND,
      }),
    );
    await page.route("**/api/v1/vta/connections/agent-1/verify", (route) =>
      json(route, agent()),
    );

    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);
    await page.getByTestId("trust-agents-connect-button").click();
    await expect(page).toHaveURL(/\/trust-agents\/connect$/);
    await expect(page.getByTestId("wizard-progress")).toBeVisible();

    await page
      .getByTestId("wizard-trust-agent-name-input")
      .fill("Production agent");
    await page
      .getByTestId("wizard-trust-agent-endpoint-input")
      .fill("https://vta.example.com");
    await page
      .getByTestId("wizard-trust-agent-did-input")
      .fill("did:webvh:abc:vta.example.com");
    await page.getByTestId("wizard-trust-agent-context-input").fill("gateway");
    await page.getByTestId("wizard-next").click();

    await expect(page.getByTestId("wizard-step-grant")).toBeVisible();
    await expect(page.getByText(GRANT_COMMAND)).toBeVisible();
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({
      name: "Production agent",
      default_context_id: "gateway",
      transport: "https",
    });
    expect(JSON.stringify(created[0])).not.toContain("admin");

    await page.getByTestId("wizard-next").click();
    await expect(page.getByTestId("wizard-step-complete")).toBeVisible();

    await page.getByTestId("wizard-submit").click();
    await expect(page).toHaveURL(/\/connections\?tab=trust-agents/);
  });

  test("a pending connection is resumed from its row at the grant step", async ({
    page,
  }) => {
    await mockTrustAgents(page, [
      agent({ status: "unpaired", pairing: { state: "pending" }, keys: {} }),
    ]);
    await page.route("**/api/v1/vta/connections/agent-1/pair", (route) =>
      json(route, {
        connection_id: "agent-1",
        control_did: "did:webvh:gw:localhost%3A8080:vta-auth:agent-1",
        vta_did: "did:webvh:abc:vta.example.com",
        endpoint: "https://vta.example.com",
        context_id: "gateway",
        requested_role: "initiator",
        expires_at: "2999-01-01T00:00:00Z",
        grant_command: GRANT_COMMAND,
      }),
    );

    await page.goto(`${BASE_URL}/connections/trust-agents/connect?id=agent-1`);

    await expect(page.getByTestId("wizard-step-grant")).toBeVisible();
    await expect(page.getByText(GRANT_COMMAND)).toBeVisible();
  });
});
