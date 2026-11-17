/**
 * Connections → Verifiable Trust Agent, its full-page connect wizard, and Settings → Security →
 * Audit signing.
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

const INTRO =
  "Connect a Verifiable Trust Agent to sign audit records with a key the gateway doesn't control. Anyone can verify your records without having to trust the gateway, and even if the gateway is compromised, its records can't be forged or altered. You keep full control of the agent.";

test.describe("Connections: Verifiable Trust Agent tab", () => {
  test("lists the agents beside the other connections, with what connecting one gives", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/connections`);
    await expect(page.getByTestId("connections-tab-trust-agents")).toHaveText(
      /Verifiable Trust Agent/,
    );
    await expect(
      page.getByTestId("connections-tab-key-management"),
    ).toHaveCount(0);

    await page.getByTestId("connections-tab-trust-agents").click();
    await expect(page).toHaveURL(/tab=trust-agents/);
    await expect(page.getByTestId("page-trust-agents")).toBeVisible();
    await expect(page.getByTestId("trust-agents-intro")).toHaveText(INTRO);
    await expect(page.getByText("Production agent")).toBeVisible();
    await expect(page.getByText(/Signing locally/)).toHaveCount(0);
  });

  test("says which DID new contexts sign as, from the deployment", async ({
    page,
  }) => {
    await mockTrustAgents(
      page,
      [agent()],
      status({
        context_did_method: "did_webvh",
        context_did_hosting: "gateway",
      }),
    );

    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);
    await expect(page.getByTestId("trust-agents-context-did")).toHaveText(
      "New contexts sign as a did:webvh, hosted by this gateway. The trust agent's operator can rotate a context's key without changing its DID.",
    );
  });

  test("says a did:webvh is hosted on the trust agent's webvh server", async ({
    page,
  }) => {
    await mockTrustAgents(
      page,
      [agent()],
      status({
        context_did_method: "did_webvh",
        context_did_hosting: "vta_server",
      }),
    );

    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);
    await expect(page.getByTestId("trust-agents-context-did")).toContainText(
      "on the trust agent's webvh server",
    );
  });

  test("says new contexts sign as a did:key by default", async ({ page }) => {
    await mockTrustAgents(
      page,
      [agent()],
      status({ context_did_method: "did_key", context_did_hosting: "gateway" }),
    );

    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);
    await expect(page.getByTestId("trust-agents-context-did")).toContainText(
      "New contexts sign as a did:key",
    );
  });

  test("has Add VTA and no filter box beside it", async ({ page }) => {
    await mockTrustAgents(page, [agent()]);
    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    await expect(page.getByTestId("trust-agents-connect-button")).toHaveText(
      /Add VTA/,
    );
    await expect(page.getByTestId("connections-search-input")).toHaveCount(0);

    await page.goto(`${BASE_URL}/connections?tab=trust-registries`);
    await expect(page.getByTestId("connections-search-input")).toBeVisible();
  });

  test("says so when there is no agent, and offers Add VTA", async ({
    page,
  }) => {
    await mockTrustAgents(page, []);
    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    const add = page.getByTestId("trust-agents-empty-connect-button");
    await expect(add).toHaveText(/Add VTA/);
    await add.click();

    await expect(page).toHaveURL(/\/connections\/trust-agents\/connect$/);
    await expect(page.getByTestId("wizard-add-trust-agent")).toBeVisible();
  });

  test("has no sidebar entry of its own", async ({ page }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    await expect(page.getByTestId("page-trust-agents")).toBeVisible();
    await expect(page.locator('a[href="/trust-agent"]')).toHaveCount(0);
    await expect(page.getByTestId("nav-trust-agent")).toHaveCount(0);
  });
});

test.describe("Settings → Security → Audit signing", () => {
  test("is the first section, labelled as the gateway-wide default, with the same choice as a surface", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();

    const section = page.getByTestId("audit-signing-settings");
    await expect(section).toBeVisible();
    await expect(section).toContainText("Audit signing");
    await expect(page.getByTestId("audit-signing-scope")).toHaveText(
      "Gateway-wide default",
    );
    await expect(section).toContainText("Signing key source");
    await expect(section).not.toContainText("Signing with");
    await expect(
      section.getByTestId("surface-signing-type-select").locator("option"),
    ).toHaveText(["Gateway secret", "Verifiable Trust Agent"]);
    await expect(page.getByTestId("audit-signing-connect-button")).toHaveText(
      /Connect my own VTA/,
    );
    await expect(page.getByTestId("key-management-settings")).toHaveCount(0);

    const first = await page
      .locator('[data-testid="audit-signing-settings"]')
      .evaluate(
        (el) =>
          el.parentElement?.firstElementChild === el ||
          el.parentElement?.querySelector(".card") === el,
      );
    expect(first, "Audit signing is the first section of the tab").toBe(true);
  });

  test("saves a Verifiable Trust Agent as the gateway-wide default", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);
    const posts: unknown[] = [];
    await page.route(/\/api\/v1\/settings$/, (route) => {
      if (route.request().method() === "POST") {
        posts.push(route.request().postDataJSON());
        return json(route, {});
      }
      return route.fallback();
    });

    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();
    const section = page.getByTestId("audit-signing-settings");
    await section
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");
    await expect(page.getByTestId("audit-signing-save-button")).toBeDisabled();
    await section
      .getByTestId("surface-signing-agent-select")
      .selectOption("agent-1");
    await page.getByTestId("audit-signing-save-button").click();

    await expect(page.getByTestId("audit-signing-saved")).toBeVisible();
    expect(posts).toEqual([
      {
        default_signing: {
          backend: "vta",
          connection_id: "agent-1",
          context_id: "gateway",
          key_id: "key-1",
        },
      },
    ]);
  });

  test("Connect my own VTA opens the wizard", async ({ page }) => {
    await mockTrustAgents(page, [agent()]);
    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();

    await page.getByTestId("audit-signing-connect-button").click();

    await expect(page).toHaveURL(/\/connections\/trust-agents\/connect$/);
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
