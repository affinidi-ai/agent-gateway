/**
 * Connections → Verifiable Trust Agent, its full-page connect wizard, and Settings → Security →
 * Gateway signing.
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

const OLD_INTRO = /Connect a Verifiable Trust Agent to sign audit records/;

test.describe("Connections: Verifiable Trust Agent tab", () => {
  test("lists the agents beside the other connections, with no intro or context DID note", async ({
    page,
  }) => {
    await mockTrustAgents(
      page,
      [agent()],
      status({ context_did_method: "did_key", context_did_hosting: "gateway" }),
    );

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
    await expect(page.getByText("Production agent")).toBeVisible();
    await expect(page.getByText(OLD_INTRO)).toHaveCount(0);
    await expect(page.getByText(/New contexts sign as/)).toHaveCount(0);
    await expect(page.getByText(/Signing locally/)).toHaveCount(0);
  });

  test("has Add VTA in the card header in place of Refresh, like Add Trust Registry, and no filter box", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);
    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    const header = page
      .getByTestId("page-trust-agents")
      .locator(".card-header")
      .filter({ hasText: "Verifiable Trust Agents" });
    const add = header.getByTestId("trust-agents-connect-button");
    await expect(add).toHaveText(/Add VTA/);
    await expect(add).toHaveClass(/btn-primary/);
    await expect(header.getByRole("button", { name: "Refresh" })).toHaveCount(
      0,
    );
    await expect(page.getByRole("button", { name: /Add VTA/ })).toHaveCount(1);
    await expect(page.getByTestId("connections-search-input")).toHaveCount(0);

    await add.click();
    await expect(page).toHaveURL(/\/connections\/trust-agents\/connect$/);
    await expect(page.getByTestId("wizard-add-trust-agent")).toBeVisible();

    await page.goto(`${BASE_URL}/connections?tab=trust-registries`);
    await expect(page.getByTestId("connections-search-input")).toBeVisible();
  });

  test("with no agent, says to add the first one and links the docs, with Add VTA only in the card header", async ({
    page,
  }) => {
    await mockTrustAgents(page, []);
    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    const tab = page.getByTestId("page-trust-agents");
    await expect(
      tab.getByText("Add your first Verifiable Trust Agent"),
    ).toBeVisible();
    await expect(tab.getByRole("link", { name: /View Docs/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /Add VTA/ })).toHaveCount(1);
    await expect(
      tab.locator(".card-header").getByTestId("trust-agents-connect-button"),
    ).toBeVisible();
    await expect(page.getByText(OLD_INTRO)).toHaveCount(0);
  });

  test("has no sidebar entry of its own", async ({ page }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);

    await expect(page.getByTestId("page-trust-agents")).toBeVisible();
    await expect(page.locator('a[href="/trust-agent"]')).toHaveCount(0);
    await expect(page.getByTestId("nav-trust-agent")).toHaveCount(0);
  });
});

test.describe("Settings → Security → Gateway signing", () => {
  test("is the first section, labelled as the gateway-wide default, with the same choice as a surface", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);

    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();

    const section = page.getByTestId("gateway-signing-settings");
    await expect(section).toBeVisible();
    await expect(section).toContainText("Gateway signing");
    await expect(page.getByTestId("gateway-signing-scope")).toHaveCount(0);
    await expect(section).not.toContainText("Gateway-wide default");
    await expect(section).toContainText("Signing key source");
    await expect(section).not.toContainText("Signing with");
    await expect(
      section.getByTestId("surface-signing-type-select").locator("option"),
    ).toHaveText(["Gateway secret", "Verifiable Trust Agent"]);
    await expect(
      section.getByTestId("surface-signing-type-select"),
    ).toHaveValue("local");
    await expect(
      page.getByTestId("gateway-signing-connect-button"),
    ).toHaveCount(0);
    await expect(page.getByTestId("key-management-settings")).toHaveCount(0);

    const first = await page
      .locator('[data-testid="gateway-signing-settings"]')
      .evaluate(
        (el) =>
          el.parentElement?.firstElementChild === el ||
          el.parentElement?.querySelector(".card") === el,
      );
    expect(first, "Gateway signing is the first section of the tab").toBe(true);
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
    const section = page.getByTestId("gateway-signing-settings");
    await section
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");
    await expect(
      page.getByTestId("gateway-signing-save-button"),
    ).toBeDisabled();
    await section
      .getByTestId("surface-signing-agent-select")
      .selectOption("agent-1");
    await page.getByTestId("gateway-signing-save-button").click();
    const dialog = page.getByRole("dialog", { name: "Change gateway signing" });
    await expect(dialog).toContainText("must trust the new issuer DID");
    expect(posts).toEqual([]);
    await page.getByTestId("gateway-signing-confirm-dialog-confirm").click();

    await expect(page.getByTestId("gateway-signing-saved")).toBeVisible();
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

  test("Connect VTA shows in the card header while Verifiable Trust Agent is chosen and opens the wizard", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);
    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();
    const section = page.getByTestId("gateway-signing-settings");
    await section
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");

    const connect = section
      .locator(".card-header")
      .getByTestId("gateway-signing-connect-button");
    await expect(connect).toHaveText(/Connect VTA/);
    await connect.click();

    await expect(page).toHaveURL(/\/connections\/trust-agents\/connect$/);
  });

  test("Connect VTA sits at the right of the card header and goes away with Gateway secret", async ({
    page,
  }) => {
    await mockTrustAgents(page, [agent()]);
    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();
    const section = page.getByTestId("gateway-signing-settings");
    const type = section.getByTestId("surface-signing-type-select");
    const connect = page.getByTestId("gateway-signing-connect-button");
    await expect(type).toHaveValue("local");
    await expect(connect).toHaveCount(0);

    await type.selectOption("remote");
    const header = section.locator(".card-header");
    await expect(
      header.getByTestId("gateway-signing-connect-button"),
    ).toBeVisible();
    const headerBox = await header.boundingBox();
    const buttonBox = await connect.boundingBox();
    const titleBox = await header.locator("h6").boundingBox();
    expect(headerBox && buttonBox && titleBox).toBeTruthy();
    expect(
      headerBox!.x + headerBox!.width - (buttonBox!.x + buttonBox!.width),
      "the button is flush with the header's right edge",
    ).toBeLessThan(40);
    expect(buttonBox!.x).toBeGreaterThan(titleBox!.x + titleBox!.width);
    await expect(connect).toHaveClass(/btn-primary/);
    await expect(
      section.getByTestId("surface-signing-agent-select"),
    ).toBeVisible();

    await type.selectOption("local");
    await expect(connect).toHaveCount(0);
    await expect(
      section.getByTestId("surface-signing-agent-select"),
    ).toHaveCount(0);
  });

  test("shows no agent list until a Verifiable Trust Agent is connected", async ({
    page,
  }) => {
    await mockTrustAgents(page, []);
    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();
    const section = page.getByTestId("gateway-signing-settings");
    await section
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");

    await expect(
      section.getByTestId("surface-signing-no-agents"),
    ).toContainText("No Verifiable Trust Agent is connected yet");
    await expect(
      section.getByTestId("surface-signing-agent-select"),
    ).toHaveCount(0);
    await expect(
      page.getByTestId("gateway-signing-save-button"),
    ).toBeDisabled();
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
