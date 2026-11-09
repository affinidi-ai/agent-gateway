import { expect, test } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const deployment = (bootstrap: Record<string, unknown> | null) => ({
  enabled: true,
  tier: "bundled",
  custody_claim: false,
  self_administered: true,
  auto_provision_contexts: true,
  reserved_origins: [],
  control_did_method: "did_key",
  bootstrap,
});

const bootstrapConnection = {
  id: "vta-bootstrap",
  name: "Bootstrap VTA",
  description: "Migrated from the [vta] configuration block.",
  enabled: true,
  transport: "https",
  endpoint: "http://127.0.0.1:8100",
  vta_did: "did:key:z6MkVta",
  default_context_id: "gateway",
  status: "connected",
  pairing: {
    state: "connected",
    pinned_vta_did: "did:key:z6MkVta",
    granted_role: "initiator",
    granted_contexts: ["gateway"],
    last_verified_at: "2026-01-01T00:00:00Z",
  },
  keys: {},
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

async function openTrustAgent(
  page: Page,
  bootstrap: Record<string, unknown> | null,
) {
  await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
    route.fulfill({ json: bootstrap ? [bootstrapConnection] : [] }),
  );
  await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
    route.fulfill({ json: deployment(bootstrap) }),
  );
  await page.goto(`${BASE_URL}/trust-agent`);
}

test.describe("Trust Agent page: bundled bootstrap", () => {
  test("a connected sidecar shows its owner as unclaimed and no custody claim", async ({
    page,
  }) => {
    await openTrustAgent(page, {
      state: "connected",
      advice: "nothing to do",
      context_id: "gateway",
      previously_connected: true,
      owner: "unclaimed",
    });
    const status = page.getByTestId("vta-bootstrap-status");
    await expect(status).toContainText("Connected");
    await expect(page.getByTestId("vta-bootstrap-owner")).toHaveText(
      "unclaimed",
    );
    await expect(page.getByTestId("vta-bootstrap-advice")).toHaveCount(0);
  });

  test("the bundled agent's connection row reads Connected and offers no Verify or Revoke", async ({
    page,
  }) => {
    await openTrustAgent(page, {
      state: "connected",
      advice: "nothing to do",
      context_id: "gateway",
      previously_connected: true,
      owner: "unclaimed",
    });
    const row = page.locator("tr", { hasText: "Bootstrap VTA" });
    await expect(row).toContainText("Connected");
    await expect(row).not.toContainText("Not paired");
    await expect(row.getByRole("button", { name: "Revoke" })).toHaveCount(0);
    await expect(row.getByRole("button", { name: "Verify" })).toHaveCount(0);
  });

  test("a revoked gateway shows what to do and that signing is refused", async ({
    page,
  }) => {
    await openTrustAgent(page, {
      state: "revoked",
      advice: "re-grant the gateway's access on the trust agent",
      context_id: "gateway",
      previously_connected: true,
      owner: "unclaimed",
    });
    await expect(page.getByTestId("vta-bootstrap-status")).toContainText(
      "Access revoked",
    );
    await expect(page.getByTestId("vta-bootstrap-advice")).toContainText(
      "re-grant",
    );
    await expect(page.getByTestId("vta-bootstrap-status")).toContainText(
      "Signing is refused until this is resolved",
    );
  });

  test("a gateway with no bundled sidecar shows no bootstrap line", async ({
    page,
  }) => {
    await openTrustAgent(page, null);
    await expect(
      page.getByRole("heading", { name: /trust agent/i }).first(),
    ).toBeVisible();
    await expect(page.getByTestId("vta-bootstrap-status")).toHaveCount(0);
  });

  test("a gateway signing locally because the sidecar never came up says why", async ({
    page,
  }) => {
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      route.fulfill({
        json: {
          ...deployment({
            state: "waiting_for_vta",
            advice: "start the bundled trust agent, then restart the gateway",
            context_id: "gateway",
            previously_connected: false,
            owner: "unclaimed",
          }),
          enabled: false,
          tier: "local",
        },
      }),
    );
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [] }),
    );
    await page.goto(`${BASE_URL}/trust-agent`);
    await expect(page.getByText("Signing locally")).toBeVisible();
    await expect(page.getByTestId("vta-bootstrap-advice")).toContainText(
      "restart the gateway",
    );
  });

  test("Settings names the bundled trust agent as the current signing default", async ({
    page,
  }) => {
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      route.fulfill({
        json: {
          ...deployment(null),
          default_resolution: {
            backend: "bundled",
            reason:
              "the [vta] block is enabled, so this appliance signs through its bundled trust agent",
            explicit: true,
          },
        },
      }),
    );
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [bootstrapConnection] }),
    );
    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("key-management-settings-toggle").click();
    const picker = page.locator("#default-signing-select");
    await expect(picker).toBeVisible();
    await expect(picker.locator("option:checked")).toHaveText(
      "The bundled trust agent (default)",
    );
    await expect(picker.locator("option", { hasText: "own key" })).toHaveCount(
      0,
    );
    await expect(
      picker.locator("option", { hasText: "Bootstrap VTA" }),
    ).toHaveCount(0);
    await expect(
      page.getByTestId("key-management-settings-signing-with"),
    ).toContainText("bundled");
  });

  test("a surface can be pinned to the connected bundled trust agent", async ({
    page,
  }) => {
    const bundledReady = {
      ...bootstrapConnection,
      keys: {
        active: { key_id: "gateway-jwt-1", public_key: "z6MkBundledKey" },
      },
    };
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [bundledReady] }),
    );
    await page.goto(`${BASE_URL}/surfaces/new`);
    await page.getByText("A2A Surface Starter", { exact: true }).click();
    await page
      .locator("button:has(i.fa-arrow-right), button:has(svg)")
      .nth(0)
      .click();
    await page
      .getByRole("button", { name: "Got it" })
      .click({ timeout: 5000 })
      .catch(() => {});
    await page.getByTestId("surface-node-surface").click();
    const select = page.locator("#surface-signing-select");
    await expect(
      select.locator("option", { hasText: "Bundled trust agent" }),
    ).toHaveCount(1);
    await expect(
      select.locator("option", { hasText: "not ready" }),
    ).toHaveCount(0);
    await select.selectOption({ label: "Bundled trust agent" });
    await expect(select.locator("option:checked")).toHaveText(
      "Bundled trust agent",
    );
  });
});
