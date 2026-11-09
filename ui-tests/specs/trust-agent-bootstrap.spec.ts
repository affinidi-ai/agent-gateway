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

  test("the bundled agent's connection row reads Connected and offers no Revoke", async ({
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
    await expect(row.getByRole("button", { name: "Verify" })).toBeVisible();
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
});
