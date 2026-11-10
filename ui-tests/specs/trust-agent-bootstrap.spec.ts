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

  test("the control key block shows the key and rotates it on request", async ({
    page,
  }) => {
    const oldDid = "did:key:z6MkOldOldOldOldOldOldOldOldOldOldOldOldOld";
    const newDid = "did:key:z6MkNewNewNewNewNewNewNewNewNewNewNewNewNew";
    let rotated = false;
    const bootstrap = () => ({
      state: "connected",
      advice: "nothing to do",
      context_id: "gateway",
      previously_connected: true,
      owner: "unclaimed",
      control_did: rotated ? newDid : oldDid,
      control_key_rotation_days: 90,
      control_key_next_rotation_at: "2027-02-08T10:00:00Z",
      ...(rotated ? { control_key_rotated_at: "2026-11-10T10:00:00Z" } : {}),
    });
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [bootstrapConnection] }),
    );
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      route.fulfill({ json: deployment(bootstrap()) }),
    );
    let posts = 0;
    await page.route(/\/api\/v1\/vta\/control-key\/rotate$/, (route) => {
      posts += 1;
      rotated = true;
      return route.fulfill({
        json: {
          previous_control_did: oldDid,
          control_did: newDid,
          rotated_at: "2026-11-10T10:00:00Z",
          next_rotation_at: "2027-02-08T10:00:00Z",
        },
      });
    });
    await page.goto(`${BASE_URL}/trust-agent`);

    await expect(page.getByTestId("bundled-control-key-did")).toHaveAttribute(
      "title",
      oldDid,
    );
    await expect(
      page.getByTestId("bundled-control-key-rotated-at"),
    ).toHaveText("Never rotated");

    await page.getByTestId("bundled-control-key-rotate").click();
    expect(posts).toBe(0);
    await page.getByTestId("bundled-control-key-confirm").click();

    await expect(page.getByTestId("bundled-control-key-did")).toHaveAttribute(
      "title",
      newDid,
    );
    await expect(
      page.getByTestId("bundled-control-key-rotated-at"),
    ).toContainText("Rotated");
    expect(posts).toBe(1);
  });

  test("a connection added by hand rotates its control key, and a stuck rotation can be cancelled", async ({
    page,
  }) => {
    const did = "did:webvh:QmScid:gw.example.com:vta-auth:custom-1";
    let state: Record<string, unknown> = {};
    const custom = () => ({
      ...bootstrapConnection,
      id: "custom-1",
      name: "Custom VTA",
      control_did: did,
      control_key_state: state,
    });
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [bootstrapConnection, custom()] }),
    );
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      route.fulfill({
        json: deployment({
          state: "connected",
          advice: "nothing to do",
          context_id: "gateway",
          previously_connected: true,
          owner: "unclaimed",
          control_key_rotation_days: 90,
        }),
      }),
    );
    const posts: string[] = [];
    let answer = 200;
    await page.route(
      /\/api\/v1\/vta\/connections\/custom-1\/control-key\/rotate(\/cancel)?$/,
      (route) => {
        const url = route.request().url();
        posts.push(url.endsWith("/cancel") ? "cancel" : "rotate");
        if (url.endsWith("/cancel")) {
          state = { last_error: "the rotation was cancelled" };
          return route.fulfill({ json: { connection_id: "custom-1" } });
        }
        if (answer === 200) {
          state = {
            verification_method: "#key-2",
            rotated_at: "2026-11-10T10:00:00Z",
          };
        } else {
          state = {
            last_error: "the trust agent could not be reached",
            rotation: {
              phase: "introduced",
              previous_verification_method: "#key-1",
              next_verification_method: "#key-2",
              started_at: "2026-11-10T10:00:00Z",
              give_up_at: "2026-11-10T10:05:30Z",
              attempts: 2,
            },
          };
        }
        return route.fulfill({ status: answer, json: { connection_id: "custom-1" } });
      },
    );
    await page.goto(`${BASE_URL}/trust-agent`);

    const row = page.locator("tr", { hasText: "Custom VTA" });
    await expect(row.getByTestId("vta-row-control-key-rotated-at")).toHaveText(
      "Never rotated",
    );
    const bundled = page.locator("tr", { hasText: "Bootstrap VTA" });
    await expect(bundled.getByTestId("vta-row-rotate-control-key")).toHaveCount(0);

    await row.getByTestId("vta-row-rotate-control-key").click();
    expect(posts).toEqual([]);
    await page.getByTestId("vta-row-rotate-confirm").click();
    await expect(row.getByTestId("vta-row-control-key")).toContainText("key-2");
    await expect(row.getByTestId("vta-row-control-key-rotated-at")).toContainText(
      "Rotated",
    );
    expect(posts).toEqual(["rotate"]);

    answer = 202;
    await row.getByTestId("vta-row-rotate-control-key").click();
    await page.getByTestId("vta-row-rotate-confirm").click();
    await expect(row.getByTestId("vta-row-rotation-status")).toBeVisible();
    await expect(row.getByTestId("vta-row-rotation-error")).toContainText(
      "could not be reached",
    );
    await expect(row.getByTestId("vta-row-rotate-control-key")).toHaveCount(0);

    await row.getByTestId("vta-row-rotate-cancel").click();
    await expect(row.getByTestId("vta-row-rotation-status")).toHaveCount(0);
    await expect(row.getByTestId("vta-row-rotate-control-key")).toBeVisible();
    expect(posts).toEqual(["rotate", "rotate", "cancel"]);
  });
});
