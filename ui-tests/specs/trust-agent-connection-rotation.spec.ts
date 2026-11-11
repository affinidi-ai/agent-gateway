import { expect, test } from "../helpers/fixtures";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const deployment = (controlKey: Record<string, unknown> | null = null) => ({
  enabled: true,
  tier: "self-hosted",
  custody_claim: false,
  auto_provision_contexts: true,
  reserved_origins: [],
  control_did_method: "did_key",
  control_key: controlKey,
});

const configConnection = {
  id: "vta-bootstrap",
  name: "Configured VTA",
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

test.describe("Trust Agent page: control key rotation", () => {
  test("the control key card shows the key and rotates it, and is absent without one", async ({
    page,
  }) => {
    const oldDid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const newDid = "did:key:z6MkNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNE";
    let rotated = false;
    const controlKey = () => ({
      control_did: rotated ? newDid : oldDid,
      rotation_days: 90,
      next_rotation_at: "2027-02-08T10:00:00Z",
      ...(rotated ? { rotated_at: "2026-11-10T10:00:00Z" } : {}),
    });
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [configConnection] }),
    );
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      route.fulfill({ json: deployment(controlKey()) }),
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

    await expect(page.getByTestId("vta-control-key-did")).toHaveAttribute(
      "title",
      oldDid,
    );
    await expect(page.getByTestId("vta-control-key-rotated-at")).toHaveText(
      "Never rotated",
    );

    await page.getByTestId("vta-control-key-rotate").click();
    expect(posts).toBe(0);
    await page.getByTestId("vta-control-key-confirm").click();

    await expect(page.getByTestId("vta-control-key-did")).toHaveAttribute(
      "title",
      newDid,
    );
    expect(posts).toBe(1);
  });

  test("the control key card is not rendered when the gateway holds no rotatable key", async ({
    page,
  }) => {
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [configConnection] }),
    );
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      route.fulfill({ json: deployment(null) }),
    );
    await page.goto(`${BASE_URL}/trust-agent`);

    await expect(page.getByText("Connections").first()).toBeVisible();
    await expect(page.getByTestId("vta-control-key")).toHaveCount(0);
  });

  test("a connection added by hand rotates its control key, and a stuck rotation can be cancelled", async ({
    page,
  }) => {
    const did = "did:webvh:QmScid:gw.example.com:vta-auth:custom-1";
    let state: Record<string, unknown> = {};
    const custom = () => ({
      ...configConnection,
      id: "custom-1",
      name: "Custom VTA",
      control_did: did,
      control_key_state: state,
    });
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      route.fulfill({ json: [configConnection, custom()] }),
    );
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      route.fulfill({
        json: deployment(),
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
        return route.fulfill({
          status: answer,
          json: { connection_id: "custom-1" },
        });
      },
    );
    await page.goto(`${BASE_URL}/trust-agent`);

    const row = page.locator("tr", { hasText: "Custom VTA" });
    await expect(row.getByTestId("vta-row-control-key-rotated-at")).toHaveText(
      "Never rotated",
    );
    const configBlock = page.locator("tr", { hasText: "Configured VTA" });
    await expect(
      configBlock.getByTestId("vta-row-rotate-control-key"),
    ).toHaveCount(0);

    await row.getByTestId("vta-row-rotate-control-key").click();
    expect(posts).toEqual([]);
    await page.getByTestId("vta-row-rotate-confirm").click();
    await expect(row.getByTestId("vta-row-control-key")).toContainText("key-2");
    await expect(
      row.getByTestId("vta-row-control-key-rotated-at"),
    ).toContainText("Rotated");
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
