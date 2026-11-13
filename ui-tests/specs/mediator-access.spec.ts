/**
 * The mediator access step of both peer pairing wizards: it shows the DIDs the
 * gateway minted, copies them, lets the user leave and resume from
 * Connections, and keeps the step while the mediator still refuses a DID.
 *
 * Every gateway, connection point and mediator call is served by `page.route`
 * mocks, so the spec needs no mediator. Every control is located by test id.
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

const MEDIATOR = {
  id: "med-x",
  name: "Mediator X",
  description: "",
  did: "did:web:mediator-x.example",
  status: "active",
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
};

const CP_DID = "did:peer:2.Ez6LSconnectionpointdidforthepause";
const CP_PERMANENT_DID = "did:peer:2.Ez6LSpermanentdidforthepairedgateway";
const TEMP_DID = "did:peer:2.Ez6LStemporarydidforthehandshake";
const ACCEPTOR_PERMANENT_DID = "did:peer:2.Ez6LSpermanentdidforthispairing";

const SELF_GATEWAY = {
  id: "gw-self",
  name: "This gateway",
  description: "",
  did: "did:web:self.example",
  gateway_type: "self",
  status: "active",
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
};

const PAUSED_GATEWAY = {
  ...SELF_GATEWAY,
  id: "gw-paused",
  name: "Partner",
  description: "Partner gateway",
  did: "did:peer:2.inviter",
  gateway_type: "remote",
  status: "awaiting-mediator-access",
  creation_type: "user",
  role: "peer",
};

const PENDING_GATEWAY = {
  ...PAUSED_GATEWAY,
  id: "gw-pending",
  name: "Partner sent",
  status: "pending",
};

const PAUSED_CP = {
  id: "cp-paused",
  gateway_id: "gw-self",
  mediator_id: "med-x",
  connection_point_did: CP_DID,
  name: "Partner invitation",
  description: "",
  oob_id: "",
  oob_url: "",
  use_count: 0,
  created_at: "2026-11-12T00:00:00Z",
  expires_at: "2026-11-19T00:00:00Z",
  cp_type: "user",
  secret: "s3cret",
  enabled: true,
  did_method: "peer",
  awaiting_mediator_access: true,
};

const OPENED_CP = {
  ...PAUSED_CP,
  oob_id: "oob-1",
  oob_url: "https://mediator-x.example/oob?_oobid=oob-1",
  awaiting_mediator_access: undefined,
};

const CP_ACCESS = {
  mediator_did: MEDIATOR.did,
  mediator_name: MEDIATOR.name,
  dids: [
    { role: "connection_point", did: CP_DID, mediator_did: MEDIATOR.did },
    { role: "permanent", did: CP_PERMANENT_DID, mediator_did: MEDIATOR.did },
  ],
  expires_at: "2026-11-19T00:00:00Z",
};

const GATEWAY_ACCESS = {
  mediator_did: MEDIATOR.did,
  mediator_name: MEDIATOR.name,
  dids: [
    { role: "temporary", did: TEMP_DID, mediator_did: MEDIATOR.did },
    {
      role: "permanent",
      did: ACCEPTOR_PERMANENT_DID,
      mediator_did: MEDIATOR.did,
    },
  ],
  expires_at: "2026-11-19T00:00:00Z",
};

const REFUSED_TEMP = {
  code: "mediator_access_refused",
  role: "temporary",
  did: TEMP_DID,
  mediator_did: MEDIATOR.did,
  message: "The mediator still refuses this DID.",
};

async function mockConnections(page: Page) {
  const posts: Array<{ url: string; body: unknown }> = [];
  await page.route("**/api/v1/gateways", (route) =>
    json(route, [SELF_GATEWAY, PAUSED_GATEWAY]),
  );
  await page.route("**/api/v1/connection-points", (route) => {
    if (route.request().method() === "POST") {
      posts.push({
        url: route.request().url(),
        body: route.request().postDataJSON(),
      });
      return json(route, {
        connection_point: PAUSED_CP,
        mediator_access: CP_ACCESS,
      });
    }
    return json(route, [PAUSED_CP]);
  });
  await page.route("**/api/v1/mediators", (route) => json(route, [MEDIATOR]));
  await page.route("**/api/v1/mediators/compatible", (route) =>
    json(route, [MEDIATOR]),
  );
  await page.route("**/api/v1/connection-points/cp-paused", (route) =>
    json(route, PAUSED_CP),
  );
  await page.route(
    "**/api/v1/connection-points/cp-paused/mediator-access",
    (route) => json(route, CP_ACCESS),
  );
  await page.route("**/api/v1/gateways/gw-paused", (route) =>
    json(route, PAUSED_GATEWAY),
  );
  await page.route("**/api/v1/gateways/gw-paused/mediator-access", (route) =>
    json(route, GATEWAY_ACCESS),
  );
  await page.route("**/api/v1/gateways/connect-via-oob", (route) => {
    posts.push({
      url: route.request().url(),
      body: route.request().postDataJSON(),
    });
    return json(route, {
      gateway: PAUSED_GATEWAY,
      mediator_access: GATEWAY_ACCESS,
    });
  });
  return { posts };
}

async function grantClipboard(page: Page) {
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: new URL(BASE_URL).origin,
  });
}

test.describe("Mediator access step", () => {
  test("Create Connection Point pauses on the step, copies the DIDs and leaves for later", async ({
    page,
  }) => {
    const { posts } = await mockConnections(page);
    await grantClipboard(page);
    await page.goto(`${BASE_URL}/gateways/publish`);

    await page.getByTestId("wizard-next").click();
    await page
      .getByPlaceholder("e.g., Public Gateway Invitation")
      .fill("Partner invitation");
    await page.getByTestId("wizard-next").click();

    const step = page.getByTestId("wizard-step-mediator-access");
    await expect(step).toContainText("Allow these DIDs on the mediator");
    await expect(step).toContainText("Mediator X");
    await expect(step.locator(".surface-info-panel")).toHaveCount(0);
    await expect(
      page.getByTestId("mediator-access-did-connection_point"),
    ).toContainText("Connection Point DID");
    await expect(
      page.getByTestId("mediator-access-did-permanent"),
    ).toContainText("Permanent DID for the paired gateway");
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toMatchObject({
      await_mediator_access: true,
      mediator_id: "med-x",
    });

    await page.getByTestId("mediator-access-copy-all").click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
      `${CP_DID}\n${CP_PERMANENT_DID}`,
    );

    await page.getByTestId("mediator-access-later-button").click();
    await expect(page).toHaveURL(/\/connections\?tab=gateways$/);
  });

  test("Add Gateway pauses on the same step as Create Connection Point and copies the DIDs", async ({
    page,
  }) => {
    const { posts } = await mockConnections(page);
    await grantClipboard(page);
    await page.goto(`${BASE_URL}/gateways/connect`);

    await page.getByTestId("wizard-oob-name-input").fill("Partner");
    await page.getByTestId("wizard-next").click();
    await page
      .getByTestId("wizard-oob-link-input")
      .fill("https://mediator-x.example/oob?_oobid=oob-1");
    await page.getByTestId("wizard-oob-secret-input").fill("s3cret");
    await page.getByTestId("wizard-next").click();

    const step = page.getByTestId("wizard-step-mediator-access");
    await expect(step).toContainText("Allow these DIDs on the mediator");
    await expect(step).toContainText("Mediator X");
    await expect(step.locator(".surface-info-panel")).toHaveCount(0);
    await expect(step).not.toContainText("sent the invitation");
    await expect(step).not.toContainText("The invitation expires on");
    await expect(
      page.getByTestId("mediator-access-did-temporary"),
    ).toContainText("Temporary DID for the handshake");
    await expect(
      page.getByTestId("mediator-access-did-permanent"),
    ).toContainText("Permanent DID for this pairing");
    expect(posts.at(-1)?.body).toMatchObject({
      await_mediator_access: true,
      secret: "s3cret",
    });

    await page.getByTestId("mediator-access-copy-all").click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
      `${TEMP_DID}\n${ACCEPTOR_PERMANENT_DID}`,
    );

    await page.getByTestId("mediator-access-later-button").click();
    await expect(page).toHaveURL(/\/connections\?tab=gateways$/);
  });

  test("Connections shows both pauses with Continue, and each resumes with the same DIDs", async ({
    page,
  }) => {
    await mockConnections(page);
    await page.goto(`${BASE_URL}/connections?tab=gateways`);

    await expect(page.getByTestId("gateway-status-gw-paused")).toHaveText(
      "Waiting for mediator access",
    );
    await expect(
      page.getByTestId("connection-points-status-cp-paused"),
    ).toHaveText("Waiting for mediator access");
    await expect(
      page.getByTestId("gateways-ping-button-gw-paused"),
    ).toHaveCount(0);
    await expect(
      page.getByTestId("connection-points-copy-link-button-cp-paused"),
    ).toHaveCount(0);
    await expect(
      page.getByTestId("connection-points-copy-secret-button-cp-paused"),
    ).toHaveCount(0);

    await page
      .getByTestId("connection-points-continue-button-cp-paused")
      .click();
    await expect(page).toHaveURL(/\/gateways\/publish\?resume=cp-paused$/);
    await expect(
      page.getByTestId("mediator-access-did-connection_point"),
    ).toContainText(CP_DID.slice(0, 16));

    await page.goto(`${BASE_URL}/connections?tab=gateways`);
    await page.getByTestId("gateways-continue-button-gw-paused").click();
    await expect(page).toHaveURL(/\/gateways\/connect\?resume=gw-paused$/);
    await expect(
      page.getByTestId("mediator-access-did-temporary"),
    ).toContainText(TEMP_DID.slice(0, 16));
    await expect(
      page.getByTestId("mediator-access-did-permanent"),
    ).toContainText(ACCEPTOR_PERMANENT_DID.slice(-16));
  });

  test("both Continue buttons share the per-row Edit button's style", async ({
    page,
  }) => {
    await mockConnections(page);
    await page.goto(`${BASE_URL}/connections?tab=gateways`);

    const gatewayContinue = page.getByTestId(
      "gateways-continue-button-gw-paused",
    );
    const cpContinue = page.getByTestId(
      "connection-points-continue-button-cp-paused",
    );
    const cpEdit = page.getByTestId("connection-points-edit-button-cp-paused");
    for (const button of [gatewayContinue, cpContinue, cpEdit]) {
      await expect(button).toHaveClass(/btn-outline-primary/);
      await expect(button).toHaveClass(/btn-sm/);
    }
    const colours = await Promise.all(
      [gatewayContinue, cpContinue].map((button) =>
        button.evaluate((el) => {
          const style = getComputedStyle(el);
          return `${style.color} ${style.backgroundColor} ${style.borderColor}`;
        }),
      ),
    );
    expect(colours[0]).toBe(colours[1]);
  });

  test("a pending gateway's row opens its details; a paused gateway's row does not", async ({
    page,
  }) => {
    await mockConnections(page);
    await page.route("**/api/v1/gateways", (route) =>
      json(route, [SELF_GATEWAY, PAUSED_GATEWAY, PENDING_GATEWAY]),
    );
    await page.route("**/api/v1/gateways/gw-pending", (route) =>
      json(route, PENDING_GATEWAY),
    );
    await page.route("**/api/v1/gateways/gw-pending/policy", (route) =>
      json(route, { opa_policy_config: null }),
    );
    await page.goto(`${BASE_URL}/connections?tab=gateways`);

    await expect(page.getByTestId("gateways-row-gw-paused")).toHaveCSS(
      "cursor",
      "default",
    );
    await expect(page.getByTestId("gateways-row-gw-pending")).toHaveCSS(
      "cursor",
      "pointer",
    );
    await page.getByTestId("gateways-row-gw-paused").click();
    await expect(page).toHaveURL(/\/connections\?tab=gateways$/);

    await page.getByTestId("gateways-row-gw-pending").click();
    await expect(page).toHaveURL(/\/gateways\/gw-pending$/);
    await expect(page.getByTestId("page-gateway-editor")).toContainText(
      "Edit Gateway: Partner sent",
    );
    await expect(
      page.getByTestId("gateway-editor-pending-notice"),
    ).toContainText("This connection is pending");
    await expect(page.locator("#status")).toBeDisabled();

    await page.getByTestId("gateway-editor-remote-tab-trigger").click();
    await expect(
      page.getByTestId("gateway-editor-remote-pending"),
    ).toContainText("once it accepts the connection");
    await expect(page.getByTestId("gateway-editor-delete-button")).toBeEnabled();
  });

  test("the Add Gateway wizard's View Connection opens the pending gateway's details", async ({
    page,
  }) => {
    await mockConnections(page);
    await page.route("**/api/v1/gateways/gw-paused/continue", (route) =>
      json(route, { gateway: { ...PENDING_GATEWAY, id: "gw-paused" } }),
    );
    await page.goto(`${BASE_URL}/gateways/connect?resume=gw-paused`);
    await page.getByTestId("mediator-access-continue-button").click();
    await expect(
      page.getByTestId("wizard-progress-step-complete"),
    ).toHaveAttribute("aria-current", "step");

    await page.route("**/api/v1/gateways/gw-paused", (route) =>
      json(route, { ...PENDING_GATEWAY, id: "gw-paused" }),
    );
    await page.route("**/api/v1/gateways/gw-paused/policy", (route) =>
      json(route, { opa_policy_config: null }),
    );
    await page.getByTestId("wizard-oob-view-button").click();
    await expect(page).toHaveURL(/\/gateways\/gw-paused$/);
    await expect(
      page.getByTestId("gateway-editor-pending-notice"),
    ).toBeVisible();
  });

  test("a refused DID keeps the Connection Point step; an admitted one opens the invitation", async ({
    page,
  }) => {
    await mockConnections(page);
    let refuse = true;
    await page.route(
      "**/api/v1/connection-points/cp-paused/continue",
      (route) =>
        refuse
          ? json(
              route,
              { ...REFUSED_TEMP, role: "permanent", did: CP_PERMANENT_DID },
              409,
            )
          : json(route, { connection_point: OPENED_CP }),
    );
    await page.goto(`${BASE_URL}/gateways/publish?resume=cp-paused`);

    await page.getByTestId("mediator-access-continue-button").click();
    await expect(page.getByTestId("mediator-access-refused")).toContainText(
      "Mediator Mediator X still refuses the Permanent DID for the paired gateway",
    );
    await expect(page.getByTestId("wizard-step-mediator-access")).toBeVisible();

    refuse = false;
    await page.getByTestId("mediator-access-continue-button").click();
    await expect(page.getByTestId("wizard-step-mediator-access")).toHaveCount(
      0,
    );
    await expect(
      page.locator(`input[value="${OPENED_CP.oob_url}"]`),
    ).toBeVisible();
  });

  test("a refused DID sends Add Gateway back to the step; an admitted one connects", async ({
    page,
  }) => {
    await mockConnections(page);
    let refuse = true;
    await page.route("**/api/v1/gateways/gw-paused/continue", (route) =>
      refuse
        ? json(route, REFUSED_TEMP, 409)
        : json(route, { gateway: { ...PAUSED_GATEWAY, status: "pending" } }),
    );
    await page.goto(`${BASE_URL}/gateways/connect?resume=gw-paused`);

    await page.getByTestId("mediator-access-continue-button").click();
    await expect(page.getByTestId("mediator-access-refused")).toContainText(
      "still refuses the Temporary DID for the handshake",
    );

    refuse = false;
    await page.getByTestId("mediator-access-continue-button").click();
    await expect(page.getByTestId("wizard-step-mediator-access")).toHaveCount(
      0,
    );
    await expect(
      page.getByTestId("wizard-progress-step-complete"),
    ).toHaveAttribute("aria-current", "step");
  });
});
