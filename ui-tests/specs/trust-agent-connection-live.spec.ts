import fs from "fs";

import type { Page } from "@playwright/test";

import { expect, test } from "../helpers/fixtures";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";
const VTA_URL = process.env.VTA_LIVE_URL;
const VTA_DID = process.env.VTA_LIVE_DID;
const CONTEXT = process.env.VTA_LIVE_CONTEXT || "gwlive";
const STATE_FILE = process.env.VTA_LIVE_STATE_FILE;
const PHASE = process.env.VTA_LIVE_PHASE;
const NAME = "Live VTA";

const configured = Boolean(VTA_URL && VTA_DID && STATE_FILE);

async function api(
  page: Page,
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<{ status: number; json: any }> {
  return page.evaluate(
    async ([p, i]) => {
      const token = sessionStorage.getItem("session_token");
      const response = await fetch(p as string, {
        method: (i as any).method ?? "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body:
          (i as any).body === undefined
            ? undefined
            : JSON.stringify((i as any).body),
      });
      const text = await response.text();
      let json: unknown = null;
      try {
        json = JSON.parse(text);
      } catch {
        json = text;
      }
      return { status: response.status, json };
    },
    [path, init] as const,
  );
}

const connectionNamed = async (page: Page) =>
  (await api(page, "/api/v1/vta/connections")).json.find(
    (c: any) => c.name === NAME,
  );

/**
 * Drives the dashboard against a real trust agent, in two runs because the trust agent's access
 * list is written offline between them:
 *
 * - `VTA_LIVE_PHASE=add` fills in the connect wizard, creates and pairs the connection, and saves
 *   the grant command the wizard shows.
 * - `VTA_LIVE_PHASE=rotate` resumes the wizard to verify the grant, completes it, clicks Rotate
 *   control key on the connection's row, and sets an issuer to sign through the agent.
 *
 * Needs `VTA_LIVE_URL`, `VTA_LIVE_DID`, `VTA_LIVE_STATE_FILE` and optionally
 * `VTA_LIVE_CONTEXT`; skipped without them. The trust agent must be able to
 * reach the gateway's `/vta-auth/<id>/did.jsonl`, which locally means the
 * gateway's DID names its plain-HTTP port.
 */
test.describe("Connections against a real trust agent", () => {
  test.skip(
    !configured,
    "set VTA_LIVE_URL, VTA_LIVE_DID and VTA_LIVE_STATE_FILE to run",
  );

  test("the connect wizard pairs a new connection for one context under the initiator role, never admin", async ({
    page,
  }) => {
    test.skip(PHASE !== "add", "VTA_LIVE_PHASE is not add");
    await page.goto(`${BASE_URL}/connections?tab=trust-agents`);
    await page.getByTestId("trust-agents-connect-button").click();
    await expect(page.getByTestId("wizard-add-trust-agent")).toBeVisible();

    await page.getByTestId("wizard-trust-agent-name-input").fill(NAME);
    await page.getByTestId("wizard-trust-agent-endpoint-input").fill(VTA_URL!);
    await page.getByTestId("wizard-trust-agent-did-input").fill(VTA_DID!);
    await page.getByTestId("wizard-trust-agent-context-input").fill(CONTEXT);
    await page.getByTestId("wizard-next").click();

    await expect(page.getByTestId("wizard-step-grant")).toBeVisible();
    const command = (
      await page
        .getByTestId("wizard-step-grant")
        .locator("pre code")
        .innerText()
    ).trim();
    expect(command).toContain("vta acl create");
    expect(command).toContain("--role initiator");
    expect(command).toContain(`--contexts ${CONTEXT}`);
    expect(command).not.toContain("admin");

    const created = await connectionNamed(page);
    expect(created.control_did).toMatch(/^did:webvh:/);
    fs.writeFileSync(
      STATE_FILE!,
      JSON.stringify({
        id: created.id,
        control_did: created.control_did,
        grant_command: command,
      }),
    );
  });

  test("the wizard verifies the grant and completes, Rotate control key moves the key under the same DID and grant, and an issuer signs through the agent", async ({
    page,
  }) => {
    test.skip(PHASE !== "rotate", "VTA_LIVE_PHASE is not rotate");
    test.setTimeout(300_000);
    const state = JSON.parse(fs.readFileSync(STATE_FILE!, "utf8"));
    const find = async () =>
      (await api(page, "/api/v1/vta/connections")).json.find(
        (c: any) => c.id === state.id,
      );

    // The wizard, resumed: the grant step, then Verify, then Complete (which mints the signing key).
    await page.goto(
      `${BASE_URL}/connections/trust-agents/connect?id=${encodeURIComponent(state.id)}`,
    );
    await expect(page.getByTestId("wizard-step-grant")).toBeVisible();
    await page.getByTestId("wizard-next").click();
    await expect(page.getByTestId("wizard-step-complete")).toBeVisible({
      timeout: 120_000,
    });
    await expect
      .poll(async () => (await find())?.keys?.active?.key_id, {
        timeout: 120_000,
      })
      .toBeTruthy();
    // The box is pre-checked only while no gateway-wide default is stored, so
    // the operator ticks it to make this agent the default.
    await page.locator("#vta-wizard-make-default").check();
    await page.getByTestId("wizard-submit").click();
    await expect(page).toHaveURL(/\/connections\?tab=trust-agents/);

    const before = await find();
    expect(before.status).toBe("connected");
    expect(before.pairing.granted_role).toBe("initiator");
    expect(before.pairing.granted_contexts).toEqual([CONTEXT]);
    expect(before.control_did).toBe(state.control_did);
    const firstKey = before.control_key_state?.verification_method;

    // The Trust Agents tab: rotate the control key from the row.
    const row = page.locator("tr", { hasText: NAME });
    await expect(row.getByTestId("vta-row-control-key")).toBeVisible();
    await row.getByTestId("vta-row-rotate-control-key").click();
    await page.getByTestId("vta-row-rotate-confirm").click();
    await expect
      .poll(
        async () => (await find())?.control_key_state?.verification_method,
        {
          timeout: 200_000,
          intervals: [2_000],
        },
      )
      .not.toBe(firstKey);
    await expect(
      row.getByTestId("vta-row-control-key-rotated-at"),
    ).toBeVisible();
    await expect(row.getByTestId("vta-row-rotation-error")).toHaveCount(0);

    const after = await find();
    expect(
      after.control_did,
      "the DID, and so the grant, does not change",
    ).toBe(state.control_did);
    expect(after.status).toBe("connected");
    expect(after.control_key_state?.rotation).toBeUndefined();
    expect(after.pairing.granted_role).toBe("initiator");
    expect(after.pairing.granted_contexts).toEqual([CONTEXT]);
    expect(after.keys?.active?.key_id).toBeTruthy();

    // Gateway signing shows the agent as the gateway-wide default once the wizard's
    // "use for all signing" was applied.
    await page.goto(`${BASE_URL}/settings`);
    await page.getByTestId("settings-security-tab-trigger").click();
    const gatewaySigning = page.getByTestId("gateway-signing-settings");
    await expect(
      gatewaySigning.getByTestId("surface-signing-type-select"),
    ).toHaveValue("remote");
    await expect(
      gatewaySigning.getByTestId("surface-signing-agent-select"),
    ).toHaveValue(state.id);

    // An issuer takes the agent to sign for its surfaces, from the issuer editor.
    await page.goto(`${BASE_URL}/identities?tab=issuers`);
    await page.getByTestId("issuers-add-button").click();
    // Named for this run's connection: issuers outlive a run of the live harness.
    const issuerName = `Live issuer ${state.id.slice(0, 8)}`;
    await page.locator("#issuer-name").fill(issuerName);
    await page
      .locator("#issuer-description")
      .fill("Signs through the live agent");
    await page
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");
    await page
      .getByTestId("surface-signing-agent-select")
      .selectOption(state.id);
    await page.getByTestId("issuer-editor-save-button").click();

    await expect(page.getByText(issuerName)).toBeVisible();
    const issuers = (await api(page, "/api/v1/issuers")).json;
    const issuer = issuers.find((i: any) => i.name === issuerName);
    expect(issuer.signing).toMatchObject({
      backend: "vta",
      connection_id: state.id,
      context_id: CONTEXT,
    });
    await expect(page.getByTestId(`issuers-signing-${issuer.id}`)).toHaveText(
      `VTA · ${NAME}`,
    );
  });
});
