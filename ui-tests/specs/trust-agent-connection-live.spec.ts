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

/**
 * Drives the Trust Agent page against a real trust agent, in two runs because
 * the trust agent's access list is written offline, between them:
 *
 * - `VTA_LIVE_PHASE=add` creates a connection through the same API the wizard
 *   uses and saves what pairing printed.
 * - `VTA_LIVE_PHASE=rotate` verifies the grant, then clicks Rotate control key.
 *
 * Needs `VTA_LIVE_URL`, `VTA_LIVE_DID`, `VTA_LIVE_STATE_FILE` and optionally
 * `VTA_LIVE_CONTEXT`; skipped without them. The trust agent must be able to
 * reach the gateway's `/vta-auth/<id>/did.jsonl`, which locally means the
 * gateway's DID names its plain-HTTP port.
 */
test.describe("Trust Agent page against a real trust agent", () => {
  test.skip(
    !configured,
    "set VTA_LIVE_URL, VTA_LIVE_DID and VTA_LIVE_STATE_FILE to run",
  );

  test("a new connection is paired for one context under the initiator role, never admin", async ({
    page,
  }) => {
    test.skip(PHASE !== "add", "VTA_LIVE_PHASE is not add");
    await page.goto(`${BASE_URL}/trust-agent`);
    await expect(page.getByText("Connections").first()).toBeVisible();

    const created = await api(page, "/api/v1/vta/connections", {
      method: "POST",
      body: {
        name: NAME,
        endpoint: VTA_URL,
        vta_did: VTA_DID,
        default_context_id: CONTEXT,
        transport: "https",
        enabled: true,
      },
    });
    expect(created.status, JSON.stringify(created.json)).toBe(201);
    const id = created.json.id as string;

    const pairing = await api(page, `/api/v1/vta/connections/${id}/pair`, {
      method: "POST",
    });
    expect(pairing.status, JSON.stringify(pairing.json)).toBe(200);
    const payload = pairing.json;

    expect(payload.control_did).toMatch(/^did:webvh:/);
    expect(payload.requested_role).toBe("initiator");
    expect(payload.grant_command).toContain(`--contexts ${CONTEXT}`);
    expect(payload.grant_command).toContain("--role initiator");
    expect(payload.grant_command).not.toContain("admin");

    await page.reload();
    await expect(page.locator("tr", { hasText: NAME })).toBeVisible();

    fs.writeFileSync(
      STATE_FILE!,
      JSON.stringify({
        id,
        control_did: payload.control_did,
        grant_command: payload.grant_command,
      }),
    );
  });

  test("Rotate control key moves the connection to a new key under the same DID and the same grant", async ({
    page,
  }) => {
    test.skip(PHASE !== "rotate", "VTA_LIVE_PHASE is not rotate");
    test.setTimeout(240_000);
    const state = JSON.parse(fs.readFileSync(STATE_FILE!, "utf8"));

    await page.goto(`${BASE_URL}/trust-agent`);
    const row = page.locator("tr", { hasText: NAME });
    await expect(row).toBeVisible();

    await row.getByRole("button", { name: "Verify" }).click();
    await expect(row.getByRole("button", { name: "Verify" })).toBeVisible();
    await expect
      .poll(
        async () =>
          (await api(page, `/api/v1/vta/connections`)).json.find(
            (c: any) => c.id === state.id,
          )?.status,
      )
      .toBe("connected");

    const before = (await api(page, "/api/v1/vta/connections")).json.find(
      (c: any) => c.id === state.id,
    );
    expect(before.pairing.granted_role).toBe("initiator");
    expect(before.pairing.granted_contexts).toEqual([CONTEXT]);
    expect(before.control_did).toBe(state.control_did);
    const firstKey = before.control_key_state?.verification_method;
    await expect(row.getByTestId("vta-row-control-key")).toBeVisible();

    await row.getByTestId("vta-row-rotate-control-key").click();
    await page.getByTestId("vta-row-rotate-confirm").click();

    await expect
      .poll(
        async () =>
          (await api(page, "/api/v1/vta/connections")).json.find(
            (c: any) => c.id === state.id,
          )?.control_key_state?.verification_method,
        { timeout: 200_000, intervals: [2_000] },
      )
      .not.toBe(firstKey);
    await expect(
      row.getByTestId("vta-row-control-key-rotated-at"),
    ).toBeVisible();
    await expect(row.getByTestId("vta-row-rotation-error")).toHaveCount(0);

    const after = (await api(page, "/api/v1/vta/connections")).json.find(
      (c: any) => c.id === state.id,
    );
    expect(
      after.control_did,
      "the DID, and so the grant, does not change",
    ).toBe(state.control_did);
    expect(after.status).toBe("connected");
    expect(after.control_key_state?.rotation).toBeUndefined();
    expect(after.pairing.granted_role).toBe("initiator");
    expect(after.pairing.granted_contexts).toEqual([CONTEXT]);

    const minted = await api(page, `/api/v1/vta/connections/${state.id}/keys`, {
      method: "POST",
    });
    expect(
      minted.status,
      `the new key signs in and the grant still mints a key: ${JSON.stringify(minted.json)}`,
    ).toBeLessThan(300);
    expect(
      minted.json.keys?.active,
      "a signing key now exists in the context",
    ).toBeTruthy();
  });
});
