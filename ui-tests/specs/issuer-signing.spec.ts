/**
 * Identity → Issuers: the Signing column and the signing choice in the issuer editor.
 *
 * The issuer and trust agent calls are served by `page.route` mocks. Every control is located by
 * test id.
 */

import type { Route } from "@playwright/test";
import { expect, test } from "../helpers/fixtures";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

const issuer = (
  id: string,
  name: string,
  signing?: Record<string, string>,
) => ({
  id,
  name,
  description: `${name} team`,
  did: `did:webvh:abc:localhost%3A8080:issuers:${id}`,
  ...(signing ? { signing } : {}),
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
});

const AGENT = {
  id: "agent-1",
  name: "Production agent",
  enabled: true,
  transport: "https",
  endpoint: "https://vta.example.com",
  vta_did: "did:webvh:abc:vta.example.com",
  default_context_id: "gateway",
  status: "connected",
  pairing: { state: "connected" },
  keys: { active: { key_id: "key-1" } },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const ISSUERS = [
  issuer("inherit", "Follows default"),
  issuer("local", "Own key", { backend: "local" }),
  issuer("remote", "Through agent", {
    backend: "vta",
    connection_id: "agent-1",
    context_id: "gateway",
    key_id: "key-1",
  }),
];

test.describe("Issuer signing", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      json(route, [AGENT]),
    );
    await page.route(/\/api\/v1\/vta\/status(\?.*)?$/, (route) =>
      json(route, {
        enabled: false,
        tier: "local",
        custody_claim: false,
        default_resolution: {
          backend: "local",
          reason: "test",
          explicit: false,
        },
      }),
    );
    await page.route(/\/api\/v1\/issuers(\?.*)?$/, (route) =>
      route.request().method() === "GET"
        ? json(route, ISSUERS)
        : route.fallback(),
    );
  });

  test("the Issuers list shows what signs for each issuer", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/identities?tab=issuers`);

    await expect(page.getByTestId("issuers-signing-inherit")).toHaveText(
      "Default",
    );
    await expect(page.getByTestId("issuers-signing-local")).toHaveText(
      "Gateway secret",
    );
    await expect(page.getByTestId("issuers-signing-remote")).toHaveText(
      "VTA · Production agent",
    );
  });

  test("the editor shows the choice, saves a change and hands one back", async ({
    page,
  }) => {
    const puts: Array<Record<string, unknown>> = [];
    await page.route(/\/api\/v1\/issuers\/remote$/, (route) => {
      if (route.request().method() === "PUT") {
        puts.push(route.request().postDataJSON());
        return json(route, ISSUERS[2]);
      }
      return json(route, ISSUERS[2]);
    });
    await page.goto(`${BASE_URL}/identities?tab=issuers`);
    await page.getByTestId("issuers-edit-button-remote").click();

    await expect(page.getByTestId("issuer-signing")).toBeVisible();
    const type = page.getByTestId("surface-signing-type-select");
    await expect(type).toHaveValue("remote");
    await expect(page.getByTestId("surface-signing-agent-select")).toHaveValue(
      "agent-1",
    );

    await type.selectOption("local");
    await page.getByTestId("issuer-editor-save-button").click();
    await expect.poll(() => puts.length).toBe(1);
    expect(puts[0].signing).toEqual({ backend: "local" });
  });

  test("handing the choice back sends an empty block", async ({ page }) => {
    const puts: Array<Record<string, unknown>> = [];
    await page.route(/\/api\/v1\/issuers\/local$/, (route) => {
      if (route.request().method() === "PUT") {
        puts.push(route.request().postDataJSON());
      }
      return json(route, ISSUERS[1]);
    });
    await page.goto(`${BASE_URL}/identities?tab=issuers`);
    await page.getByTestId("issuers-edit-button-local").click();

    await page.getByTestId("surface-signing-reset").click();
    await page.getByTestId("issuer-editor-save-button").click();

    await expect.poll(() => puts.length).toBe(1);
    expect(puts[0].signing).toEqual({});
  });

  test("the editor shows no agent list while no Verifiable Trust Agent is connected", async ({
    page,
  }) => {
    await page.route(/\/api\/v1\/vta\/connections(\?.*)?$/, (route) =>
      json(route, []),
    );
    await page.route(/\/api\/v1\/issuers\/local$/, (route) =>
      json(route, ISSUERS[1]),
    );
    await page.goto(`${BASE_URL}/identities?tab=issuers`);
    await page.getByTestId("issuers-edit-button-local").click();

    await page
      .getByTestId("surface-signing-type-select")
      .selectOption("remote");

    await expect(page.getByTestId("surface-signing-no-agents")).toHaveText(
      "No Verifiable Trust Agent is connected yet.",
    );
    await expect(page.getByTestId("surface-signing-agent-select")).toHaveCount(
      0,
    );
    await expect(
      page.getByTestId("surface-signing-connect-link"),
    ).toBeVisible();
  });
});
