import { expect, test } from "../helpers/fixtures";
import type { Page, Route } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const record = (id: string, name: string, surface: string) => ({
  id,
  name,
  protocol: "a2a",
  runtime: "url",
  endpoint: `https://${id}.agents.example.com/a2a`,
  tags: [],
  surfaces: [{ surface_id: `${surface}-id`, name: surface }],
  identities: [],
  trust_registry: { recorded: false },
  last_activity_at: null,
});

const timeAsker = record("ui-agent-a1", "TimeAsker", "rick");
const oxygen = record("ui-agent-b1", "Oxygen", "morty");

const details = (agent: ReturnType<typeof record>) => ({
  ...agent,
  surfaces: agent.surfaces.map((surface) => ({
    ...surface,
    protocol: "a2a",
    route: `/${surface.name}`,
  })),
  target_name: null,
  traffic: {
    window_minutes: 360,
    total_requests: 0,
    failed: 0,
    gateway_faults: 0,
    p95_latency_ms: null,
  },
});

type CardAnswer = { status: number; json: unknown };

const cardOf = (name: string): CardAnswer => ({
  status: 200,
  json: { available: true, card: { name, skills: [] }, source: "fetched" },
});

/**
 * Answers the Agents API from fixtures; every other request reaches the gateway. `card` may
 * depend on the `surface_id` the card is read through.
 */
async function serveAgents(
  page: Page,
  {
    list = 200,
    agents = [timeAsker, oxygen],
    card,
  }: {
    list?: number;
    agents?: ReturnType<typeof record>[];
    card?: CardAnswer | ((surfaceId: string | null) => CardAnswer);
  } = {},
) {
  await page.route(/\/api\/v1\/agents(\/[^?]*)?(\?.*)?$/, async (route: Route) => {
    const url = new URL(route.request().url());
    const [, id, tail] =
      url.pathname.match(/\/api\/v1\/agents(?:\/([^/]+))?(\/agent-card)?$/) ?? [];
    if (!id) {
      await route.fulfill(
        list === 200
          ? { json: { agents, window_minutes: 360 } }
          : { status: list, json: { error: "Internal Server Error" } },
      );
      return;
    }
    const agent = agents.find((a) => a.id === decodeURIComponent(id));
    if (!agent) {
      await route.fulfill({ status: 404, json: { error: "Not Found" } });
      return;
    }
    if (tail) {
      const answer =
        typeof card === "function"
          ? card(url.searchParams.get("surface_id"))
          : (card ?? cardOf(agent.name));
      await route.fulfill({ status: answer.status, json: answer.json });
      return;
    }
    await route.fulfill({ json: details(agent) });
  });
}

async function openAgents(page: Page) {
  await page.goto(`${BASE_URL}/agent-registry`);
  await expect(page.getByTestId("page-agents")).toBeVisible();
}

test.describe("Agents page", () => {
  test("opens an agent's details from the list", async ({ page }) => {
    await serveAgents(page);
    await openAgents(page);

    await expect(page.getByTestId("agents-count")).toHaveText("2");
    await page.getByTestId(`agents-row-${timeAsker.id}`).click();

    await expect(page).toHaveURL(new RegExp(`/agent-registry/${timeAsker.id}$`));
    await expect(page.getByTestId("agent-details-name")).toHaveText("TimeAsker");
    await expect(page.getByTestId("agent-tab-agent-card")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.getByTestId("agent-card-preview-name")).toHaveText(
      "TimeAsker",
    );
    await expect(page.getByTestId("agent-card-source")).toHaveAttribute(
      "data-source",
      "fetched",
    );

    await page.getByTestId("agent-back-button").click();
    await expect(page.getByTestId("page-agents")).toBeVisible();
  });

  test("filters the list by agent and surface name", async ({ page }) => {
    await serveAgents(page);
    await openAgents(page);
    const filter = page.getByTestId("agents-filter-input");

    await filter.fill("morty");
    await expect(page.getByTestId(`agents-row-${oxygen.id}`)).toBeVisible();
    await expect(page.getByTestId(`agents-row-${timeAsker.id}`)).toHaveCount(0);
    await expect(page.getByTestId("agents-count")).toHaveText("1 of 2");

    await filter.fill("no such agent");
    await expect(page.getByTestId("agents-no-match")).toBeVisible();
  });

  test("shows a list read failure with Retry", async ({ page }) => {
    await serveAgents(page, { list: 500 });
    await openAgents(page);

    await expect(page.getByTestId("agents-load-error")).toBeVisible();
    await expect(page.getByTestId("agents-retry-button")).toBeVisible();
  });

  test("opens the surface creation flow from the empty list", async ({ page }) => {
    await serveAgents(page, { agents: [] });
    await openAgents(page);

    await page.getByTestId("agents-add-surface-button").click();

    await expect(page).toHaveURL(/\/surfaces\/new$/);
  });

  test("keeps the surface picker when the card can't be read through the picked surface", async ({
    page,
  }) => {
    const twoSurfaces = {
      ...timeAsker,
      surfaces: [
        { surface_id: "helium-id", name: "helium" },
        { surface_id: "oxygen-id", name: "oxygen" },
      ],
    };
    await serveAgents(page, {
      agents: [twoSurfaces],
      card: (surfaceId) =>
        surfaceId === "oxygen-id"
          ? { status: 404, json: { error: "Not Found" } }
          : {
              status: 200,
              json: {
                ...(cardOf("TimeAsker").json as object),
                surface_id: "helium-id",
                card_surface_ids: ["helium-id", "oxygen-id"],
              },
            },
    });
    await page.goto(`${BASE_URL}/agent-registry/${timeAsker.id}`);
    await expect(page.getByTestId("agent-card-preview-name")).toHaveText(
      "TimeAsker",
    );

    await page.getByTestId("agent-card-surface-select").click();
    await page.getByRole("option", { name: /oxygen/ }).click();

    await expect(page.getByTestId("agent-card-surface-unavailable")).toBeVisible();
    await expect(page.getByTestId("agent-card-error")).toHaveCount(0);
    await expect(page.getByTestId("agent-card-surface-select")).toContainText(
      "oxygen",
    );
  });

  test("shows a failed Agent Card read with Retry", async ({ page }) => {
    await serveAgents(page, {
      card: { status: 502, json: { error: "Bad Gateway" } },
    });
    await page.goto(`${BASE_URL}/agent-registry/${timeAsker.id}`);

    await expect(page.getByTestId("agent-card-error")).toBeVisible();
    await expect(page.getByTestId("agent-card-retry-button")).toBeVisible();
    await expect(page.getByTestId("agent-card-preview-name")).toHaveCount(0);
  });

  test("shows a card refused to a tenant as operator only", async ({ page }) => {
    await serveAgents(page, {
      card: { status: 200, json: { available: false, reason: "operator_only" } },
    });
    await page.goto(`${BASE_URL}/agent-registry/${timeAsker.id}`);

    await expect(page.getByTestId("agent-card-operator_only")).toBeVisible();
    await expect(page.getByTestId("agent-card-preview-name")).toHaveCount(0);
  });

  test("shows not found for an agent outside the caller's scope", async ({
    page,
  }) => {
    await serveAgents(page);
    await page.goto(`${BASE_URL}/agent-registry/ui-agent-unknown`);

    await expect(page.getByTestId("agent-not-found")).toBeVisible();
  });

  test("is hidden and not served without surfaces.view", async ({ page }) => {
    let agentsRequested = false;
    await page.route("**/api/v1/permissions", async (route) => {
      const response = await route.fetch();
      const permissions = await response.json();
      await route.fulfill({
        response,
        json: { ...permissions, "surfaces.view": false },
      });
    });
    await page.route(/\/api\/v1\/agents/, async (route) => {
      agentsRequested = true;
      await route.abort();
    });

    await page.goto(`${BASE_URL}/agent-registry`);

    await expect(page.getByTestId("page-dashboard")).toBeVisible();
    await expect(page.getByTestId("nav-agents")).toHaveCount(0);
    await expect(page.getByTestId("page-agents")).toHaveCount(0);
    expect(agentsRequested).toBe(false);
  });
});
