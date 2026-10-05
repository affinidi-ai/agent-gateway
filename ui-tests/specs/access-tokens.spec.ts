import { expect, test } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

const activeToken = {
  id: "atgat-ui-token",
  name: "UI automation",
  description: "Playwright fixture",
  user_id: "test-admin",
  scopes: ["gateways.view"],
  resource_pattern: null,
  required_headers: [],
  created_by: "test-admin",
  created_at: "2026-09-08T10:00:00Z",
  active: true,
};

async function mockAccessTokenApi(page: Page) {
  let revoked = false;
  let createRequests = 0;
  let updateRequests = 0;
  await page.route("**/api/v1/access-tokens**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (
      request.method() === "GET" &&
      url.pathname.endsWith("/atgat-ui-token")
    ) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(activeToken),
      });
      return;
    }
    if (request.method() === "GET" && url.pathname.endsWith("/access-tokens")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          access_tokens: revoked
            ? [
                {
                  ...activeToken,
                  active: false,
                  revoked_at: "2026-09-08T11:00:00Z",
                },
              ]
            : [activeToken],
        }),
      });
      return;
    }
    if (
      request.method() === "POST" &&
      url.pathname.endsWith("/access-tokens")
    ) {
      createRequests += 1;
      const body = request.postDataJSON();
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          ...activeToken,
          ...body,
          id: "agat-created",
          token: "agpat_one_time_secret",
        }),
      });
      return;
    }
    if (
      request.method() === "PUT" &&
      url.pathname.endsWith("/atgat-ui-token")
    ) {
      updateRequests += 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...activeToken,
          ...request.postDataJSON(),
        }),
      });
      return;
    }
    if (
      request.method() === "DELETE" &&
      url.pathname.endsWith("/atgat-ui-token")
    ) {
      revoked = true;
      await route.fulfill({ status: 204 });
      return;
    }
    await route.continue();
  });
  await page.route("**/api/v1/users/test-admin", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        first_name: "Ada",
        last_name: "Lovelace",
        email: "ada@example.com",
      }),
    }),
  );
  return {
    createRequests: () => createRequests,
    updateRequests: () => updateRequests,
  };
}

async function openAccessTokens(page: Page) {
  await page.goto(`${BASE_URL}/secrets?tab=access-tokens`);
  await expect(page.getByTestId("access-tokens-tab")).toBeVisible();
}

test.describe("Access Tokens tab", () => {
  test("creates a token and shows its secret once", async ({ page }) => {
    await mockAccessTokenApi(page);
    await openAccessTokens(page);

    await page.getByTestId("access-token-new-button").click();
    const name = page.getByTestId("access-token-name");
    await expect(name).toHaveAttribute("required", "");
    await expect(name).toHaveAttribute("placeholder", "e.g. external");
    await page.getByTestId("access-token-save-button").click();
    await expect(
      page.getByTestId("access-token-validation-alert"),
    ).toContainText("Please correct the highlighted fields");
    await expect(page.getByTestId("access-token-name-error")).toContainText(
      "Name is required.",
    );

    await name.fill("Deployment token");
    await page.keyboard.press("Control+s");

    await expect(page.getByTestId("access-token-created-view")).toBeVisible();
    await expect(page.getByTestId("access-token-secret")).toHaveValue(
      "agpat_one_time_secret",
    );
  });

  test("blocks ambiguous tenant-header selection", async ({ page }) => {
    const api = await mockAccessTokenApi(page);
    await openAccessTokens(page);

    await page.getByTestId("access-token-new-button").click();
    await page.getByTestId("access-token-name").fill("Scoped token");
    await page.getByTestId("access-token-resource-scope-toggle").click();
    await page
      .getByTestId("access-token-resource-pattern")
      .fill("TENANT:${account}:${region}:.*");

    await expect(page.getByTestId("access-token-preview-errors")).toBeVisible();
    await expect(page.getByTestId("access-token-save-button")).toBeEnabled();
    await page.getByTestId("access-token-save-button").click();
    expect(api.createRequests()).toBe(0);
  });

  test("uses a full-page editor with scope pills and shared collapse styling", async ({
    page,
  }) => {
    await mockAccessTokenApi(page);
    await openAccessTokens(page);

    await page.getByTestId("access-token-new-button").click();
    await expect(page).toHaveURL(/\/access-tokens\/new$/);
    await expect(page.getByTestId("page-access-token")).toBeVisible();
    await expect(page.getByTestId("access-token-about-card")).toBeVisible();
    await expect(page.getByTestId("access-token-details-card")).toBeHidden();
    await expect(page.getByTestId("access-token-description")).toHaveAttribute(
      "type",
      "text",
    );
    await expect(
      page.getByTestId("access-token-selected-scopes-label"),
    ).toContainText("Selected scopes");
    await expect(
      page.getByTestId("access-token-available-scopes-label"),
    ).toContainText("Available scopes");
    await page.getByTestId("access-token-scope-add-gateways.view").click();
    await expect(
      page.getByTestId("access-token-selected-scope-gateways.view"),
    ).toBeVisible();
    await expect(
      page.getByTestId("access-token-scope-add-gateways.view"),
    ).toBeHidden();
    await expect(
      page.getByTestId("access-token-resource-scope-content"),
    ).toBeHidden();
    await page.getByTestId("access-token-resource-scope-toggle").click();
    await expect(
      page.getByTestId("access-token-resource-scope-content"),
    ).toBeVisible();
  });

  test("tests a canonical scope with the resource-scope controls", async ({
    page,
  }) => {
    await mockAccessTokenApi(page);
    await openAccessTokens(page);

    await page.getByTestId("access-token-new-button").click();
    await page.getByTestId("access-token-resource-scope-toggle").click();
    await expect(page.getByTestId("access-token-scope-preview")).toBeHidden();
    await page.getByTestId("access-token-add-header").click();
    await page.getByTestId("access-token-header-name-0").fill("account");
    await page.getByTestId("access-token-header-pattern-0").fill("\\d");
    await page
      .getByTestId("access-token-resource-pattern")
      .fill("TENANT:${account}:gateways:.*");
    await page.getByTestId("access-token-test-header-0").fill("1234");
    await page.getByTestId("access-token-test-id").fill("gateway-1");

    await expect(
      page.getByTestId("access-token-test-header-result-0"),
    ).toContainText("no match");
    await expect(page.getByTestId("access-token-test-result")).toContainText(
      "denied",
    );

    await page.getByTestId("access-token-header-pattern-0").fill("\\d{4}");
    await expect(page.getByTestId("access-token-test-result")).toContainText(
      "allowed",
    );
    await expect(
      page.getByTestId("access-token-canonical-target"),
    ).toContainText("TENANT:1234:gateways:gateway-1");
  });

  test("shows token metadata and bound-user details while editing", async ({
    page,
  }) => {
    await mockAccessTokenApi(page);
    await openAccessTokens(page);

    await page.getByTestId("access-token-row-atgat-ui-token").click();
    await expect(page).toHaveURL(/\/access-tokens\/atgat-ui-token$/);
    await expect(page.getByTestId("access-token-details-card")).toBeVisible();
    await expect(page.getByTestId("access-token-bound-user")).toContainText(
      "Ada Lovelace",
    );
    await expect(page.getByTestId("access-token-bound-user")).toContainText(
      "ada@example.com",
    );
    await expect(page.getByTestId("access-token-bound-user")).toContainText(
      "test-admin",
    );
    await expect(page.getByTestId("access-token-about-card")).toBeVisible();
  });

  test("saves and keeps an existing token editor open with the keyboard shortcut", async ({
    page,
  }) => {
    const api = await mockAccessTokenApi(page);
    await openAccessTokens(page);

    await page.getByTestId("access-token-row-atgat-ui-token").click();
    await page.getByTestId("access-token-name").fill("Updated automation");
    await page.keyboard.press("Control+s");

    await expect.poll(api.updateRequests).toBe(1);
    await expect(page).toHaveURL(/\/access-tokens\/atgat-ui-token$/);
    await expect(page.getByTestId("page-access-token")).toBeVisible();
  });

  test("allows never or a validated future expiration", async ({ page }) => {
    await mockAccessTokenApi(page);
    await openAccessTokens(page);

    await page.getByTestId("access-token-new-button").click();
    await page.getByTestId("access-token-name").fill("Expiring token");

    const never = page.getByTestId("access-token-never-expires");
    const expiry = page.getByTestId("access-token-expiry-date-time");
    await expect(never).toBeChecked();
    await expect(expiry).toBeDisabled();
    await expect(expiry).toHaveValue("Never");

    if (!(await page.evaluate(() => document.body.classList.contains("dark-theme")))) {
      await page.getByTestId("topbar-theme-button").click();
    }
    await expect
      .poll(() => page.evaluate(() => document.body.classList.contains("dark-theme")))
      .toBe(true);
    const sharedDisabledColors = await page.evaluate(() => {
      const colors = (element: HTMLElement) => {
        document.body.appendChild(element);
        const styles = window.getComputedStyle(element);
        const result = {
          background: styles.backgroundColor,
          border: styles.borderColor,
        };
        element.remove();
        return result;
      };
      const input = document.createElement("input");
      input.className = "form-control";
      input.disabled = true;
      const select = document.createElement("select");
      select.className = "form-select";
      select.disabled = true;
      const legacySelect = document.createElement("select");
      legacySelect.className = "form-control dropdown-styling";
      legacySelect.disabled = true;
      return {
        input: colors(input),
        select: colors(select),
        legacySelect: colors(legacySelect),
      };
    });
    const disabledColors = sharedDisabledColors.input;
    expect(sharedDisabledColors.select).toEqual(disabledColors);
    expect(sharedDisabledColors.legacySelect).toEqual(disabledColors);

    const expiryColors = () =>
      expiry.evaluate((element) => {
        const styles = window.getComputedStyle(element);
        return {
          background: styles.backgroundColor,
          border: styles.borderColor,
        };
      });
    await expect.poll(expiryColors).toEqual(disabledColors);

    await never.click();
    await expect(expiry).toBeEnabled();
    await expect.poll(expiryColors).not.toEqual(disabledColors);
    const future = await page.evaluate(() => {
      const date = new Date(Date.now() + 6 * 60 * 60 * 1000);
      return new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
        .toISOString()
        .slice(0, 16);
    });
    await expiry.fill(future);
    await expect(page.getByTestId("access-token-save-button")).toBeEnabled();
  });

  test("revokes an active token after confirmation", async ({ page }) => {
    await mockAccessTokenApi(page);
    await openAccessTokens(page);

    const revoke = page.getByTestId("access-token-revoke-atgat-ui-token");
    await expect(revoke).toHaveClass(/btn-danger/);
    await revoke.click();
    await revoke.click();

    await expect(page).toHaveURL(/\/secrets\?tab=access-tokens$/);
    await expect(page.getByTestId("access-token-empty-filter")).toBeVisible();
  });
});
