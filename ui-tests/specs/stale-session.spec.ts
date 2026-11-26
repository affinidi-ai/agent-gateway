import { expect, test } from "@playwright/test";

const BASE_URL = process.env.AG_BASE_URL || "http://localhost:8080";

test.use({ storageState: { cookies: [], origins: [] } });

test.describe("a session token left in the browser that the gateway no longer knows", () => {
  test("lands on the sign-in page and stays there", async ({ page }) => {
    await page.addInitScript(() => {
      try {
        sessionStorage.setItem(
          "session_token",
          "left-over-from-an-earlier-gateway",
        );
      } catch {
        // ignore
      }
    });
    let navigations = 0;
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) navigations += 1;
    });

    await page.goto(`${BASE_URL}/dashboard`);

    await expect(page.getByTestId("login-username")).toBeVisible();
    await page.waitForTimeout(3000);
    expect(navigations).toBeLessThan(6);
    await expect(page.getByTestId("login-username")).toBeVisible();
    expect(
      await page.evaluate(() => sessionStorage.getItem("session_token")),
    ).toBeNull();
  });
});
