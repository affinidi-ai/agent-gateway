/**
 * Wait Utilities
 *
 * Custom wait functions for common UI testing scenarios.
 */

import {expect, Locator, Page} from '@playwright/test';

/**
 * Wait for network to be idle with a custom timeout
 */
export async function waitForNetworkIdle(
    page: Page,
    timeout: number = 30000
): Promise<void> {
    await page.waitForLoadState('networkidle', {timeout});
}

/**
 * Wait for an element to become visible
 */
export async function waitForVisible(
    page: Page,
    selector: string,
    timeout: number = 10000
): Promise<Locator> {
    const locator = page.locator(selector).first();
    await expect(locator).toBeVisible({timeout});
    return locator;
}

/**
 * Wait for an element to disappear
 */
export async function waitForHidden(
    page: Page,
    selector: string,
    timeout: number = 10000
): Promise<void> {
    const locator = page.locator(selector);
    await expect(locator).toBeHidden({timeout});
}

/**
 * Wait for text to appear on the page
 */
export async function waitForText(
    page: Page,
    text: string,
    timeout: number = 10000
): Promise<Locator> {
    const locator = page.locator(`text=${text}`).first();
    await expect(locator).toBeVisible({timeout});
    return locator;
}

/**
 * Wait for a specific URL pattern
 */
export async function waitForUrl(
    page: Page,
    urlPattern: string | RegExp,
    timeout: number = 10000
): Promise<void> {
    await expect(page).toHaveURL(urlPattern, {timeout});
}

/**
 * Wait for API response
 */
export async function waitForApiResponse(
    page: Page,
    urlPattern: string | RegExp,
    timeout: number = 30000
): Promise<any> {
    const response = await page.waitForResponse(
        (response) => {
            const url = response.url();
            if (typeof urlPattern === 'string') {
                return url.includes(urlPattern);
            }
            return urlPattern.test(url);
        },
        {timeout}
    );

    return response;
}

/**
 * Wait for a loading indicator to disappear
 */
export async function waitForLoadingComplete(
    page: Page,
    timeout: number = 30000
): Promise<void> {
    // Common loading indicator selectors
    const loadingSelectors = [
        '.loading',
        '.spinner',
        '.loader',
        '[data-loading="true"]',
        '[aria-busy="true"]',
        '.skeleton',
        '.shimmer',
    ];

    for (const selector of loadingSelectors) {
        const locator = page.locator(selector);
        const count = await locator.count();

        if (count > 0) {
            await expect(locator.first()).toBeHidden({timeout});
        }
    }
}

/**
 * Wait for animations to complete
 */
export async function waitForAnimations(
    page: Page,
    timeout: number = 5000
): Promise<void> {
    await page.waitForFunction(
        () => {
            const animations = document.getAnimations();
            return animations.every((animation) => animation.playState === 'finished');
        },
        {timeout}
    );
}

/**
 * Wait for element to be stable (not moving/changing)
 */
export async function waitForStable(
    locator: Locator,
    timeout: number = 5000
): Promise<void> {
    let previousBox = await locator.boundingBox();

    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
        await locator.page().waitForTimeout(100);
        const currentBox = await locator.boundingBox();

        if (
            previousBox &&
            currentBox &&
            previousBox.x === currentBox.x &&
            previousBox.y === currentBox.y &&
            previousBox.width === currentBox.width &&
            previousBox.height === currentBox.height
        ) {
            return;
        }

        previousBox = currentBox;
    }

    throw new Error(`Element did not stabilize within ${timeout}ms`);
}

/**
 * Retry an action until it succeeds or times out
 */
export async function retryUntilSuccess<T>(
    action: () => Promise<T>,
    maxRetries: number = 3,
    delayMs: number = 1000
): Promise<T> {
    let lastError: Error | null = null;

    for (let i = 0; i < maxRetries; i++) {
        try {
            return await action();
        } catch (error) {
            lastError = error as Error;
            console.log(`Retry ${i + 1}/${maxRetries} failed: ${lastError.message}`);

            if (i < maxRetries - 1) {
                await new Promise((resolve) => setTimeout(resolve, delayMs));
            }
        }
    }

    throw lastError || new Error('Action failed after retries');
}

/**
 * Wait for a condition to become true
 */
export async function waitForCondition(
    page: Page,
    condition: () => Promise<boolean>,
    timeout: number = 10000,
    pollInterval: number = 100
): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
        if (await condition()) {
            return;
        }
        await page.waitForTimeout(pollInterval);
    }

    throw new Error(`Condition not met within ${timeout}ms`);
}
