/**
 * Ticket annotations and acceptance screenshots for the test report.
 *
 * `ticket(...ids)` adds one `ticket` annotation per id to the running test, so
 * the HTML and JSON reports list the tickets a test proves. Call it at the start
 * of a test or in a `beforeEach`.
 *
 * `attachCriterion(id, criterion, title, target)` attaches a screenshot to the
 * running test as `<id> criterion <n>: <title>`: of the element when `target`
 * is a locator, or the PNG given. Take it of the area under test only, never of
 * a page that can show secret material.
 */

import {test, type Locator} from '@playwright/test';

export function ticket(...ids: string[]): void {
    const info = test.info();
    for (const id of ids) {
        info.annotations.push({type: 'ticket', description: id});
    }
}

export async function attachCriterion(
    id: string,
    criterion: number,
    title: string,
    target: Locator | Buffer
): Promise<void> {
    const body = Buffer.isBuffer(target) ? target : await target.screenshot();
    await test.info().attach(`${id} criterion ${criterion}: ${title}`, {body, contentType: 'image/png'});
}
