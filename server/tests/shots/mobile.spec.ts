// Screenshot every console page at phone size (not part of the regular suite: npx playwright test tests/shots).
import { devices, expect, test } from '@playwright/test';

test.use({ ...devices['iPhone 13'], browserName: 'chromium' });

const email = process.env.E2E_ADMIN_EMAIL!;
const password = process.env.E2E_ADMIN_PASSWORD!;
const out = process.env.SHOT_DIR ?? 'test-results/shots';

test('mobile screenshots', async ({ page }) => {
  await page.goto('/login');
  await page.screenshot({ path: `${out}/01-login.png`, fullPage: true });
  await page.fill('input[name=email]', email);
  await page.fill('input[name=password]', password);
  await page.click('button:has-text("ログイン")');
  await expect(page).toHaveURL(/\/$/);
  const hostHref = await (async () => {
    await page.goto('/hosts');
    return page.locator('table a').first().getAttribute('href');
  })();
  const taskHref = await (async () => { await page.goto('/actions'); return page.locator('a[href^="/actions/"]').first().getAttribute('href'); })();
  const sysHref = await (async () => { await page.goto('/systems'); return page.locator('a[href^="/systems/"]:has-text("album")').first().getAttribute('href'); })();
  const pages: [string, string][] = [
    ['00d-system-album', sysHref ?? '/systems'],
    ['00-actions', '/actions'], ['00b-task', taskHref ?? '/actions'], ['00c-explore', '/explore'],
    ['02-dashboard', '/'], ['02b-changes', '/changes?all=1'], ['03-hosts', '/hosts'], ['03b-systems', '/systems'], ['03c-system-new', '/systems/new'], ['04-host', hostHref ?? '/hosts'], ['05-findings', '/findings'],
    ['06-findings-kev', '/findings?kev=1'], ['07-alerts', '/alerts'], ['08-logs', '/logs'], ['09-watch', '/watch'],
    ['10-enroll', '/enroll'], ['11-settings', '/settings'], ['14-cve', '/cve/CVE-2026-109618'],
  ];
  const report: string[] = [];
  for (const [name, path] of pages) {
    await page.goto(path);
    await page.waitForLoadState('networkidle');
    const wide = await page.evaluate(() => {
      const w = window.innerWidth;
      return [...document.querySelectorAll('body *')]
        .filter((el) => el.getBoundingClientRect().right > w + 1 && !el.closest('.overflow-x-auto'))
        .slice(0, 5).map((el) => `${el.tagName.toLowerCase()}.${String((el as HTMLElement).className).slice(0, 60)}`);
    });
    report.push(`${name}: scrollWidth=${await page.evaluate(() => document.documentElement.scrollWidth)} overflow=${JSON.stringify(wide)}`);
    const h = await page.evaluate(() => document.documentElement.scrollHeight);
    await page.screenshot({ path: `${out}/${name}.png`, fullPage: h < 6000 });
  }
  await page.goto('/');
  await page.click('summary[aria-label=設定とアカウント]');
  await page.screenshot({ path: `${out}/13-menu.png` });
  await page.goto('/enroll');
  await page.fill('input[name=label]', 'e2e-test');
  await page.click('button:has-text("登録トークンを作成")');
  await page.waitForSelector('pre');
  await page.screenshot({ path: `${out}/12-enroll-token.png`, fullPage: true });
  console.log(report.join('\n'));
});
