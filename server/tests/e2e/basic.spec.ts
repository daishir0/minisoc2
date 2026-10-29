import { expect, test } from '@playwright/test';

const email = process.env.E2E_ADMIN_EMAIL;
const password = process.env.E2E_ADMIN_PASSWORD;

test.describe('public endpoints', () => {
  test('health', async ({ request }) => {
    const r = await request.get('/api/health');
    expect(r.status()).toBe(200);
    expect(await r.json()).toEqual({ ok: true });
  });

  test('signed agent manifest and builds are downloadable', async ({ request }) => {
    const m = await (await request.get('/agent/manifest.json')).json();
    expect(m.latest).toMatch(/^\d+\.\d+\.\d+$/);
    const entry = m.versions[m.latest];
    expect(entry.signature.length).toBeGreaterThan(40);
    expect((await request.get(`/agent/${entry.file}`)).status()).toBe(200);
    expect((await request.get('/agent/minisoc2-agent.tgz')).status()).toBe(200);
    expect((await request.get('/agent/..%2F.env')).status()).not.toBe(200);
  });

  test('agent API rejects bad credentials', async ({ request }) => {
    expect((await request.post('/api/v1/report', { data: {}, headers: { authorization: 'Bearer nope' } })).status()).toBe(401);
    expect((await request.post('/api/v1/enroll', { data: { token: 'enr_invalid' } })).status()).toBe(403);
  });

  test('console requires login', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveURL(/\/(login|setup)$/);
  });
});

test.describe('console', () => {
  test.skip(!email || !password, 'E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD not set');

  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[name=email]', email!);
    await page.fill('input[name=password]', password!);
    await page.click('button:has-text("ログイン")');
    await expect(page).toHaveURL(/\/$/);
  });

  test('dashboard, hosts and findings', async ({ page }) => {
    await expect(page.getByRole('link', { name: '対応' }).first()).toBeVisible();
    await page.goto('/hosts');
    const host = page.locator('table a').first();
    await expect(host).toBeVisible();
    await host.click();
    await expect(page.getByText('待受ポート')).toBeVisible();
    await page.goto('/findings?kev=1');
    await expect(page.locator('text=KEV').first()).toBeVisible();
  });

  test('settings save', async ({ page }) => {
    await page.goto('/settings');
    await page.locator('input[name=staleHours]').fill('26');
    await page.click('button:has-text("保存") >> nth=2');
    await expect(page.getByText('保存しました。').first()).toBeVisible();
  });

  test('watch list and enroll token', async ({ page }) => {
    await page.goto('/watch');
    await page.fill('input[name=cve]', 'CVE-2099-0001');
    await page.click('button:has-text("監視する")');
    await expect(page.getByText('CVE-2099-0001 の監視を始めました')).toBeVisible();
    await page.goto('/enroll');
    await page.fill('input[name=label]', 'e2e-test');
    await page.click('button:has-text("登録トークンを作成")');
    await expect(page.locator('pre').first()).toContainText('install --server');
  });

  test('systems page', async ({ page }) => {
    await page.goto('/systems');
    await expect(page.getByRole('heading', { name: 'システム', exact: true })).toBeVisible();
    await expect(page.getByText('OSパッケージ').first()).toBeVisible();
    await page.getByRole('link', { name: '編集' }).nth(1).click();
    await expect(page.getByText('登録内容')).toBeVisible();
    await expect(page.locator('select[name=exposure]')).toBeVisible();
    await page.goto('/systems/new');
    await expect(page.locator('input[name=root]')).toBeVisible();
  });

  test('cve lookup', async ({ page }) => {
    await page.goto('/cve');
    await page.fill('input[placeholder="CVE-2026-109618"]', 'CVE-2021-4490');
    await expect(page.getByRole('button', { name: /CVE-2021-44906/ })).toBeVisible();
    await page.getByRole('button', { name: /CVE-2021-44906/ }).click();
    await expect(page.getByText('ホストごとの判定')).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(/影響を受けるホストがあります|すべてのホストで影響はありません|判定できないホストがあります/)).toBeVisible();
  });

  test('actions inbox and task', async ({ page }) => {
    await page.goto('/actions');
    await expect(page.getByRole('heading', { name: '対応', exact: true })).toBeVisible();
    const first = page.locator('a[href^="/actions/"]').first();
    if (await first.count()) {
      await first.click();
      await expect(page.getByText('手順')).toBeVisible();
      await expect(page.locator('select[name=status]')).toBeVisible();
    }
  });

  test('every task link opens its page', async ({ page }) => {
    await page.goto('/actions');
    const hrefs = await page.locator('a[href^="/actions/"]').evaluateAll((as) => as.map((a) => a.getAttribute('href')));
    for (const href of hrefs.slice(0, 10)) {
      const res = await page.goto(href!);
      expect(res?.status(), href!).toBe(200);
      await expect(page.getByText('手順')).toBeVisible();
    }
  });

  test('system detail: impact layers and SBOM', async ({ page, request }) => {
    await page.goto('/systems');
    await page.getByRole('link', { name: '編集' }).nth(1).click();
    await expect(page.getByText('このシステムに影響する脆弱性')).toBeVisible();
    const href = await page.getByRole('link', { name: 'SBOM を出力' }).getAttribute('href');
    const res = await page.request.get(href!);
    expect(res.status()).toBe(200);
    const bom = await res.json();
    expect(bom.bomFormat).toBe('CycloneDX');
    void request;
  });

  test('header search', async ({ page }) => {
    await page.goto('/');
    await page.fill('input[aria-label=検索]', 'CVE-2021-4490');
    await expect(page.getByRole('button', { name: /CVE-2021-44906/ })).toBeVisible();
  });

  test('logs page', async ({ page }) => {
    await page.goto('/logs');
    await expect(page.getByText('日別のログ量')).toBeVisible();
    await expect(page.getByText('検知ルールに一致したログの件数', { exact: false })).toBeVisible();
    await page.fill('input[name=q]', 'sshd');
    await page.click('button:has-text("検索")');
    await expect(page).toHaveURL(/q=sshd/);
  });

  test('mobile layout', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
    expect(overflow).toBe(false);
  });
});
