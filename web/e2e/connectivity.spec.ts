import { test, expect } from '@playwright/test';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Page } from '@playwright/test';

// These browser-only fixtures exercise observation freshness. They never apply
// a policy, start a firewall, use the operator key or claim real Linux results.
function fixture() {
  return {
    system: {
      name: 'WireWall', version: '0.1.0', backend: 'xdp', platform: 'fixture/browser', hostname: 'browser-fixture',
      interface: 'fixture0', xdpMode: 'generic', attached: true, mode: 'enforce', policyVersion: 1,
      startedAt: new Date().toISOString(), uptimeSeconds: 10, simulated: false, scenario: 'normal', activationPending: false,
      capabilities: [], health: [{ name: 'Fixture', status: 'info', detail: 'Deterministik tarayıcı test verisi' }],
      resources: { available: false, detail: 'Tarayıcı fixture verisi', cpuPercent: null, memoryUsedBytes: null,
        memoryTotalBytes: null, conntrackCount: null, conntrackMax: null },
    },
    metrics: { receivedPackets: 1000, passedPackets: 999, droppedPackets: 1, wouldDropPackets: 0, receivedBytes: 60000,
      pps: 10, bps: 800, dropPps: 1, activeConnections: 0, blockedSources: 0, mapCapacityFailures: 0, eventDrops: 0,
      reasons: [], protocols: [], services: [] },
    history: [], rules: [], bans: [], events: [], connections: [], alerts: [],
    policy: { version: 1, mode: 'enforce', interface: 'fixture0', xdpMode: 'generic', managementCidrs: ['192.0.2.1/32'],
      managementPort: 22, host: { tcpPorts: [443], udpPorts: [], ipv6: true }, rules: [] },
  };
}

async function mockSessionAndStreamFailure(page: Page) {
  await page.route('**/api/v1/session', route => route.fulfill({ json: { authenticated: true, csrfToken: 'browser-fixture-csrf' } }));
  await page.route('**/api/v1/stream', route => route.abort('failed'));
}

async function controlledStream(page: Page) {
  await page.addInitScript(() => {
    class ControlledStream extends EventTarget {
      onerror: (() => void) | null = null;
      constructor() { super(); (window as unknown as { fixtureStream: EventTarget }).fixtureStream = this; }
      close() { /* The fixture owns this browser-only event source. */ }
    }
    Object.defineProperty(window, 'EventSource', { value: ControlledStream });
  });
}

async function settleRendering(page: Page) {
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
}

test('successful HTTP fallback keeps API connected while SSE is unavailable', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  let snapshotRequests = 0;
  await mockSessionAndStreamFailure(page);
  await page.route('**/api/v1/snapshot', route => {
    snapshotRequests++;
    const data = fixture(); data.metrics.receivedPackets += snapshotRequests;
    return route.fulfill({ json: data });
  });
  await page.goto('/');
  await expect(page).toHaveTitle('WireWall — Firewall Yönetimi');
  await expect(page.getByRole('heading', { name: 'Genel Bakış', exact: true })).toBeVisible();
  await expect(page.getByText('API bağlı', { exact: true })).toBeVisible();
  await expect.poll(() => snapshotRequests, { timeout: 12000 }).toBeGreaterThanOrEqual(3);
  await expect(page.getByText('API bağlı', { exact: true })).toBeVisible();
  await expect(page.getByText('XDP uygulama modu etkin.', { exact: true })).toBeVisible();
  await expect(page.getByText(/Veriler güncel değil/)).toHaveCount(0);
  await expect(page.locator('vite-error-overlay, nextjs-portal')).toHaveCount(0);
  await page.reload();
  await expect(page.getByText('API bağlı', { exact: true })).toBeVisible();
  await page.screenshot({ path: join(tmpdir(), 'wirewall-http-fallback-desktop.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: join(tmpdir(), 'wirewall-http-fallback-mobile.png'), animations: 'disabled' });
  expect(errors).toEqual([]);
});

test('transport loss labels the last observation stale and recovers after a successful refresh', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  let offline = false;
  await mockSessionAndStreamFailure(page);
  await page.route('**/api/v1/snapshot', route => offline ? route.abort('failed') : route.fulfill({ json: fixture() }));
  await page.goto('/');
  await expect(page.getByText('XDP uygulama modu etkin.', { exact: true })).toBeVisible();
  offline = true;
  await page.getByRole('button', { name: 'Yenile', exact: true }).click();
  await expect(page.getByText(/Veriler güncel değil/)).toBeVisible();
  await expect(page.getByText(/Son gözlem:/)).toBeVisible();
  await expect(page.getByText(/XDP korumasının güncel durumu doğrulanamadı/)).toBeVisible();
  await expect(page.getByText('XDP uygulama modu etkin.', { exact: true })).toHaveCount(0);
  await expect(page.getByText('XDP arayüze bağlı değil; erken filtre koruması doğrulanamadı.')).toHaveCount(0);
  await page.getByRole('navigation', { name: 'Ana gezinme' }).getByRole('button', { name: 'Sistem', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Doğrula ve uygula', exact: true })).toBeDisabled();
  await expect(page.locator('vite-error-overlay, nextjs-portal')).toHaveCount(0);
  await page.screenshot({ path: join(tmpdir(), 'wirewall-stale-observation-desktop.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: join(tmpdir(), 'wirewall-stale-observation-mobile.png'), animations: 'disabled' });
  offline = false;
  await page.getByRole('button', { name: 'Yenile', exact: true }).click();
  await expect(page.locator('.api-status')).toHaveText('API bağlı');
  await expect(page.getByText('XDP uygulama modu etkin.', { exact: true })).toBeVisible();
  await expect(page.getByText(/Veriler güncel değil/)).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Doğrula ve uygula', exact: true })).toBeEnabled();
  expect(errors).toEqual([]);
});

test('an already open rule dialog blocks button and form submission while observations are stale', async ({ page }) => {
  let offline = false;
  let mutations = 0;
  await mockSessionAndStreamFailure(page);
  await page.route('**/api/v1/snapshot', route => offline ? route.abort('failed') : route.fulfill({ json: fixture() }));
  for (const pattern of ['**/api/v1/policy', '**/api/v1/policy/validate']) {
    await page.route(pattern, route => { mutations++; return route.fulfill({ json: { valid: true } }); });
  }
  await page.goto('/');
  await expect(page.getByText('API bağlı', { exact: true })).toBeVisible();
  await page.getByRole('navigation', { name: 'Ana gezinme' }).getByRole('button', { name: 'Kurallar', exact: true }).click();
  await page.getByRole('button', { name: 'Yeni kural', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Kural adı').fill('Browser fixture stale dialog');
  const submit = dialog.getByRole('button', { name: 'Doğrula ve uygula', exact: true });
  await expect(submit).toBeEnabled();
  offline = true;
  await expect(submit).toBeDisabled({ timeout: 12000 });
  await dialog.locator('form').evaluate(form => (form as HTMLFormElement).requestSubmit());
  await settleRendering(page);
  expect(mutations).toBe(0);
  await expect(dialog.getByRole('button', { name: 'Vazgeç', exact: true })).toBeEnabled();
  await page.screenshot({ path: join(tmpdir(), 'wirewall-stale-rule-dialog.png'), animations: 'disabled' });
  offline = false;
  await expect(submit).toBeEnabled({ timeout: 12000 });
  await dialog.getByRole('button', { name: 'Vazgeç', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  expect(mutations).toBe(0);
});

test('a delayed HTTP snapshot cannot rewind a newer stream observation', async ({ page }) => {
  await controlledStream(page);
  await page.route('**/api/v1/session', route => route.fulfill({ json: { authenticated: true, csrfToken: 'browser-fixture-csrf' } }));
  let requested = false;
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const old = fixture(); old.metrics.pps = 5;
  await page.route('**/api/v1/snapshot', async route => { requested = true; await gate; await route.fulfill({ json: old }); });
  try {
    await page.goto('/');
    await expect.poll(() => requested).toBe(true);
    const latest = fixture(); latest.metrics.pps = 321;
    await page.evaluate(data => (window as unknown as { fixtureStream: EventTarget }).fixtureStream.dispatchEvent(new MessageEvent('snapshot', { data: JSON.stringify(data) })), latest);
    await expect(page.getByText('321 pps', { exact: true })).toBeVisible();
    const response = page.waitForResponse(reply => reply.url().endsWith('/api/v1/snapshot'));
    release(); await response; await settleRendering(page);
    await expect(page.getByText('321 pps', { exact: true })).toBeVisible();
    await expect(page.getByText('5 pps', { exact: true })).toHaveCount(0);
    await expect(page.getByText('API bağlı', { exact: true })).toBeVisible();
  } finally { release(); }
});

test('a delayed prior-session 401 cannot log out a later successful login', async ({ page }) => {
  await controlledStream(page);
  await page.route('**/api/v1/session', route => route.fulfill({ json: { authenticated: true, csrfToken: 'browser-fixture-csrf' } }));
  let requests = 0;
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/v1/snapshot', async route => {
    requests++;
    if (requests === 2) { await gate; await route.fulfill({ status: 401, json: { error: 'Old fixture session expired' } }); return; }
    const data = fixture(); data.metrics.pps = requests > 2 ? 321 : 10;
    await route.fulfill({ json: data });
  });
  try {
    await page.goto('/'); await expect(page.getByText('10 pps', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Yenile', exact: true }).click();
    await expect.poll(() => requests).toBe(2);
    await page.getByRole('button', { name: 'Oturumu kapat', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Yönetim paneline bağlan', exact: true })).toBeVisible();
    // This is a fake fixture credential; no real operator key is used.
    await page.getByLabel('Operatör anahtarı').fill('browser-fixture-key');
    await page.getByRole('button', { name: 'Güvenli oturum aç', exact: true }).click();
    await expect(page.getByText('321 pps', { exact: true })).toBeVisible();
    const response = page.waitForResponse(reply => reply.url().endsWith('/api/v1/snapshot') && reply.status() === 401);
    release(); await response; await settleRendering(page);
    await expect(page.getByRole('heading', { name: 'Genel Bakış', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Yönetim paneline bağlan', exact: true })).toHaveCount(0);
    await expect(page.getByText('321 pps', { exact: true })).toBeVisible();
  } finally { release(); }
});
