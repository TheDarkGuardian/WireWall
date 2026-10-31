import { test, expect } from '@playwright/test';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readFile } from 'node:fs/promises';
import type { Page } from '@playwright/test';
import type { Policy } from '../src/types';

const token = process.env.WIREWALL_TOKEN;
test.skip(!token, 'Start the lab API on :8080 and set WIREWALL_TOKEN to its operator token.');

async function login(page: Page) {
  await page.goto('/');
  await expect(page).toHaveTitle('WireWall — Firewall Yönetimi');
  await page.getByLabel('Operatör anahtarı').fill(token!);
  const response = page.waitForResponse(reply => reply.url().endsWith('/api/v1/session') && reply.request().method() === 'POST');
  await page.getByRole('button', { name: 'Güvenli oturum aç' }).click();
  const result = await response;
  if (!result.ok()) await page.getByLabel('Operatör anahtarı').clear();
  await expect(page.getByRole('heading', { name: 'Genel Bakış', exact: true })).toBeVisible();
  await expect(page.getByText('Laboratuvar modu — gerçek ağ trafiği filtrelenmiyor.')).toBeVisible();
  await expect(page.getByText('API bağlı', { exact: true })).toBeVisible();
  const data = await (await page.request.get('/api/v1/snapshot')).json();
  expect(data.system.simulated, 'E2E mutations may only run against the laboratory backend').toBe(true);
  expect((await page.context().cookies()).find(cookie => cookie.name === 'wirewall_session')?.httpOnly).toBe(true);
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
}

async function updatePolicy(page: Page, policy: Policy) {
  const session = await (await page.request.get('/api/v1/session')).json();
  const current = await (await page.request.get('/api/v1/policy')).json();
  const reply = await page.request.put('/api/v1/policy', { headers: { 'X-WireWall-CSRF': session.csrfToken }, data: { policy, expectedVersion: current.version } });
  expect(reply.ok()).toBe(true);
}

async function setScenario(page: Page, scenario: string) {
  const session = await (await page.request.get('/api/v1/session')).json();
  const reply = await page.request.post('/api/v1/lab/scenarios', { headers: { 'X-WireWall-CSRF': session.csrfToken }, data: { scenario } });
  expect(reply.ok()).toBe(true);
}

test('byte budget rejection leaves policy intact and a valid byte rule changes laboratory decisions', async ({ page }) => {
  await login(page);
  const original: Policy = await (await page.request.get('/api/v1/policy')).json();
  const baseline = { ...original, mode: 'enforce' as const, rules: original.rules.map(rule => ({ ...rule, enabled: false })) };
  const name = `Byte bütçesi testi ${Date.now()}`;
  try {
    await updatePolicy(page, baseline);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Genel Bakış', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Kurallar', exact: true }).click();
    await page.getByRole('button', { name: 'Yeni kural' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Kural adı').fill(name);
    await dialog.getByLabel('Kaynak CIDR', { exact: true }).fill('198.51.100.10/32');
    await dialog.getByLabel('Hedef port', { exact: true }).fill('443');
    await dialog.getByRole('combobox', { name: 'Karar', exact: true }).selectOption('limit');
    await dialog.getByLabel('Paket / saniye', { exact: true }).fill('1000000');
    await dialog.getByLabel('Burst kapasitesi', { exact: true }).fill('1000000');
    await dialog.getByLabel('Servis hızı (byte/s)').fill('1');
    const beforeInvalid = await (await page.request.get('/api/v1/policy')).json();
    await dialog.getByRole('button', { name: 'Doğrula ve uygula' }).click();
    await expect(dialog.getByRole('alert')).toContainText('bps and byteBurst');
    expect((await (await page.request.get('/api/v1/policy')).json()).version).toBe(beforeInvalid.version);
    await dialog.getByLabel('Servis byte burst (byte)').fill('60');
    await dialog.getByRole('button', { name: 'Doğrula ve uygula' }).click();
    await expect(dialog).not.toBeVisible();
    const saved = (await (await page.request.get('/api/v1/policy')).json()).rules.find((rule: { name: string }) => rule.name === name);
    expect(saved).toMatchObject({ bps: 1, byteBurst: 60, pps: 1000000, burst: 1000000 });
    await setScenario(page, 'normal');
    await expect.poll(async () => {
      const snapshot = await (await page.request.get('/api/v1/snapshot')).json();
      return snapshot.events.some((event: { ruleId: string; reason: string; action: string; wouldDrop: boolean }) => event.ruleId === saved.id && event.reason === 'byte_limit' && event.action === 'drop' && !event.wouldDrop);
    }).toBe(true);
    await page.getByRole('button', { name: 'Canlı Trafik', exact: true }).click();
    await page.getByLabel('Paket kararlarında ara').fill(saved.id);
    await expect(page.locator('tbody tr').first()).toContainText('Servis byte sınırı');
    await expect(page.locator('tbody .verdict').first()).toHaveText('DROP');
    await page.getByRole('button', { name: 'Kurallar', exact: true }).click();
    const row = page.getByRole('row').filter({ hasText: name });
    await row.getByRole('button', { name: `${name} sil` }).click();
    await page.getByRole('button', { name: 'Kuralı sil', exact: true }).click();
    await expect(row).toHaveCount(0);
  } finally {
    await updatePolicy(page, original);
    await setScenario(page, 'normal');
  }
});

test('port scan scenario produces a clearly synthetic warning without adding an automatic ban', async ({ page }) => {
  await login(page);
  const original = await (await page.request.get('/api/v1/snapshot')).json();
  let banMutations = 0;
  page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/api/v1/bans')) banMutations++; });
  try {
    await setScenario(page, 'normal');
    await page.getByRole('button', { name: 'Laboratuvarı sıfırla' }).click();
    await expect(page.getByText('Port taraması uyarıları: Henüz şüpheli port taraması uyarısı yok.')).toBeVisible();
    await page.getByRole('button', { name: 'Senaryo çalıştır', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('radio', { name: /^Port taraması/ }).check();
    await dialog.getByRole('button', { name: 'Senaryoyu çalıştır' }).click();
    await expect(page.getByRole('heading', { name: 'Şüpheli port taraması' })).toBeVisible();
    const alerts = page.getByRole('region', { name: 'Port taraması uyarıları' });
    await expect(alerts).toContainText('198.51.100.77');
    await expect(alerts).toContainText('Sentetik laboratuvar gözlemi');
    await expect(alerts).toContainText('otomatik IP engeli uygulanmaz');
    const snapshot = await (await page.request.get('/api/v1/snapshot')).json();
    const scan = snapshot.alerts.find((alert: { source: string }) => alert.source === '198.51.100.77');
    expect(scan).toMatchObject({ type: 'port_scan', severity: 'warning', sampled: false, windowSeconds: 10 });
    expect(scan.uniquePorts).toBeGreaterThanOrEqual(20);
    expect(snapshot.bans.map((ban: { id: string }) => ban.id)).toEqual(original.bans.map((ban: { id: string }) => ban.id));
    expect(banMutations).toBe(0);
    await alerts.getByRole('button', { name: 'Engelleri görüntüle' }).click();
    await expect(page.getByRole('heading', { name: 'Engeller', exact: true })).toBeVisible();
    expect(banMutations).toBe(0);
    await page.getByRole('button', { name: 'Genel Bakış', exact: true }).click();
    await page.locator('.toast').waitFor({ state: 'hidden' });
    await page.screenshot({ path: join(tmpdir(), 'wirewall-scan-alerts-desktop.png'), fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expect.poll(() => page.locator('.traffic-chart text').evaluateAll(labels => labels.every(label => (label as SVGGraphicsElement).getBBox().x >= 0))).toBe(true);
    await page.screenshot({ path: join(tmpdir(), 'wirewall-scan-alerts-mobile.png'), fullPage: true, animations: 'disabled' });
  } finally {
    await setScenario(page, original.system.scenario || 'normal');
  }
});

test('authenticated dashboard, scenario, filters and responsive navigation', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await login(page);
  await page.getByRole('button', { name: 'Senaryo çalıştır', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Karışık trafik').check();
  await dialog.getByRole('button', { name: 'Senaryoyu çalıştır' }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.locator('.scenario-label')).toHaveText('Karışık trafik');
  await expect(page.locator('tbody tr').first()).not.toContainText('Henüz paket kararı yok');
  await page.locator('.toast').waitFor({ state: 'hidden' });
  await page.screenshot({ path: join(tmpdir(), 'wirewall-overview-desktop.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('button', { name: 'Canlı Trafik', exact: true }).click();
  await page.getByLabel('Karar filtresi').selectOption('drop');
  await expect(page.locator('tbody .verdict').first()).toHaveText('DROP');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'JSON indir' }).click();
  const download = await downloadPromise;
  const exported = JSON.parse(await readFile((await download.path())!, 'utf-8'));
  expect(exported.simulated).toBe(true);
  expect(exported.events.length).toBeGreaterThan(0);
  expect(exported.events.every((event: { action: string }) => event.action === 'drop')).toBe(true);
  const csvPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'CSV indir' }).click();
  const csvDownload = await csvPromise;
  const csv = await readFile((await csvDownload.path())!, 'utf-8');
  expect(csv).toContain('timestamp,source,destination,sourcePort,destinationPort');
  expect(csv).toContain('simulated,policyVersion');
  expect(csv).toContain('"drop"');
  expect(csvDownload.suggestedFilename()).toMatch(/\.csv$/);
  await page.getByLabel('Paket kararlarında ara').fill('no-matching-address');
  await expect(page.getByText('Eşleşen paket kararı yok.')).toBeVisible();
  await page.getByLabel('Paket kararlarında ara').clear();
  await page.getByRole('button', { name: 'Bağlantılar', exact: true }).click();
  await expect(page.getByText(/sentetik laboratuvar akışlarını gösterir/)).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Menüyü aç' }).click();
  await expect(page.locator('.sidebar').getByRole('button', { name: 'Menüyü kapat' })).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(page.getByRole('button', { name: 'Oturumu kapat' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('.sidebar').getByRole('button', { name: 'Menüyü kapat' })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: 'Menüyü aç' })).toBeFocused();
  await page.getByRole('button', { name: 'Menüyü aç' }).click();
  await page.getByRole('button', { name: 'Genel Bakış', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Genel Bakış', exact: true })).toBeVisible();
  await expect(page.locator('.sidebar.mobile-open')).toHaveCount(0);
  await expect(page.locator('.sidebar')).toHaveAttribute('inert');
  await expect.poll(async () => (await page.locator('.sidebar').boundingBox())?.x ?? 0).toBeLessThan(-247);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: join(tmpdir(), 'wirewall-overview-mobile.png'), fullPage: true, animations: 'disabled' });
  expect(errors).toEqual([]);
});

test('invalid login clears the input and invalid rule keeps the existing policy', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Operatör anahtarı').fill('invalid-test-operator-key');
  await page.getByRole('button', { name: 'Güvenli oturum aç' }).click();
  await expect(page.getByRole('alert')).toContainText('geçersiz');
  await expect(page.getByLabel('Operatör anahtarı')).toHaveValue('');
  await login(page);
  const before = await (await page.request.get('/api/v1/policy')).json();
  await page.getByRole('button', { name: 'Kurallar', exact: true }).click();
  await page.getByRole('button', { name: 'Yeni kural' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Kural adı').fill('Geçersiz CIDR testi');
  await dialog.getByLabel('Kaynak CIDR', { exact: true }).fill('invalid-network');
  await dialog.getByRole('button', { name: 'Doğrula ve uygula' }).click();
  await expect(dialog.getByRole('alert')).toContainText('source');
  await expect(dialog).toBeVisible();
  expect((await (await page.request.get('/api/v1/policy')).json()).version).toBe(before.version);
  await dialog.getByRole('button', { name: 'Vazgeç' }).click();
  await expect(dialog).not.toBeVisible();
});

test('real-mode rendering keeps unavailable accounting and detached XDP explicit', async ({ page }) => {
  await login(page);
  const base = await (await page.request.get('/api/v1/snapshot')).json();
  let pending = true; let confirmationHeader = ''; let showAlert = true; let banMutations = 0;
  page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/api/v1/bans')) banMutations++; });
  const mocked = () => ({ ...base, system: { ...base.system, backend: 'xdp', simulated: false, attached: false,
    activationPending: pending, activationDeadline: new Date(Date.now() + 60000).toISOString(),
    resources: { available: true, detail: 'Deterministik tarayıcı test verisi', cpuPercent: 12.5,
      memoryUsedBytes: 1073741824, memoryTotalBytes: 4294967296, conntrackCount: 100, conntrackMax: 2048 } },
    alerts: showAlert ? [{ id: 'scan-fixture', timestamp: new Date().toISOString(), source: '198.51.100.23', destination: '203.0.113.10',
      uniquePorts: 32, windowSeconds: 10, sampled: true, type: 'port_scan', severity: 'warning', message: 'Örneklenmiş pencerede farklı hedef portlar gözlendi.' }] : [],
    events: [{ id: 'csv-safety', policyVersion: 17, timestamp: new Date().toISOString(), source: '198.51.100.23', destination: '203.0.113.10',
      sourcePort: 42000, destinationPort: 443, protocol: 'tcp', length: 60, action: 'drop', reason: 'rule_drop', ruleId: ' =2+2', wouldDrop: false, simulated: false }],
    connections: [{ id: 'accounting-disabled', source: '198.51.100.23', destination: '203.0.113.10', sourcePort: 42000,
      destinationPort: 443, protocol: 'tcp', state: 'ESTABLISHED', direction: 'original', packets: 0, bytes: 0,
      observedAt: new Date().toISOString(), accountingAvailable: false, simulated: false }] });
  // These are deterministic browser fixtures, never a requested real firewall mutation.
  await page.route('**/api/v1/snapshot', route => route.fulfill({ json: mocked() }));
  await page.route('**/api/v1/stream', route => route.fulfill({ contentType: 'text/event-stream', body: `event: snapshot\ndata: ${JSON.stringify(mocked())}\n\n` }));
  await page.route('**/api/v1/policy/confirm', route => {
    confirmationHeader = route.request().headers()['x-wirewall-csrf'] || '';
    pending = false; return route.fulfill({ json: { ok: true } });
  });
  await page.reload();
  await expect(page.getByText('XDP arayüze bağlı değil; erken filtre koruması doğrulanamadı.')).toBeVisible();
  await expect(page.getByText('Gösterilen conntrack akışları (en fazla 256)', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Senaryo çalıştır', exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Şüpheli port taraması' })).toBeVisible();
  await expect(page.getByRole('cell').filter({ hasText: '32 farklı port' })).toBeVisible();
  await expect(page.getByText('Örneklenmiş veri · yaklaşık gözlem')).toBeVisible();
  await page.getByRole('button', { name: 'Engelleri görüntüle' }).click();
  await expect(page.getByRole('heading', { name: 'Engeller', exact: true })).toBeVisible();
  expect(banMutations).toBe(0);
  await page.getByRole('button', { name: 'Genel Bakış', exact: true }).click();
  showAlert = false;
  await page.getByRole('button', { name: 'Yenile', exact: true }).click();
  await expect(page.getByText('Port taraması uyarıları: Henüz şüpheli port taraması uyarısı yok.')).toBeVisible();
  showAlert = true;
  await page.getByRole('button', { name: 'Yenile', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Şüpheli port taraması' })).toBeVisible();
  await expect(page.getByText('Geçici politika onayı bekleniyor')).toBeVisible();
  await page.getByRole('button', { name: 'Erişimi doğruladım, onayla' }).click();
  await expect(page.getByText('Geçici politika onayı bekleniyor')).toHaveCount(0);
  expect(confirmationHeader.length).toBeGreaterThan(0);
  await page.screenshot({ path: join(tmpdir(), 'wirewall-alerts-fixture.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('button', { name: 'Bağlantılar', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'Sayaç yok' })).toBeVisible();
  await expect(page.getByText(/kernel akış sayaçları kapalıysa/)).toBeVisible();
  await expect(page.locator('.info-note')).toContainText('Gösterilen conntrack akışları (en fazla 256).');
  await page.getByRole('button', { name: 'Canlı Trafik', exact: true }).click();
  // A displayed source port must be searchable even when it does not occur in
  // either address, the destination port, the reason or the rule identifier.
  await page.getByLabel('Paket kararlarında ara').fill('42000');
  await expect(page.locator('tbody tr')).toHaveCount(1);
  await expect(page.locator('tbody tr').first()).toContainText('198.51.100.23:42000');
  const sourceJsonPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'JSON indir' }).click();
  const sourceJson = await sourceJsonPromise;
  const sourceExport = JSON.parse(await readFile((await sourceJson.path())!, 'utf-8'));
  expect(sourceExport.events).toHaveLength(1);
  expect(sourceExport.events[0]).toMatchObject({ sourcePort: 42000, policyVersion: 17 });
  const safeCsvPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'CSV indir' }).click();
  const safeCsv = await safeCsvPromise;
  const safeCsvContent = await readFile((await safeCsv.path())!, 'utf-8');
  expect(safeCsvContent).toContain('"\' =2+2"');
  const csvLines = safeCsvContent.trim().split(/\r?\n/);
  expect(csvLines[0].split(',').at(-1)).toBe('policyVersion');
  expect(csvLines[1].split(',').at(-1)).toBe('"17"');
  await page.getByRole('button', { name: 'Sistem', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Makine kaynakları' })).toBeVisible();
  await expect(page.getByText('%12,5', { exact: true })).toBeVisible();
  await expect(page.getByText('1 GiB / 4 GiB', { exact: true })).toBeVisible();
  await page.screenshot({ path: join(tmpdir(), 'wirewall-system-fixture.png'), fullPage: true, animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('rule and temporary ban management round trips persist through the API', async ({ page }) => {
  await login(page);
  const name = `Tarayıcı testi ${Date.now()}`;
  await page.getByRole('button', { name: 'Kurallar', exact: true }).click();
  await page.getByRole('button', { name: 'Yeni kural' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Kural adı').fill(name);
  await dialog.getByLabel('Hedef port', { exact: true }).fill('8080');
  await dialog.getByRole('combobox', { name: 'Karar', exact: true }).selectOption('limit');
  await dialog.getByLabel('Paket / saniye', { exact: true }).fill('1000');
  await dialog.getByLabel('Burst kapasitesi', { exact: true }).fill('2000');
  await dialog.getByLabel('Servis hızı (byte/s)').fill('100000');
  await dialog.getByLabel('Servis byte burst (byte)').fill('200000');
  await dialog.getByLabel('Kaynak IP hızı (byte/s)').fill('10000');
  await dialog.getByLabel('Kaynak IP byte burst (byte)').fill('20000');
  await dialog.getByRole('button', { name: 'Doğrula ve uygula' }).click();
  await expect(dialog).not.toBeVisible();
  const row = page.getByRole('row').filter({ hasText: name });
  await expect(row).toBeVisible();
  await expect(row).toContainText('100.000 byte/s');
  const created = (await (await page.request.get('/api/v1/policy')).json()).rules.find((rule: { name: string }) => rule.name === name);
  expect(created).toMatchObject({ bps: 100000, byteBurst: 200000, sourceBps: 10000, sourceByteBurst: 20000 });
  await row.getByRole('switch').click();
  await expect(row.getByRole('switch')).toHaveAttribute('aria-checked', 'false');
  await row.getByRole('button', { name: `${name} düzenle` }).click();
  await page.getByRole('dialog').getByLabel('Hedef port', { exact: true }).fill('8081');
  await page.getByRole('dialog').getByRole('button', { name: 'Doğrula ve uygula' }).click();
  await expect(row).toContainText('8081');
  await row.getByRole('button', { name: `${name} sil` }).click();
  await page.getByRole('button', { name: 'Kuralı sil', exact: true }).click();
  await expect(row).toHaveCount(0);
  await page.getByRole('button', { name: 'Engeller', exact: true }).click();
  await page.getByRole('button', { name: 'IP engelle' }).click();
  await page.getByLabel('IP adresi', { exact: true }).fill('198.51.100.244');
  await page.getByLabel('Gerekçe').fill(name);
  await page.getByRole('button', { name: 'Engeli uygula' }).click();
  const banRow = page.getByRole('row').filter({ hasText: name });
  await expect(banRow).toBeVisible();
  await banRow.getByRole('button', { name: 'Kaldır' }).click();
  await expect(banRow).toHaveCount(0);
  await page.getByRole('button', { name: 'Sistem', exact: true }).click();
  const original = await (await page.request.get('/api/v1/policy')).json();
  const next = original.mode === 'observe' ? 'enforce' : 'observe';
  await page.getByLabel('Erken filtre modu').selectOption(next);
  await page.getByRole('button', { name: 'Doğrula ve uygula' }).click();
  await expect.poll(async () => (await (await page.request.get('/api/v1/policy')).json()).mode).toBe(next);
  await page.getByLabel('Erken filtre modu').selectOption(original.mode);
  await page.getByRole('button', { name: 'Doğrula ve uygula' }).click();
  await expect.poll(async () => (await (await page.request.get('/api/v1/policy')).json()).mode).toBe(original.mode);
  await page.getByRole('button', { name: 'Oturumu kapat' }).click();
  await expect(page.getByRole('heading', { name: 'Yönetim paneline bağlan' })).toBeVisible();
  await expect(page.locator('.form-error')).toHaveCount(0);
});
