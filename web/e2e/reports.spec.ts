import { test, expect } from '@playwright/test';
import type { Download, Page } from '@playwright/test';

const token = process.env.WIREWALL_TOKEN;
test.skip(!token, 'A separate laboratory API and in-memory operator token are required.');

async function login(page: Page) {
  await page.goto('/');
  await page.getByLabel('Operatör anahtarı').fill(token!);
  await page.getByRole('button', { name: 'Güvenli oturum aç' }).click();
  await expect(page.getByRole('heading', { name: 'Genel Bakış', exact: true })).toBeVisible();
  expect((await (await page.request.get('/api/v1/snapshot')).json()).system.simulated).toBe(true);
}
async function contents(file: Download) {
  const stream = await file.createReadStream(); if (!stream) throw new Error('Download unavailable');
  const chunks = []; for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

test('persistent history filters, anchored pagination and CSV export use the real lab API', async ({ page }) => {
  await login(page);
  await expect.poll(async () => (await (await page.request.get('/api/v1/events?limit=50')).json()).summary.matchedEvents, { timeout: 15000 }).toBeGreaterThan(50);
  const firstResponse = page.waitForResponse(reply => reply.url().includes('/api/v1/events?'));
  await page.getByRole('button', { name: 'Olay Geçmişi', exact: true }).click();
  const first = await (await firstResponse).json();
  await expect(page.getByRole('heading', { name: 'Kalıcı olay kayıtları' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sonraki', exact: true })).toBeEnabled();
  const nextResponse = page.waitForResponse(reply => reply.url().includes('/api/v1/events?') && reply.url().includes('cursor='));
  await page.getByRole('button', { name: 'Sonraki', exact: true }).click();
  const second = await (await nextResponse).json();
  expect(second.items.every((item: { id: string }) => !first.items.some((old: { id: string }) => old.id === item.id))).toBe(true);
  await expect(page.getByText(/Sayfa 2 ·/)).toBeVisible();
  await page.getByLabel('Geçmiş kaynak IP').fill(first.items[0].source);
  const filteredResponse = page.waitForResponse(reply => reply.url().includes('/api/v1/events?') && reply.url().includes('source='));
  await page.getByRole('button', { name: 'Filtreleri uygula', exact: true }).click();
  const filtered = await (await filteredResponse).json();
  expect(filtered.items.length).toBeGreaterThan(0);
  expect(filtered.items.every((item: { source: string }) => item.source === first.items[0].source)).toBe(true);
  await expect(page.getByRole('button', { name: 'Geçmiş CSV', exact: true })).toBeEnabled();
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Geçmiş CSV', exact: true }).click();
  const csv = await contents(await downloaded);
  expect(csv.split('\n')[0]).toContain('policyVersion');
  expect(csv).toContain(first.items[0].source);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test('empty and failed report queries stay explicit and HTML exports escape filter text', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: 'Olay Geçmişi', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Filtreleri uygula', exact: true })).toBeEnabled();
  await page.getByLabel('Geçmişte ara').fill('<img src=x onerror=alert(1)>');
  const response = page.waitForResponse(reply => reply.url().includes('/api/v1/events?') && reply.url().includes('q='));
  await page.getByRole('button', { name: 'Filtreleri uygula', exact: true }).click();
  expect((await (await response).json()).summary.matchedEvents).toBe(0);
  await expect(page.getByText('Eşleşen paket kararı yok.', { exact: true })).toBeVisible();
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: 'HTML raporu indir', exact: true }).click();
  const html = await contents(await downloaded);
  expect(html).toContain('&lt;img'); expect(html).not.toContain('<img src=x');
  expect(html).toContain('Sentetik laboratuvar');
  await page.route('**/api/v1/events?*', route => route.fulfill({ status: 503, json: { error: 'Test: geçmiş kaynağı erişilemiyor' } }));
  await page.getByRole('button', { name: 'Raporu yenile', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Test: geçmiş kaynağı erişilemiyor');
  await expect(page.getByRole('button', { name: 'HTML raporu indir', exact: true })).toHaveCount(0);
});
