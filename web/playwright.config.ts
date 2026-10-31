import { defineConfig } from '@playwright/test';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const baseURL = process.env.WIREWALL_BASE_URL || 'http://127.0.0.1:5173';
export default defineConfig({
  testDir: './e2e',
  timeout: 45000,
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  outputDir: join(tmpdir(), 'wirewall-playwright-results'),
  use: { baseURL, viewport: { width: 1536, height: 1024 }, trace: 'off', actionTimeout: 10000 },
  webServer: process.env.WIREWALL_BASE_URL ? undefined : { command: 'npm run dev -- --port 5173 --strictPort', url: baseURL, reuseExistingServer: true },
});
