import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './browser',
  retries: 0,
  workers: 1,
  forbidOnly: !!process.env.CI,
  reporter: [['line'], ['junit', { outputFile: 'test-results/browser.xml' }]],
  use: { baseURL: 'http://127.0.0.1:4173', trace: 'retain-on-failure' },
  webServer: {
    command: 'node server.mjs',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
