import { test, expect } from '@playwright/test';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { root } from '../pipeline.mjs';

const browserErrors = new WeakMap();
test.beforeEach(async ({ page }) => {
  const errors = [];
  browserErrors.set(page, errors);
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('response', response => { if (!response.ok()) errors.push(`HTTP ${response.status()}: ${response.url()}`); });
});
test.afterEach(async ({ page }) => {
  expect(browserErrors.get(page)).toEqual([]);
});

test('wizard gates navigation, generates scoped commands and restores state', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Start the eight-step wizard' }).click();
  await page.locator('#wizardBegin').click();
  await expect(page.locator('#wizardNext')).toBeDisabled();
  await expect(page.locator('[data-wizard-go="4"]')).toBeDisabled();
  await page.locator('[data-wizard-panel="0"] [data-wizard-complete]').check();
  await page.locator('#wizardNext').click();
  await expect(page.locator('#wizardTitle1')).toBeVisible();
  await page.locator('#scopePicker input[value="Transport"]').check();
  await expect(page.locator('#scopeArgument')).toContainText("'Transport'");
  await page.locator('[data-wizard-panel="1"] [data-wizard-complete]').check();
  await page.locator('#wizardNext').click();
  await expect(page.locator('#wizardTitle2')).toBeVisible();
  await page.reload();
  await expect(page.locator('#wizardTitle2')).toBeVisible();
  await page.locator('[data-wizard-go="1"]').click();
  await page.locator('#scopePicker input[value="Organization"]').check();
  await expect(page.locator('#scopeArgument')).toContainText("'Organization'");
  await expect(page.locator('#wizardNext')).toBeDisabled();
  await expect(page.locator('[data-wizard-go="2"]')).toBeDisabled();
});

test('every staged guide is served and the in-site reader renders a deep link', async ({ page, request }) => {
  const docs = readdirSync(path.join(root, '.artifacts', 'bundle', 'site', 'docs')).filter(name => name.endsWith('.md'));
  expect(docs.length).toBeGreaterThan(0);
  for (const name of docs) {
    const response = await request.get(`/docs/${encodeURIComponent(name)}`);
    expect(response.ok(), name).toBeTruthy();
    expect((await response.text()).length, name).toBeGreaterThan(0);
  }
  await page.goto('/#doc=APPROVED-CHANGE.md');
  await expect(page.locator('#documentContent')).toContainText('Preview');
  await page.reload();
  await expect(page.locator('#documentContent')).toContainText('Preview');
});

test('only publishable assets are staged and version identity is available', async ({ request }) => {
  const version = await request.get('/version.json');
  expect(version.ok()).toBeTruthy();
  const plan = JSON.parse(readFileSync(path.join(root, '.artifacts', 'ci', 'plan.json'), 'utf8').replace(/^\uFEFF/, ''));
  expect(await version.json()).toMatchObject({ sourceTree: plan.tree, sourceCommit: plan.commit });
  expect((await request.get('/Start-MicrositePreview.ps1')).status()).toBe(404);
  expect((await request.get('/docs/DOES-NOT-EXIST.md')).status()).toBe(404);
});
