import { chromium } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { spawn } from 'node:child_process';

const host = '127.0.0.1';
const port = '4321';
const configuredBase = process.env.BASE_PATH ?? (process.env.GITHUB_ACTIONS === 'true' ? '/caphe' : '/');
const base = `/${configuredBase.replace(/^\/+|\/+$/g, '')}/`.replace('//', '/');
const origin = `http://${host}:${port}`;
const preview = spawn('npm', ['run', 'preview', '--', '--host', host, '--port', port], { stdio: 'ignore', shell: process.platform === 'win32' });

async function ready() {
  for (let i = 0; i < 40; i += 1) {
    try { if ((await fetch(`${origin}${base}`)).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('Preview server did not become ready');
}

try {
  await ready();
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const routes = ['', 'docs/getting-started/', 'benchmarks/', 'roadmap/'];
  const violations = [];
  for (const route of routes) {
    const url = `${origin}${base}${route}`;
    await page.goto(url, { waitUntil: 'networkidle' });
    const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
    for (const item of result.violations.filter((v) => ['critical', 'serious'].includes(v.impact ?? ''))) {
      const targets = item.nodes.map((node) => node.target.join(' ')).join(', ');
      violations.push(`${route || '/'}: ${item.id} — ${item.help} (${targets})`);
    }
  }
  const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' });
  const mobilePage = await mobile.newPage();
  for (const route of ['', 'docs/getting-started/']) {
    await mobilePage.goto(`${origin}${base}${route}`, { waitUntil: 'networkidle' });
    const overflow = await mobilePage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 1) violations.push(`${route || '/'}: horizontal overflow of ${overflow}px at 390px viewport`);
  }
  await mobilePage.goto(`${origin}${base}`, { waitUntil: 'networkidle' });
  await mobilePage.getByRole('tab', { name: 'Compile' }).click();
  if (!(await mobilePage.locator('#panel-compile').isVisible())) violations.push('/: terminal tabs did not switch on mobile');
  const previousTheme = await mobilePage.locator('html').getAttribute('data-theme');
  await mobilePage.getByRole('button', { name: 'Switch color theme' }).click();
  if ((await mobilePage.locator('html').getAttribute('data-theme')) === previousTheme) violations.push('/: theme toggle did not change theme');
  await mobilePage.locator('summary[aria-label="Open navigation"]').click();
  if (!(await mobilePage.locator('.mobile-menu').getByRole('link', { name: 'Documentation', exact: true }).isVisible())) violations.push('/: mobile navigation did not open');
  await mobile.close();
  await context.close();
  await browser.close();
  if (violations.length) throw new Error(`Accessibility violations:\n${violations.join('\n')}`);
  console.log(`Checked ${routes.length} representative routes: no serious or critical axe violations.`);
} finally {
  preview.kill('SIGTERM');
}
