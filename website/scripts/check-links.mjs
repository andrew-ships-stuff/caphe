import { readdir, readFile, stat } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';

const root = resolve('dist');
const configuredBase = process.env.BASE_PATH ?? (process.env.GITHUB_ACTIONS === 'true' ? '/caphe' : '/');
const base = `/${configuredBase.replace(/^\/+|\/+$/g, '')}`.replace(/^\/$/, '');
const htmlFiles = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (entry.name.endsWith('.html')) htmlFiles.push(path);
  }
}

async function exists(path) {
  try { await stat(path); return true; } catch { return false; }
}

await walk(root);
const failures = [];
for (const file of htmlFiles) {
  const html = await readFile(file, 'utf8');
  const links = [...html.matchAll(/(?:href|src)=["']([^"']+)["']/g)].map((match) => match[1]);
  for (const raw of links) {
    if (/^(?:https?:|mailto:|data:|javascript:|#)/.test(raw)) continue;
    const clean = decodeURIComponent(raw.split('#')[0].split('?')[0]);
    if (!clean) continue;
    let target;
    if (clean.startsWith('/')) {
      const withoutBase = base && (clean === base || clean.startsWith(`${base}/`)) ? clean.slice(base.length) || '/' : clean;
      target = join(root, withoutBase);
    } else target = resolve(dirname(file), clean);
    const candidates = [target, join(target, 'index.html')];
    if (!(await Promise.all(candidates.map(exists))).some(Boolean)) failures.push(`${file.replace(root, '')}: ${raw}`);
  }
}

if (failures.length) {
  console.error(`Broken local links (${failures.length}):\n${failures.join('\n')}`);
  process.exit(1);
}
console.log(`Checked ${htmlFiles.length} HTML files: no broken local links.`);
