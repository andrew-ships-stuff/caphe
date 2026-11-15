// Regenerates the committed brand assets in public/ (and the README copy) from
// the source artwork in the repository-level assets/ directory.
//
//   cd website && npm run render:brand
//
// The generated files are committed so the Pages build stays hermetic; rerun
// this only after replacing the source logos.
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import sharp from 'sharp';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const repo = dirname(root);
const source = join(repo, 'assets');
const target = join(root, 'public');

// The full logo ships on its own dark canvas; the site background is --caphe-bg.
const artworkBackground = { r: 15, g: 18, b: 21 };
const siteBackground = { r: 12, g: 16, b: 20 };

const png = { palette: true, quality: 95, effort: 10 };
const fullLogo = () => sharp(join(source, 'caphe_logo.png')).trim({ background: artworkBackground, threshold: 12 });
const mark = (size, pad) => sharp(join(source, 'caphe_simple_logo.png'))
  .trim({ threshold: 8 })
  .resize({ width: size - pad * 2, height: size - pad * 2, fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
  .extend({ top: pad, bottom: pad, left: pad, right: pad, background: { ...siteBackground, alpha: 1 } })
  .flatten({ background: siteBackground });

await mkdir(target, { recursive: true });

await fullLogo()
  .extend({ top: 36, bottom: 36, left: 44, right: 44, background: artworkBackground })
  .resize({ width: 640 })
  .png(png)
  .toFile(join(source, 'caphe_logo_640.png'));

await fullLogo()
  .flatten({ background: siteBackground })
  .extend({ top: 28, bottom: 28, left: 32, right: 32, background: siteBackground })
  .resize({ width: 960 })
  .png(png)
  .toFile(join(target, 'caphe-logo.png'));

await mark(64, 7).png(png).toFile(join(target, 'favicon.png'));
await mark(180, 20).png(png).toFile(join(target, 'apple-touch-icon.png'));

// Footer mark keeps transparency so it can sit on any themed tile.
await sharp(join(source, 'caphe_simple_logo.png'))
  .trim({ threshold: 8 })
  .resize({ width: 200, height: 200, fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
  .png(png)
  .toFile(join(target, 'caphe-mark.png'));

console.log('Rendered brand assets from assets/ into website/public/.');
