import sharp from 'sharp';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
await sharp(join(root, 'public', 'og-image.svg')).png().toFile(join(root, 'public', 'og-image.png'));
