import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';
import tailwindcss from '@tailwindcss/vite';

const repository = process.env.GITHUB_REPOSITORY?.split('/')[1] ?? 'caphe';
const owner = process.env.GITHUB_REPOSITORY_OWNER ?? 'andrew-ships-stuff';
const isActions = process.env.GITHUB_ACTIONS === 'true';
const base = process.env.BASE_PATH ?? (isActions ? `/${repository}` : '/');
const site = process.env.SITE_URL ?? `https://${owner}.github.io`;
const socialImage = new URL(`${base.replace(/^\/+/, '').replace(/\/+$/, '')}${base === '/' ? '' : '/'}og-image.png`, `${site}/`).href;

export default defineConfig({
  site,
  base,
  output: 'static',
  trailingSlash: 'always',
  integrations: [
    sitemap(),
    starlight({
      title: 'Caphe',
      description: 'CPU-native compiled security workflows.',
      favicon: '/favicon.png',
      customCss: ['./src/styles/global.css'],
      logo: { src: './src/assets/mark.svg', alt: 'Caphe' },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/andrew-ships-stuff/caphe' }
      ],
      editLink: { baseUrl: 'https://github.com/andrew-ships-stuff/caphe/edit/main/website/' },
      lastUpdated: false,
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Getting started', slug: 'docs/getting-started' },
            { label: 'Architecture', slug: 'docs/architecture' },
            { label: 'CLI reference', slug: 'docs/cli' },
            { label: 'Cluster execution', slug: 'docs/cluster' }
          ]
        },
        {
          label: 'Core concepts',
          items: [
            { label: 'Workflows', slug: 'docs/workflows' },
            { label: 'Evidence graph', slug: 'docs/evidence-graph' },
            { label: 'CPU inference', slug: 'docs/cpu-inference' },
            { label: 'Security model', slug: 'docs/security' }
          ]
        },
        {
          label: 'Integrations',
          items: [{ autogenerate: { directory: 'docs/integrations' } }]
        },
        {
          label: 'Project',
          items: [
            { label: 'Benchmarking', link: '/benchmarks/' },
            { label: 'Roadmap', link: '/roadmap/' },
            { label: 'Contributing', link: '/contributing/' }
          ]
        }
      ],
      head: [
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: `${base.replace(/\/$/, '')}/apple-touch-icon.png` } },
        { tag: 'meta', attrs: { property: 'og:image', content: socialImage } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#0c1014' } }
      ]
    })
  ],
  vite: { plugins: [tailwindcss()] }
});
