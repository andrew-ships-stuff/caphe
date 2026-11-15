import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
  docs: defineCollection({
    loader: docsLoader({
      generateId: ({ entry, data }) => {
        const slug = typeof data.slug === 'string'
          ? data.slug
          : entry.replace(/\.(md|mdx)$/, '').replace(/\/index$/, '');
        return `docs/${slug}`;
      }
    }),
    schema: docsSchema()
  })
};
