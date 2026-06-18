import { defineConfig, defineDocs } from 'fumadocs-mdx/config';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';
import { remarkInstall } from 'fumadocs-docgen';
import { transformerTwoslash } from 'fumadocs-twoslash';
import { rehypeCodeDefaultOptions, type RehypeCodeOptions } from 'fumadocs-core/mdx-plugins';

export const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: pageSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

export default defineConfig({
  mdxOptions: {
    // `package-install` code blocks → npm / pnpm / yarn / bun tabs.
    remarkPlugins: [remarkInstall],
    rehypeCodeOptions: {
      ...rehypeCodeDefaultOptions,
      // Twoslash: `ts twoslash` blocks get inline types/errors on hover.
      transformers: [...(rehypeCodeDefaultOptions.transformers ?? []), transformerTwoslash()],
      // Twoslash can't lazy-load languages for its popups — declare common ones up front.
      langs: ['ts', 'tsx', 'js', 'jsx', 'yaml', 'bash', 'json'],
    } as RehypeCodeOptions,
  },
});
