// Local TypeDoc plugin: give every generated API page a Fumadocs-compatible
// frontmatter `title` (taken from the reflection name), since Fumadocs requires
// a title on each MDX/MD page. Runs alongside typedoc-plugin-frontmatter, which
// serializes `page.frontmatter` into the output file.
import { MarkdownPageEvent } from 'typedoc-plugin-markdown';

/** @param {import('typedoc-plugin-markdown').MarkdownApplication} app */
export function load(app) {
  app.renderer.on(
    MarkdownPageEvent.BEGIN,
    /** @param {import('typedoc-plugin-markdown').MarkdownPageEvent} page */
    (page) => {
      const title = page.model?.name ?? 'API Reference';
      page.frontmatter = {
        title,
        ...page.frontmatter,
      };
    },
  );
}
