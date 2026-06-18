// Generates the @passage/core API reference (TypeDoc -> Fumadocs markdown) and
// writes the API section's meta.json (title + nav order), since TypeDoc cleans
// the output directory on each run.
import { $ } from 'bun';

await $`typedoc`;

await Bun.write(
  'content/docs/api/meta.json',
  JSON.stringify(
    {
      title: 'API Reference',
      description: 'Generated from the @passage/core public API.',
      pages: ['index', 'classes', 'functions', 'interfaces', 'type-aliases', 'variables', '...'],
    },
    null,
    2,
  ) + '\n',
);

console.log('[gen-api] API reference + meta.json generated');
