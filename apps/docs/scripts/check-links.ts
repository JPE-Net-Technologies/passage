// Broken-link linter for the docs. Scans content/docs MDX for internal links and
// verifies each resolves to a real page — including the generated TypeDoc API
// cross-references (a common breakage source). Exits non-zero on any break.
//
// Run AFTER the API reference is generated: `bun run gen:api && bun scripts/check-links.ts`
// (wired as `lint:links`).
import { Glob } from 'bun';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const ROOT = 'content/docs';
const files = [...new Glob('**/*.{md,mdx}').scanSync(ROOT)].map((f) => join(ROOT, f));

/** Map a `/docs/...` route back to a content file, if one exists. */
function routeExists(route: string): boolean {
  const rel = route.replace(/^\/docs\/?/, '').replace(/\/$/, '');
  const candidates =
    rel === ''
      ? ['index.md', 'index.mdx']
      : [`${rel}.md`, `${rel}.mdx`, `${rel}/index.md`, `${rel}/index.mdx`];
  return candidates.some((c) => existsSync(join(ROOT, c)));
}

const linkRe = /\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
let broken = 0;

for (const file of files) {
  const content = readFileSync(file, 'utf8');
  for (const m of content.matchAll(linkRe)) {
    const raw = m[1];
    if (!raw || /^(https?:|mailto:|#)/.test(raw)) continue;
    const target = raw.split('#')[0];
    if (!target) continue;

    let ok: boolean;
    if (target.startsWith('/docs')) {
      ok = routeExists(target);
    } else if (target.startsWith('/')) {
      ok = existsSync(join('public', target)); // public asset
    } else {
      ok = existsSync(resolve(dirname(file), target)); // relative file (e.g. TypeDoc cross-ref)
    }

    if (!ok) {
      console.error(`✗ ${file} → ${raw}`);
      broken++;
    }
  }
}

if (broken > 0) {
  console.error(`\n${broken} broken link(s) found.`);
  process.exit(1);
}
console.log(`✓ no broken links (${files.length} files scanned)`);
