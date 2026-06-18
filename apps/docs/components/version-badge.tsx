// Baked version indicator shown at the top of the docs sidebar. Versioning is a
// single baked label for now; git-tag-driven version snapshots + a real switcher
// land once @passage/core has published tags.
export function VersionBadge() {
  return (
    <div
      className="flex items-center gap-2 rounded-lg border px-3 py-2 font-mono text-sm"
      style={{ borderColor: 'var(--p-border)', background: 'var(--p-bg-1)' }}
    >
      <span className="size-1.5 shrink-0 rounded-full" style={{ background: 'var(--p-safe)' }} />
      <span style={{ color: 'var(--p-text)' }}>v0.1</span>
      <span style={{ color: 'var(--p-text-3)' }}>· preview</span>
    </div>
  );
}
