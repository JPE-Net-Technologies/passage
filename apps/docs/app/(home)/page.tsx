import Link from 'next/link';

const partners = ['Supabase', 'Fly.io', 'Neon', 'Vercel', 'Cloudflare', 'Redis', 'Snyk', 'Resend'];

const principles = [
  {
    c: 'Correctness',
    d: 'Security is the product. The core holds 100% line coverage and 100% mutation-kill gates, and conforms to the OAuth2/OIDC security specs.',
  },
  {
    c: 'Customization',
    d: 'Declarative YAML and injectable seams give deep flex. Integrate trusted partners instead of rebuilding.',
  },
  {
    c: 'Cognitive-Overhead-Awareness',
    d: 'Secure by default — you only have to think when you deliberately choose to flex. Low cognitive load is a feature.',
  },
];

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col" style={{ color: 'var(--p-text)' }}>
      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden border-b" style={{ borderColor: 'var(--p-border)' }}>
        <div
          className="p-grid pointer-events-none absolute inset-0"
          style={{ maskImage: 'radial-gradient(ellipse 70% 60% at 50% 0%, #000 30%, transparent 75%)' }}
        />
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-[420px] opacity-40"
          style={{ background: 'radial-gradient(ellipse 60% 100% at 50% 0%, rgba(40,215,229,0.12), transparent 70%)' }}
        />
        <div className="relative mx-auto max-w-3xl px-6 py-24 text-center sm:py-28">
          <span
            className="inline-flex items-center gap-2 rounded-full border px-4 py-1.5 font-mono text-xs tracking-wide"
            style={{ borderColor: 'var(--p-border-strong)', background: 'var(--p-bg-1)', color: 'var(--p-text-2)' }}
          >
            <span className="size-1.5 rounded-full" style={{ background: 'var(--p-safe)' }} />
            MIT · SELF-HOSTED · OAuth2 / OIDC / SAML
          </span>

          <h1 className="mt-8 text-5xl font-bold leading-[1.05] sm:text-6xl">
            The passage to identity —
            <br />
            <span className="p-gradient-text">and everything beyond.</span>
          </h1>

          <p className="mx-auto mt-6 max-w-2xl text-lg" style={{ color: 'var(--p-text-2)' }}>
            The self-hosted identity broker that grows into a hub for secure web development. Rigid by
            default, customizable when you flex — <strong style={{ color: 'var(--p-text)' }}>the Terraform of your dev practices</strong>.
          </p>

          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/docs"
              className="rounded-lg px-5 py-2.5 font-medium transition-transform hover:-translate-y-0.5"
              style={{ background: 'var(--p-grad)', color: 'var(--p-accent-ink)' }}
            >
              Get started →
            </Link>
            <Link
              href="/docs/federation/manual"
              className="rounded-lg border px-5 py-2.5 font-medium transition-colors hover:border-[var(--p-border-strong)]"
              style={{ borderColor: 'var(--p-border)', color: 'var(--p-text)' }}
            >
              Read the manual
            </Link>
          </div>
        </div>
      </section>

      {/* ── Cookbook / partners ──────────────────────────────────────────── */}
      <section className="mx-auto w-full max-w-5xl px-6 py-16">
        <p className="font-mono text-xs tracking-widest" style={{ color: 'var(--p-accent)' }}>
          THE COOKBOOK · INTEGRATE, DON&apos;T REBUILD
        </p>
        <p className="mt-3 max-w-2xl text-lg" style={{ color: 'var(--p-text-2)' }}>
          Trusted projects, wired in as tested add-on modules.{' '}
          <span style={{ color: 'var(--p-text-3)' }}>Roadmap — not shipped yet.</span>
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          {partners.map((p) => (
            <span
              key={p}
              className="rounded-lg border px-4 py-2 font-mono text-sm"
              style={{ borderColor: 'var(--p-border)', background: 'var(--p-bg-1)', color: 'var(--p-text-2)' }}
            >
              {p}
            </span>
          ))}
        </div>
      </section>

      {/* ── The Three C's ────────────────────────────────────────────────── */}
      <section className="mx-auto w-full max-w-5xl px-6 pb-24">
        <h2 className="text-2xl font-bold">The Three C&apos;s</h2>
        <div className="mt-8 grid gap-4 sm:grid-cols-3">
          {principles.map((p, i) => (
            <div
              key={p.c}
              className="rounded-xl border p-6"
              style={{ borderColor: 'var(--p-border)', background: 'var(--p-bg-1)' }}
            >
              <span className="font-mono text-sm" style={{ color: 'var(--p-accent)' }}>
                C{i + 1}
              </span>
              <h3 className="mt-2 text-lg font-semibold">{p.c}</h3>
              <p className="mt-2 text-sm" style={{ color: 'var(--p-text-2)' }}>
                {p.d}
              </p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
