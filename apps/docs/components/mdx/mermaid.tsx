'use client';

// Renders a Mermaid diagram. Dark-only to match the Passage docs theme.
import { useEffect, useId, useState } from 'react';

export function Mermaid({ chart }: { chart: string }) {
  const id = useId();
  const [svg, setSvg] = useState('');

  useEffect(() => {
    let active = true;
    void (async () => {
      const { default: mermaid } = await import('mermaid');
      mermaid.initialize({
        startOnLoad: false,
        theme: 'dark',
        securityLevel: 'loose',
        fontFamily: 'inherit',
      });
      try {
        const { svg } = await mermaid.render(`mermaid-${id.replace(/[^a-zA-Z0-9]/g, '')}`, chart.trim());
        if (active) setSvg(svg);
      } catch {
        // invalid diagram — leave it empty rather than crash the page
      }
    })();
    return () => {
      active = false;
    };
  }, [chart, id]);

  return <div className="my-4 flex justify-center [&_svg]:max-w-full" dangerouslySetInnerHTML={{ __html: svg }} />;
}
