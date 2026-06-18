import { source } from '@/lib/source';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { baseOptions } from '@/lib/layout.shared';
import { VersionBadge } from '@/components/version-badge';

export default function Layout({ children }: LayoutProps<'/docs'>) {
  return (
    <DocsLayout
      tree={source.getPageTree()}
      sidebar={{ banner: <VersionBadge /> }}
      {...baseOptions()}
    >
      {children}
    </DocsLayout>
  );
}
