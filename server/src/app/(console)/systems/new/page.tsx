import { Card } from '@/components/ui';
import { q } from '@/lib/db';
import { SystemForm } from '../SystemForm';

export default async function NewSystemPage({ searchParams }: { searchParams: Promise<{ host?: string; root?: string }> }) {
  const sp = await searchParams;
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  return (
    <Card title="システムを登録">
      <p className="mb-4 text-sm text-muted">
        通常はエージェントが自動で検出するので登録は不要です。自動検出の区切りが実態と違うとき（1つのフォルダに複数のシステムがある、深い階層にあるなど）に使います。
      </p>
      <SystemForm v={{ hostId: sp.host, root: sp.root }} hosts={hosts} />
    </Card>
  );
}
