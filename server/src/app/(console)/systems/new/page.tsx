import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import { Card } from '@/components/ui';
import { q } from '@/lib/db';
import { SystemForm } from '../SystemForm';

export default async function NewSystemPage({ searchParams }: { searchParams: Promise<{ host?: string; root?: string }> }) {
  const sp = await searchParams;
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  return (
    <>
      <Breadcrumbs items={[CRUMB.home, CRUMB.assets, { label: 'プロジェクトを手動登録' }]} />
    <Card title="プロジェクトを登録">
      <p className="mb-4 text-sm text-muted">
        評価（SBOM・脆弱性・改ざん検知）は登録済みプロジェクトだけに対して行います。通常はエージェントが検出した候補を<b>ホスト画面から登録</b>すれば十分です。このフォームは、候補に出てこない場所を手動で追加したいとき（自動検出の区切りが実態と違う、深い階層にあるなど）に使います。
      </p>
      <SystemForm v={{ hostId: sp.host, root: sp.root }} hosts={hosts} />
    </Card>
    </>
  );
}
