import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Timeline } from '@/components/Timeline';
import { Card } from '@/components/ui';
import { q } from '@/lib/db';
import { timeline } from '@/lib/timeline';

const KINDS: [string, string][] = [
  ['', 'すべての種類'], ['kev_added', 'KEV入り'], ['vuln_new', '新しい脆弱性'], ['vuln_resolved', '解消'], ['system_new', 'システム追加・基準線'],
  ['host_state', 'ホストの変化'], ['log', 'ログの検知'], ['feed', '脆弱性情報'], ['health', '監視の健全性'], ['ops', '運用の記録'],
];

export default async function ChangesPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const all = sp.all === '1';
  const days = [7, 30, 90, 180].includes(Number(sp.days)) ? Number(sp.days) : 30;
  const hostId = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;
  const kind = KINDS.some(([k]) => k && k === sp.kind) ? sp.kind : undefined;
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  const groups = await timeline({ days, importantOnly: !all, hostId, kind });
  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: "検知" }]} />
      <ExploreTabs />
    <Card title="変化の履歴">
      <form className="mb-4 grid grid-cols-2 gap-2 text-sm sm:flex sm:flex-wrap" action="/changes">
        <select name="days" defaultValue={String(days)} className="input sm:w-auto">{[7, 30, 90, 180].map((d) => <option key={d} value={d}>{d}日</option>)}</select>
        <select name="host" defaultValue={hostId ?? ''} className="input sm:w-auto"><option value="">全ホスト</option>{hosts.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}</select>
        <select name="kind" defaultValue={kind ?? ''} className="input sm:w-auto">{KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        <label className="flex items-center gap-1"><input type="checkbox" name="all" value="1" defaultChecked={all} /> 高以下・運用の記録も表示</label>
        <button className="btn">表示</button>
      </form>
      <p className="mb-3 text-xs text-muted">
        {all ? 'すべての変化を表示しています。' : '重要な変化（KEV・緊急・侵入の兆候・監視の停止）だけを表示しています。'}
        日ごとの上位5件を表示し、残りは畳んでいます。{!all && <Link className="ml-1 text-accent" href={`/changes?days=${days}&all=1`}>すべて表示</Link>}
      </p>
      <Timeline groups={groups} days={days} perDay={5} />
    </Card>
    </>
  );
}
