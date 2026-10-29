import Link from 'next/link';
import { Timeline, TrendChart } from '@/components/Timeline';
import { Card, Stat } from '@/components/ui';
import { q } from '@/lib/db';
import { getMail, getSetting } from '@/lib/settings';
import { EXPOSURE } from '@/lib/systemmeta';
import { listTasks, openDetections } from '@/lib/tasks';
import { timeline } from '@/lib/timeline';
import { dismissOnboarding } from './actions';

// Home: the state of things in 30 seconds. Only KEV / critical / detections are surfaced.
export default async function Home() {
  const [t] = await q<{ kev: string; critical: string; stale: string; hosts: string; exposed: string }>(
    `SELECT (SELECT count(*) FROM findings WHERE status='open' AND kev) AS kev,
            (SELECT count(*) FROM findings WHERE status='open' AND NOT kev AND severity='critical') AS critical,
            (SELECT count(*) FROM hosts WHERE stale_alerted AND NOT disabled) AS stale,
            (SELECT count(*) FROM hosts WHERE NOT disabled) AS hosts,
            (SELECT count(*) FROM systems WHERE exposure <> 'unknown') AS exposed`,
  );
  const tasks = (await listTasks()).filter((x) => x.status !== 'hold' || x.overdue);
  const det = await openDetections(5);
  const trend = await q<{ day: string; kev: string; critical: string }>(
    `SELECT to_char(day, 'YYYY-MM-DD') AS day, sum(kev) AS kev, sum(critical) AS critical FROM daily_snapshots ds
     WHERE day > current_date - 30 AND NOT EXISTS (SELECT 1 FROM systems s WHERE s.host_id=ds.host_id AND s.root=ds.system_root AND s.ignored)
     GROUP BY day ORDER BY day`,
  );
  const changes = await timeline({ days: 7, importantOnly: true });
  const mail = await getMail();
  const onboarding = await getSetting<{ dismissed: boolean }>('onboarding', { dismissed: false });
  const steps = [
    { done: mail.enabled, label: 'メール通知を設定する', href: '/settings' },
    { done: Number(t.hosts) > 0, label: '最初のホストを追加する', href: '/enroll' },
    { done: Number(t.exposed) > 0, label: '外部に公開しているシステムの「公開区分」を設定する', href: '/systems' },
  ];
  const showOnboarding = !onboarding.dismissed && steps.some((s) => !s.done);
  const nKev = Number(t.kev), nCrit = Number(t.critical), nStale = Number(t.stale);

  return (
    <>
      {showOnboarding && (
        <Card title="はじめに" right={<form action={dismissOnboarding}><button className="text-xs text-muted">閉じる</button></form>}>
          <ol className="space-y-2 text-sm">
            {steps.map((s, i) => (
              <li key={i} className="flex items-center gap-2">
                <span>{s.done ? '✅' : '⬜'}</span>
                {s.done ? <span className="text-muted line-through">{s.label}</span> : <Link href={s.href} className="text-accent">{s.label}</Link>}
              </li>
            ))}
          </ol>
        </Card>
      )}

      {nKev + nCrit + nStale === 0 ? (
        <Card><p className="text-lg">🟢 KEV・緊急の未対応はありません。報告が止まっているホストもありません（全{t.hosts}台）。</p></Card>
      ) : (
        <div className="grid grid-cols-3 gap-3">
          <Stat label="KEV（悪用確認済み）" value={nKev || '—'} href="/findings?kev=1" tone={nKev ? 'text-red-600' : 'text-muted'} />
          <Stat label="緊急（CVSS 9.0以上）" value={nCrit || '—'} href="/findings?severity=critical" tone={nCrit ? 'text-orange-500' : 'text-muted'} />
          <Stat label={`報告停止（全${t.hosts}台）`} value={nStale || '—'} href="/hosts" tone={nStale ? 'text-orange-500' : 'text-muted'} />
        </div>
      )}

      {(tasks.length > 0 || det.length > 0) && (
        <Card title={`今日の対応（作業 ${tasks.length}件${det.length ? `・検知 ${det.length}件` : ''}）`} right={<Link href="/actions" className="text-xs text-accent">対応へ</Link>}>
          <ul className="divide-y divide-line">
            {det.map((d) => (
              <li key={d.id} className="py-2 text-sm"><Link href="/actions" className="block"><span className="mr-1">⚠</span>{d.title}</Link></li>
            ))}
            {tasks.slice(0, 5).map((x) => (
              <li key={x.key} className="py-2">
                <Link href={`/actions/${x.key}`} className="flex flex-wrap items-center gap-2">
                  <span>{x.kev ? '🔴' : '🟠'}</span>
                  <span className="font-medium text-accent">{x.root === '__os__' ? `${x.host} OS` : `${x.host}／${x.name}`}</span>
                  {x.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 py-0.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
                  <span className="ml-auto text-sm">{x.kev ? <b className="text-red-600">KEV {x.kev}</b> : null}{x.kev && x.critical ? '・' : ''}{x.critical ? <span className="text-orange-600">緊急 {x.critical}</span> : null}</span>
                  {x.protects.length > 0 && <span className="w-full break-words pl-7 text-xs text-muted">守る：{x.protects.slice(0, 3).map((p) => p.name).join('、')}{x.protects.length > 3 ? ` ほか${x.protects.length - 3}` : ''}</span>}
                </Link>
              </li>
            ))}
            {tasks.length > 5 && <li className="py-2 text-sm"><Link href="/actions" className="text-accent">ほか {tasks.length - 5}件の作業</Link></li>}
          </ul>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="最近の変化（7日・重要なもの）" right={<Link href="/changes" className="text-xs text-accent">履歴</Link>}>
          <Timeline groups={changes} days={7} />
        </Card>
        <Card title="推移（30日）">
          <TrendChart points={trend.map((r) => ({ day: r.day, kev: Number(r.kev), critical: Number(r.critical) }))} />
        </Card>
      </div>
    </>
  );
}
