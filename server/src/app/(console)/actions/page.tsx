import Link from 'next/link';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { EXPOSURE } from '@/lib/systemmeta';
import { listTasks, openDetections } from '@/lib/tasks';
import { ackDetection, trustIp } from '../actions';

const STATUS: Record<string, string> = { todo: '未着手', doing: '対応中', hold: '保留' };
const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}:[0-9a-f:]{2,38})(?!.*\d{1,3}(?:\.\d{1,3}){3})/i;

export default async function ActionsPage({ searchParams }: { searchParams: Promise<{ host?: string; show?: string }> }) {
  const sp = await searchParams;
  const hostId = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;
  const all = await listTasks({ hostId });
  const showHold = sp.show === 'hold';
  const tasks = all.filter((t) => (showHold ? t.status === 'hold' && !t.overdue : t.status !== 'hold' || t.overdue));
  const held = all.filter((t) => t.status === 'hold' && !t.overdue).length;
  const kev = all.reduce((s, t) => s + t.kev, 0);
  const crit = all.reduce((s, t) => s + t.critical, 0);
  const det = await openDetections();
  const reviews = await q<{ id: number; system_id: number; pattern: string; name: string; host: string; review: string }>(
    `SELECT e.id, e.system_id, e.pattern, s.name, h.name AS host, to_char(e.review_date, 'YYYY-MM-DD') AS review
     FROM system_excludes e JOIN systems s ON s.id=e.system_id JOIN hosts h ON h.id=s.host_id
     WHERE e.review_date IS NOT NULL AND e.review_date <= current_date ORDER BY e.review_date`,
  );

  return (
    <>
      <div>
        <h1 className="text-xl font-semibold">対応</h1>
        <p className="mt-1 text-sm text-muted">
          {all.length ? <>{all.length}件の作業で KEV {kev}件・緊急 {crit}件を解消できます。1行が1回の作業です。</> : 'KEV・緊急の未対応はありません。'}
          {hostId && <Link href="/actions" className="ml-2 text-accent">全ホストを表示</Link>}
        </p>
      </div>

      <Card title={showHold ? `保留中の作業（${held}）` : '脆弱性の修正'} right={held ? <Link href={showHold ? '/actions' : '/actions?show=hold'} className="text-xs text-accent">{showHold ? '作業一覧に戻る' : `保留中 ${held}件`}</Link> : undefined}>
        {tasks.length === 0 ? <p className="text-sm text-muted">{showHold ? '保留中の作業はありません。' : 'いま必要な作業はありません。'}</p> : (
          <ul className="divide-y divide-line">
            {tasks.map((t) => (
              <li key={t.key} className="py-3">
                <Link href={`/actions/${t.key}`} className="block">
                  <div className="flex flex-wrap items-center gap-2">
                    <span>{t.kev ? '🔴' : '🟠'}</span>
                    <span className="font-medium text-accent">{t.root === '__os__' ? `${t.host} OS` : `${t.host}／${t.name}`}</span>
                    {t.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 py-0.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
                    {t.status !== 'todo' && <span className={`rounded px-1.5 py-0.5 text-[11px] ${t.overdue ? 'bg-red-600 text-white' : 'bg-bg text-muted'}`}>{t.overdue ? '保留の期限切れ' : STATUS[t.status]}{t.owner ? `・${t.owner}` : ''}{t.due && !t.overdue ? `・${t.due}まで` : ''}</span>}
                  </div>
                  <div className="mt-1 break-words pl-7 text-sm">
                    {t.packages.slice(0, 4).map((p) => (t.root === '__os__' ? p.name.replace(/^(kernel)[\w-]*$/, '$1') : `${p.name}${p.target ? ` → ${p.target}` : ''}`)).filter((v, i, a) => a.indexOf(v) === i).join('、')}
                    {t.packages.length > 4 && ` ほか${t.packages.length - 4}`}
                  </div>
                  <div className="mt-0.5 pl-7 text-xs text-muted">
                    → {t.kev ? <b className="text-red-600">KEV {t.kev}</b> : null}{t.kev && t.critical ? '・' : ''}{t.critical ? `緊急 ${t.critical}` : ''} を解消{t.reboot ? '／再起動が必要' : ''}
                  </div>
                  {t.protects.length > 0 && (
                    <div className="mt-0.5 break-words pl-7 text-xs text-muted">
                      守る：{t.protects.slice(0, 4).map((p) => p.name).join('、')}{t.protects.length > 4 ? ` ほか${t.protects.length - 4}` : ''}
                    </div>
                  )}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {reviews.length > 0 && (
        <Card title={`除外の見直し（期限到来 ${reviews.length}件）`}>
          <ul className="divide-y divide-line text-sm">
            {reviews.map((r) => (
              <li key={r.id} className="py-2"><Link href={`/systems/${r.system_id}`} className="text-accent">{r.host}／{r.name}</Link>：<span className="font-mono">{r.pattern}</span><span className="ml-2 text-xs text-muted">期限 {r.review}</span></li>
            ))}
          </ul>
        </Card>
      )}

      <Card title={`検知（侵入の兆候・監視の停止）${det.length ? `：${det.length}件` : ''}`} right={<Link href="/alerts" className="text-xs text-accent">記録をすべて見る</Link>}>
        {det.length === 0 ? <p className="text-sm text-muted">確認が必要な検知はありません。</p> : (
          <ul className="divide-y divide-line">
            {det.map((d) => {
              const ip = d.kind === 'log' ? d.title.match(IP_RE)?.[1] : undefined;
              return (
                <li key={d.id} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm"><span className="mr-1">⚠</span>{d.title}</div>
                    <div className="text-xs text-muted">{ago(d.created_at)}{d.detail ? ` · ${d.detail.split('\n')[0].slice(0, 120)}` : ''}</div>
                  </div>
                  <div className="flex flex-wrap gap-2 pl-6 sm:pl-0">
                    {ip && (
                      <form action={trustIp}>
                        <input type="hidden" name="id" value={d.id} /><input type="hidden" name="ip" value={ip} />
                        <button className="btn-ghost" title="このIPを既知として登録し、今後は通知しません">自分です（{ip}）</button>
                      </form>
                    )}
                    <form action={ackDetection}><input type="hidden" name="id" value={d.id} /><button className="btn-ghost">確認済み</button></form>
                    {d.host_id && <Link href={`/logs?host=${d.host_id}`} className="btn-ghost">調べる</Link>}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </>
  );
}
