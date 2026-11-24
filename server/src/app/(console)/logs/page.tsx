import { ExploreTabs } from '@/components/ExploreTabs';
import { Masked, MaskFree } from '@/components/Mask';
import { Card, ago } from '@/components/ui';
import { DrillLink } from '@/components/DrillLink';
import { RawLogs } from '@/components/RawLogs';
import { LogExplorer } from '@/components/LogExplorer';
import { q } from '@/lib/db';
import { rawIngestPaused } from '@/lib/logs';
import { RULES } from '@/lib/rules';
import { getPolicy } from '@/lib/settings';
import { alertFormAction, trustIp } from '../actions';

const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}:[0-9a-f:]{2,38})(?!.*\d{1,3}(?:\.\d{1,3}){3})/i;

export default async function LogsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const policy = await getPolicy();
  const paused = await rawIngestPaused();
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  const hostOk = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;

  const threats = await q<{ id: string; host: string | null; host_id: string | null; title: string; created_at: Date }>(
    `SELECT a.id, h.name AS host, a.host_id, a.title, a.created_at FROM alerts a LEFT JOIN hosts h ON h.id=a.host_id
     WHERE a.kind='log' AND a.status='open' AND a.created_at > now() - interval '24 hours' ${hostOk ? 'AND a.host_id=$1' : ''} ORDER BY a.created_at DESC`, hostOk ? [hostOk] : []);

  const sigmaTitles = Object.fromEntries((await q<{ id: string; title: string }>('SELECT id, title FROM sigma_rules')).map((r) => [r.id, `Sigma: ${r.title}`]));
  const hostMap = Object.fromEntries(hosts.map((h) => [h.id, h.name]));
  const ruleTitleMap = Object.fromEntries([...RULES.map((r) => [r.id, r.title]), ...Object.entries(sigmaTitles)]);
  const vhostList = (await q<{ vhost: string }>("SELECT DISTINCT vhost FROM web_daily WHERE day > current_date - 35 ORDER BY vhost")).map((r) => r.vhost);
  const sevClear = { source: '', vhost: '', rule: '', q: '', status: '', day: '' } as const;

  return (
    <>
      <ExploreTabs />
      {paused && (
        <div className="rounded-md border border-orange-400 bg-orange-50 px-4 py-3 text-sm text-orange-900 dark:bg-orange-950 dark:text-orange-100">
          ディスク使用率が上限（{policy.diskGuardPercent}%）を超えたため、生ログの保存を停止しています。ルール判定と集計は続けています。
        </div>
      )}

      <Card title={`ログ脅威（直近24時間・未対応 ${threats.length}件）`}>
        {threats.length === 0 ? <p className="text-sm text-green-600">✅ 直近24時間に未対応のログ脅威はありません。</p> : (
          <ul className="divide-y divide-line">
            {threats.map((t) => {
              const ip = t.title.match(IP_RE)?.[1];
              return (
                <li key={t.id} className="flex flex-col gap-2 py-2 sm:flex-row sm:items-start sm:gap-3">
                  <div className="min-w-0 flex-1"><div className="text-sm"><span className="mr-1">⚠</span><MaskFree>{t.title}</MaskFree></div>
                    <div className="text-xs text-muted">{t.host ? <><Masked kind="host">{t.host}</Masked> · </> : ''}{ago(t.created_at)}</div></div>
                  <div className="flex flex-wrap gap-1 sm:shrink-0">
                    {ip && <form action={trustIp}><input type="hidden" name="id" value={t.id} /><input type="hidden" name="ip" value={ip} /><button className="btn-ghost">自分です（<Masked kind="addr">{ip}</Masked>）</button></form>}
                    {t.host_id && <DrillLink patch={{ host: t.host_id, ...sevClear, cat: '' }} className="btn-ghost">調べる</DrillLink>}
                    <form action={alertFormAction}><input type="hidden" name="id" value={t.id} /><button name="status" value="ack" className="btn-ghost">確認済み</button></form>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {/* One BI panel: measure × dimension × chart, drill-down to the raw logs below */}
      <Card title="ログエクスプローラ">
        <LogExplorer hosts={hostMap} ruleTitles={ruleTitleMap} />
      </Card>

      {/* raw logs (client, in-place) */}
      <div id="raw" className="scroll-mt-20">
        <Card title={`生ログ（条件連動・最大300行／保存 ${policy.logRetentionDays}日）`}>
          <RawLogs hosts={hostMap} ruleTitles={ruleTitleMap} vhosts={vhostList} retentionDays={policy.logRetentionDays} />
        </Card>
      </div>
    </>
  );
}
