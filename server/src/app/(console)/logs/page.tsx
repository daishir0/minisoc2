import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, ago } from '@/components/ui';
import { RawLogs } from '@/components/RawLogs';
import { LogExplorer } from '@/components/LogExplorer';
import { LogThreatPicker } from '@/components/LogThreatPicker';
import { q } from '@/lib/db';
import { rawIngestPaused } from '@/lib/logs';
import { RULES } from '@/lib/rules';
import { getPolicy } from '@/lib/settings';
import { alertFormAction, trustIp, reviewLogThreatBenign } from '../actions';

const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}:[0-9a-f:]{2,38})(?!.*\d{1,3}(?:\.\d{1,3}){3})/i;

export default async function LogsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const policy = await getPolicy();
  const paused = await rawIngestPaused();
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  const hostOk = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;

  const threats = await q<{ id: string; host: string | null; host_id: string | null; title: string; detail: string | null; address: string; created_at: Date; dedupe_key: string }>(
    `SELECT a.id, h.name AS host, a.host_id, a.title, a.detail, a.dedupe_key,
       COALESCE(CASE WHEN h.kind='pull' THEN pt.ssh_host ELSE h.hostname END, '') AS address, a.created_at
     FROM alerts a LEFT JOIN hosts h ON h.id=a.host_id LEFT JOIN pull_targets pt ON pt.host_id=h.id
     WHERE a.kind='log' AND a.status='open' AND a.created_at > now() - interval '24 hours' ${hostOk ? 'AND a.host_id=$1' : ''} ORDER BY a.created_at DESC`, hostOk ? [hostOk] : []);
  // Topic = the alert's dedupe stem without the trailing date; a benign review on it downgrades future
  // recurrences. Only recon / app-errors (and journal recon) are offered the benign action.
  const topicOf = (k: string) => k.replace(/:\d{4}-\d{2}-\d{2}$/, '');

  const sigmaTitles = Object.fromEntries((await q<{ id: string; title: string }>('SELECT id, title FROM sigma_rules')).map((r) => [r.id, `Sigma: ${r.title}`]));
  const hostMap = Object.fromEntries(hosts.map((h) => [h.id, h.name]));
  const ruleTitleMap = Object.fromEntries([...RULES.map((r) => [r.id, r.title]), ...Object.entries(sigmaTitles)]);
  const vhostList = (await q<{ vhost: string }>("SELECT DISTINCT vhost FROM web_daily WHERE day > current_date - 35 ORDER BY vhost")).map((r) => r.vhost);

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
          <LogThreatPicker
            threats={threats.map((t) => {
              const topic = topicOf(t.dedupe_key);
              return {
                id: t.id, host: t.host, hostId: t.host_id, address: t.address,
                title: t.title, detail: t.detail, agoText: ago(t.created_at),
                ip: t.title.match(IP_RE)?.[1] ?? null,
                // offer "benign (downgrade future)" only for the downgradeable classes, and not if already downgraded
                topic, benignReviewable: /:(recon|app-errors)$/.test(topic) && !t.dedupe_key.startsWith('logack:'),
              };
            })}
            ackAction={alertFormAction}
            trustAction={trustIp}
            benignAction={reviewLogThreatBenign}
          />
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
