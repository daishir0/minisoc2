import { ExploreTabs } from '@/components/ExploreTabs';
import { Masked, MaskFree } from '@/components/Mask';
import { Card, ago } from '@/components/ui';
import { CategoryChart } from '@/components/CategoryChart';
import { DrillLink } from '@/components/DrillLink';
import { RawLogs } from '@/components/RawLogs';
import { q } from '@/lib/db';
import { rawIngestPaused } from '@/lib/logs';
import { RULES } from '@/lib/rules';
import { getPolicy } from '@/lib/settings';
import { CAT } from '@/lib/logcat';
import { alertFormAction, trustIp } from '../actions';

const RULE_TITLE = Object.fromEntries(RULES.map((r) => [r.id, r.title]));
const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}:[0-9a-f:]{2,38})(?!.*\d{1,3}(?:\.\d{1,3}){3})/i;
const fmtBytes = (b: number) => (b >= 1 << 30 ? (b / (1 << 30)).toFixed(1) + ' GB' : b >= 1 << 20 ? (b / (1 << 20)).toFixed(1) + ' MB' : b >= 1024 ? Math.round(b / 1024) + ' KB' : b + ' B');

export default async function LogsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const policy = await getPolicy();
  const paused = await rawIngestPaused();
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  const hostOk = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;
  const hc = hostOk ? 'AND host_id=$1' : '';
  const hp = hostOk ? [hostOk] : [];

  const threats = await q<{ id: string; host: string | null; host_id: string | null; title: string; created_at: Date }>(
    `SELECT a.id, h.name AS host, a.host_id, a.title, a.created_at FROM alerts a LEFT JOIN hosts h ON h.id=a.host_id
     WHERE a.kind='log' AND a.status='open' AND a.created_at > now() - interval '24 hours' ${hostOk ? 'AND a.host_id=$1' : ''} ORDER BY a.created_at DESC`, hp);

  const catDays = await q<{ day: string; web: string; auth: string; audit: string; sys: string }>(
    `SELECT to_char(day,'YYYY-MM-DD') AS day,
       coalesce(sum(lines) FILTER (WHERE ${CAT.web}),0) web, coalesce(sum(lines) FILTER (WHERE ${CAT.auth}),0) auth,
       coalesce(sum(lines) FILTER (WHERE ${CAT.audit}),0) audit, coalesce(sum(lines) FILTER (WHERE ${CAT.sys}),0) sys
     FROM log_daily WHERE day > current_date - 30 ${hc} GROUP BY day ORDER BY day`, hp);

  const web = await q<{ vhost: string; req: string; c4: string; c5: string; bytes: string }>(
    `SELECT vhost, sum(req) req, sum(c4xx) c4, sum(c5xx) c5, sum(bytes) bytes FROM web_daily
     WHERE day=(SELECT max(day) FROM web_daily) ${hostOk ? 'AND host_id=$1' : ''} GROUP BY vhost ORDER BY req DESC LIMIT 8`, hp);

  const authRows = await q<{ rule_id: string; n: string }>(
    `SELECT rule_id, sum(hits) n FROM log_rule_daily WHERE day > current_date - 7
       AND rule_id IN ('ssh_accept_new_ip','ssh_bruteforce','sudo_new_user','sudo_auth_failure') ${hc} GROUP BY rule_id`, hp);
  const authN = (id: string) => Number(authRows.find((r) => r.rule_id === id)?.n ?? 0);
  const brute = await q<{ grp: string; n: string }>(
    `SELECT grp, count(*) n FROM log_hits WHERE rule_id='ssh_bruteforce' AND ts > now() - interval '7 days' ${hostOk ? 'AND host_id=$1' : ''} AND grp<>'' GROUP BY grp ORDER BY 2 DESC LIMIT 3`, hp);

  const ruleTop = await q<{ rule_id: string; wk: string; prev: string }>(
    `SELECT rule_id, coalesce(sum(hits) FILTER (WHERE day > current_date - 7),0) wk, coalesce(sum(hits) FILTER (WHERE day <= current_date - 7),0) prev
     FROM log_rule_daily WHERE day > current_date - 14 ${hc} GROUP BY rule_id
     HAVING sum(hits) FILTER (WHERE day > current_date - 7) > 0 ORDER BY wk DESC LIMIT 8`, hp);
  const rsRows = await q<{ rule_id: string; day: string; hits: string }>(
    `SELECT rule_id, to_char(day,'YYYY-MM-DD') AS day, sum(hits) AS hits FROM log_rule_daily WHERE day > current_date - 14 ${hc} GROUP BY rule_id, day`, hp);
  const dayKeys = Array.from({ length: 14 }, (_, i) => new Date(Date.now() - (13 - i) * 86400_000).toISOString().slice(0, 10));
  const series = (ruleId: string) => { const m = new Map(rsRows.filter((r) => r.rule_id === ruleId).map((r) => [r.day, Number(r.hits)])); return dayKeys.map((d) => m.get(d) ?? 0); };
  const sigmaTitles = Object.fromEntries((await q<{ id: string; title: string }>('SELECT id, title FROM sigma_rules')).map((r) => [r.id, `Sigma: ${r.title}`]));
  const title = (id: string) => RULE_TITLE[id] ?? sigmaTitles[id] ?? id;
  const sigmaFeed = (await q<{ item_count: number | null }>("SELECT item_count FROM feed_status WHERE name='sigma'"))[0];

  const heat = await q<{ host_id: string; name: string; day: string; n: string }>(
    `SELECT l.host_id, h.name, to_char(l.day,'YYYY-MM-DD') AS day, sum(l.lines) AS n FROM log_daily l JOIN hosts h ON h.id=l.host_id
     WHERE l.day > current_date - 14 ${hostOk ? 'AND l.host_id=$1' : ''} GROUP BY l.host_id, h.name, l.day`, hp);
  const hmHosts = [...new Map(heat.map((r) => [r.host_id, r.name])).entries()];
  const hmDays = [...new Set(heat.map((r) => r.day))].sort();
  const hmVal = new Map(heat.map((r) => [`${r.host_id}|${r.day}`, Number(r.n)]));
  const hostMax = new Map(hmHosts.map(([id]) => [id, Math.max(1, ...hmDays.map((d) => hmVal.get(`${id}|${d}`) ?? 0))]));
  const heatColor = (rel: number) => rel <= 0 ? 'var(--bg)' : rel < 0.35 ? '#cfe6e8' : rel < 0.6 ? '#8fcbd0' : rel < 0.85 ? '#f6c343' : '#e8743b';

  // props for the client raw viewer
  const hostMap = Object.fromEntries(hosts.map((h) => [h.id, h.name]));
  const ruleTitleMap = Object.fromEntries([...RULES.map((r) => [r.id, r.title]), ...Object.entries(sigmaTitles)]);
  const sevClear = { source: '', vhost: '', rule: '', q: '', status: '', day: '' } as const;

  const Spark = ({ v }: { v: number[] }) => {
    const W = 80, H = 20, max = Math.max(1, ...v);
    const pts = v.map((x, i) => `${(i / (v.length - 1)) * W},${H - (x / max) * (H - 2) - 1}`).join(' ');
    return <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: 80, height: 20 }} aria-hidden="true"><polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth="1.3" vectorEffect="non-scaling-stroke" /></svg>;
  };

  return (
    <>
      <ExploreTabs />
      {paused && (
        <div className="rounded-md border border-orange-400 bg-orange-50 px-4 py-3 text-sm text-orange-900 dark:bg-orange-950 dark:text-orange-100">
          ディスク使用率が上限（{policy.diskGuardPercent}%）を超えたため、生ログの保存を停止しています。ルール判定と集計は続けています。
        </div>
      )}

      <form className="flex flex-wrap items-center gap-2 text-sm" action="/logs">
        <span className="text-xs text-muted">ホスト</span>
        <select name="host" defaultValue={hostOk ?? ''} className="input sm:w-auto">
          <option value="">すべて</option>
          {hosts.map((h) => <option key={h.id} value={h.id}><Masked kind="host">{h.name}</Masked></option>)}
        </select>
        <button className="btn">表示</button>
        <span className="ml-auto text-xs text-muted">俯瞰の棒・凡例・セル・ルールをクリック → 下の生ログがその場で切り替わります</span>
      </form>

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

      {/* A */}
      <Card title="ログ量の推移（30日・カテゴリ別）">
        <CategoryChart host={hostOk ?? ''} points={catDays.map((d) => ({ day: d.day, web: Number(d.web), auth: Number(d.auth), audit: Number(d.audit), sys: Number(d.sys) }))} />
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* D web */}
        <Card title="Web の俯瞰（最新日・サイト別）">
          <div className="mb-3 flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-muted">ステータスで絞る：</span>
            {[['2xx', 'text-green-700'], ['3xx', 'text-muted'], ['4xx', 'text-amber-700'], ['5xx', 'text-red-700']].map(([s, c]) => (
              <DrillLink key={s} patch={{ host: hostOk ?? '', cat: 'web', status: s, source: '', vhost: '', rule: '', q: '', day: '' }} className={`rounded-full border border-line px-2 py-0.5 ${c} hover:border-accent`}>{s}</DrillLink>
            ))}
          </div>
          {web.length === 0 ? <p className="text-sm text-muted">Webアクセスログの集計がありません。</p> : (
            <div className="overflow-x-auto"><table className="tbl">
              <thead><tr><th>サイト</th><th className="text-right">req</th><th>エラー率</th><th className="text-right">転送</th></tr></thead>
              <tbody>
                {web.map((w) => { const req = Number(w.req), err = req ? ((Number(w.c4) + Number(w.c5)) / req) * 100 : 0; const col = err >= 5 ? 'text-red-600' : err >= 2 ? 'text-amber-600' : 'text-green-600';
                  return (
                    <tr key={w.vhost}>
                      <td><DrillLink patch={{ host: hostOk ?? '', cat: 'web', vhost: w.vhost, source: '', status: '', rule: '', q: '', day: '' }} className="text-left text-accent">{w.vhost}</DrillLink></td>
                      <td className="whitespace-nowrap text-right font-mono">{req.toLocaleString()}</td>
                      <td className="whitespace-nowrap"><span className={`font-mono ${col}`}>{err.toFixed(1)}%</span>{Number(w.c5) > 0 && <DrillLink patch={{ host: hostOk ?? '', cat: 'web', vhost: w.vhost, status: '5xx', source: '', rule: '', q: '', day: '' }} className="ml-2 text-xs text-accent">5xx {w.c5}</DrillLink>}</td>
                      <td className="whitespace-nowrap text-right font-mono">{fmtBytes(Number(w.bytes))}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table></div>
          )}
        </Card>

        {/* C auth */}
        <Card title="認証の俯瞰（7日）">
          <div className="grid grid-cols-2 gap-2 text-sm">
            {([['SSH初見IP成功', authN('ssh_accept_new_ip'), 'Accepted', 'text-red-600'], ['SSH失敗集中', authN('ssh_bruteforce'), 'Failed', 'text-amber-600'], ['sudo初見ユーザー', authN('sudo_new_user'), 'COMMAND=', 'text-muted'], ['sudo認証失敗', authN('sudo_auth_failure'), 'authentication failure', 'text-amber-600']] as [string, number, string, string][]).map(([label, n, qq, col]) => (
              <DrillLink key={label} patch={{ host: hostOk ?? '', cat: 'auth', q: qq, source: '', vhost: '', rule: '', status: '', day: '' }} className="rounded-lg border border-line bg-bg p-3 text-left hover:border-accent">
                <div className="text-xs text-muted">{label}</div><div className={`font-mono text-xl font-bold ${n ? col : 'text-muted'}`}>{n}</div>
              </DrillLink>
            ))}
          </div>
          {brute.length > 0 && (
            <div className="mt-3"><p className="mb-1 text-xs font-semibold">失敗元の上位IP（7日）</p>
              <ul className="divide-y divide-line text-sm">
                {brute.map((b) => <li key={b.grp} className="flex items-center justify-between py-1.5"><DrillLink patch={{ host: hostOk ?? '', cat: 'auth', q: b.grp, source: '', vhost: '', rule: '', status: '', day: '' }} className="font-mono text-accent"><Masked kind="addr">{b.grp}</Masked></DrillLink><span className="font-mono text-xs text-muted">×{b.n}</span></li>)}
              </ul>
            </div>
          )}
        </Card>
      </div>

      {/* E rule top + sparkline */}
      <Card title="検知ルール Top（7日・前週比／右は14日の推移）" right={<span className="text-xs text-muted">Sigma {sigmaFeed?.item_count ?? 0} ルール適用中</span>}>
        {ruleTop.length === 0 ? <p className="text-sm text-muted">一致はありません。</p> : (
          <ul className="space-y-1.5">
            {ruleTop.map((r) => { const wk = Number(r.wk), d = wk - Number(r.prev), max = Math.max(1, ...ruleTop.map((x) => Number(x.wk)));
              return (
                <li key={r.rule_id} className="grid grid-cols-[1fr_auto_auto_auto] items-center gap-3">
                  <div className="min-w-0"><DrillLink patch={{ host: hostOk ?? '', rule: r.rule_id, cat: '', source: '', vhost: '', status: '', q: '', day: '' }} className="block truncate text-left text-sm text-accent hover:underline">{title(r.rule_id)}</DrillLink>
                    <div className="mt-1 h-2 rounded" style={{ background: 'var(--soft)' }}><div className="h-full rounded" style={{ width: `${Math.max(4, (wk / max) * 100)}%`, background: 'var(--accent)' }} /></div></div>
                  <Spark v={series(r.rule_id)} />
                  <span className="font-mono text-sm tabular-nums">{wk.toLocaleString()}</span>
                  <span className={`font-mono text-xs tabular-nums ${d > 0 ? 'text-red-600' : d < 0 ? 'text-green-600' : 'text-muted'}`}>{d > 0 ? '▲' : d < 0 ? '▼' : '－'}{Math.abs(d)}</span>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {/* B heatmap */}
      {hmHosts.length > 0 && hmDays.length > 1 && (
        <Card title="ホスト×日 ログ量ヒートマップ（14日・各ホストの平常比）">
          <div className="space-y-1 text-xs">
            {hmHosts.map(([id, name]) => (
              <div key={id} className="grid items-center gap-1.5" style={{ gridTemplateColumns: '84px 1fr' }}>
                <DrillLink patch={{ host: id, cat: '', source: '', vhost: '', status: '', rule: '', q: '', day: '' }} className="truncate text-left font-mono text-accent"><Masked kind="host">{name}</Masked></DrillLink>
                <div className="grid gap-0.5" style={{ gridTemplateColumns: `repeat(${hmDays.length}, 1fr)` }}>
                  {hmDays.map((dd) => { const v = hmVal.get(`${id}|${dd}`) ?? 0; const rel = v / (hostMax.get(id) ?? 1);
                    return <DrillLink key={dd} patch={{ host: id, day: dd, cat: '', source: '', vhost: '', status: '', rule: '', q: '' }} title={`${name} ${dd}: ${v.toLocaleString()}行 → この日の生ログ`} className="block w-full" ><span className="block" style={{ aspectRatio: '1', borderRadius: 3, background: heatColor(rel) }} /></DrillLink>;
                  })}
                </div>
              </div>
            ))}
            <div className="grid gap-1.5" style={{ gridTemplateColumns: '84px 1fr' }}><span /><div className="flex justify-between text-[11px] text-muted"><span>14日前</span><span>今日</span></div></div>
          </div>
        </Card>
      )}

      {/* raw logs (client, in-place) */}
      <div id="raw" className="scroll-mt-20">
        <Card title={`生ログ（条件連動・最大300行／保存 ${policy.logRetentionDays}日）`}>
          <RawLogs hosts={hostMap} ruleTitles={ruleTitleMap} retentionDays={policy.logRetentionDays} />
        </Card>
      </div>
    </>
  );
}
