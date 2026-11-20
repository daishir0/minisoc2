import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Masked, MaskFree } from '@/components/Mask';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { rawIngestPaused } from '@/lib/logs';
import { RULES } from '@/lib/rules';
import { getPolicy } from '@/lib/settings';
import { alertFormAction, trustIp } from '../actions';

const RULE_TITLE = Object.fromEntries(RULES.map((r) => [r.id, r.title]));
const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}:[0-9a-f:]{2,38})(?!.*\d{1,3}(?:\.\d{1,3}){3})/i;

// Source → category. The buckets are what a reader "feels" at a glance; kept as SQL fragments reused by the
// overview and the raw filter (no overlap: access/audit/auth are distinct substrings).
const CAT = {
  web: "source ~* 'access[_.]log'",
  auth: "source ~* 'auth\\.log|secure|sshd|sudo|fail2ban'",
  audit: "source ~* 'audit'",
  sys: "NOT (source ~* 'access[_.]log|auth\\.log|secure|sshd|sudo|fail2ban|audit')",
} as const;
const CAT_LABEL: Record<string, string> = { web: 'Web', auth: '認証', audit: '監査', sys: 'システム' };
const fmtBytes = (b: number) => (b >= 1 << 30 ? (b / (1 << 30)).toFixed(1) + ' GB' : b >= 1 << 20 ? (b / (1 << 20)).toFixed(1) + ' MB' : b >= 1024 ? Math.round(b / 1024) + ' KB' : b + ' B');

export default async function LogsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const policy = await getPolicy();
  const paused = await rawIngestPaused();
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  const hostOk = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;
  const hc = hostOk ? 'AND host_id=$1' : '';
  const hp = hostOk ? [hostOk] : [];

  // ---- 俯瞰 (overview, from permanent aggregates) ----
  const threats = await q<{ id: string; host: string | null; host_id: string | null; title: string; detail: string | null; created_at: Date }>(
    `SELECT a.id, h.name AS host, a.host_id, a.title, a.detail, a.created_at FROM alerts a LEFT JOIN hosts h ON h.id=a.host_id
     WHERE a.kind='log' AND a.status='open' AND a.created_at > now() - interval '24 hours' ${hostOk ? 'AND a.host_id=$1' : ''} ORDER BY a.created_at DESC`, hp);

  // A: category-stacked daily volume (30d)
  const catDays = await q<{ day: string; web: string; auth: string; audit: string; sys: string }>(
    `SELECT to_char(day,'YYYY-MM-DD') AS day,
       coalesce(sum(lines) FILTER (WHERE ${CAT.web}),0) web,
       coalesce(sum(lines) FILTER (WHERE ${CAT.auth}),0) auth,
       coalesce(sum(lines) FILTER (WHERE ${CAT.audit}),0) audit,
       coalesce(sum(lines) FILTER (WHERE ${CAT.sys}),0) sys
     FROM log_daily WHERE day > current_date - 30 ${hc} GROUP BY day ORDER BY day`, hp);

  // D: web overview (latest day per vhost)
  const web = await q<{ vhost: string; req: string; c4: string; c5: string; bytes: string }>(
    `SELECT vhost, sum(req) req, sum(c4xx) c4, sum(c5xx) c5, sum(bytes) bytes FROM web_daily
     WHERE day=(SELECT max(day) FROM web_daily) ${hostOk ? 'AND host_id=$1' : ''} GROUP BY vhost ORDER BY req DESC LIMIT 8`, hp);

  // C: auth summary (7d)
  const authRows = await q<{ rule_id: string; n: string }>(
    `SELECT rule_id, sum(hits) n FROM log_rule_daily WHERE day > current_date - 7
       AND rule_id IN ('ssh_accept_new_ip','ssh_bruteforce','sudo_new_user','sudo_auth_failure') ${hc} GROUP BY rule_id`, hp);
  const authN = (id: string) => Number(authRows.find((r) => r.rule_id === id)?.n ?? 0);
  const brute = await q<{ grp: string; n: string }>(
    `SELECT grp, count(*) n FROM log_hits WHERE rule_id='ssh_bruteforce' AND ts > now() - interval '7 days' ${hostOk ? 'AND host_id=$1' : ''} AND grp<>'' GROUP BY grp ORDER BY 2 DESC LIMIT 3`, hp);

  // E: rule top (this week vs previous)
  const ruleTop = await q<{ rule_id: string; wk: string; prev: string }>(
    `SELECT rule_id, coalesce(sum(hits) FILTER (WHERE day > current_date - 7),0) wk,
       coalesce(sum(hits) FILTER (WHERE day <= current_date - 7),0) prev
     FROM log_rule_daily WHERE day > current_date - 14 ${hc} GROUP BY rule_id
     HAVING sum(hits) FILTER (WHERE day > current_date - 7) > 0 ORDER BY wk DESC LIMIT 8`, hp);
  const sigmaTitles = Object.fromEntries((await q<{ id: string; title: string }>('SELECT id, title FROM sigma_rules')).map((r) => [r.id, `Sigma: ${r.title}`]));
  const title = (id: string) => RULE_TITLE[id] ?? sigmaTitles[id] ?? id;
  const sigmaFeed = (await q<{ item_count: number | null }>("SELECT item_count FROM feed_status WHERE name='sigma'"))[0];

  // B: host × day heatmap (14d)
  const heat = await q<{ host_id: string; name: string; day: string; n: string }>(
    `SELECT l.host_id, h.name, to_char(l.day,'YYYY-MM-DD') AS day, sum(l.lines) AS n FROM log_daily l JOIN hosts h ON h.id=l.host_id
     WHERE l.day > current_date - 14 ${hostOk ? 'AND l.host_id=$1' : ''} GROUP BY l.host_id, h.name, l.day`, hp);

  // ---- 詳細 (raw viewer) — same filter drives the lines ----
  const where: string[] = [];
  const params: unknown[] = [];
  if (hostOk) { params.push(hostOk); where.push(`l.host_id=$${params.length}`); }
  if (sp.source) { params.push(sp.source); where.push(`l.source=$${params.length}`); }
  const catOk = sp.cat && sp.cat in CAT ? (sp.cat as keyof typeof CAT) : undefined;
  if (catOk) where.push(`(l.${CAT[catOk]})`);
  const vhostOk = sp.vhost && /^[\w.*-]{1,120}$/.test(sp.vhost) ? sp.vhost : undefined;
  if (vhostOk) { params.push(`%${vhostOk}%`); where.push(`l.source ILIKE $${params.length}`); }
  const statusOk = sp.status && /^[1-5](xx|\d\d)$/.test(sp.status) ? sp.status : undefined;
  if (statusOk) { const pat = statusOk.endsWith('xx') ? `" ${statusOk[0]}[0-9][0-9] ` : `" ${statusOk} `; params.push(pat); where.push(`l.message ~ $${params.length}`); }
  if (sp.q) { params.push(`%${sp.q}%`); where.push(`l.message ILIKE $${params.length}`); }
  const hours = Math.min(24 * 365, Math.max(1, Number(sp.hours ?? 24) || 24));
  params.push(String(hours));
  where.push(`l.received_at > now() - ($${params.length} || ' hours')::interval`);
  const lines = await q<{ received_at: Date; ts: Date | null; source: string; message: string; host: string }>(
    `SELECT l.received_at, l.ts, l.source, l.message, h.name AS host FROM raw_logs l JOIN hosts h ON h.id=l.host_id
     WHERE ${where.join(' AND ')} ORDER BY l.received_at DESC, l.ts DESC NULLS LAST LIMIT 300`, params);

  // link helper: carry the current params, set/clear some, land on the raw section
  const link = (patch: Record<string, string | undefined>, anchor = '#raw') => {
    const u = new URLSearchParams(Object.entries({ ...sp, ...patch }).filter(([, v]) => v) as [string, string][]);
    return `/logs?${u}${anchor}`;
  };
  const conds: { k: string; label: string }[] = [];
  if (hostOk) conds.push({ k: 'host', label: `ホスト：${hosts.find((h) => h.id === hostOk)?.name ?? '?'}` });
  if (catOk) conds.push({ k: 'cat', label: `カテゴリ：${CAT_LABEL[catOk]}` });
  if (vhostOk) conds.push({ k: 'vhost', label: `サイト：${vhostOk}` });
  if (statusOk) conds.push({ k: 'status', label: `ステータス：${statusOk}` });
  if (sp.source) conds.push({ k: 'source', label: `ソース：${sp.source.replace(/^file:/, '')}` });
  if (sp.q) conds.push({ k: 'q', label: `検索：${sp.q}` });

  const catMax = Math.max(1, ...catDays.map((d) => Number(d.web) + Number(d.auth) + Number(d.audit) + Number(d.sys)));
  const CATC: [keyof typeof CAT, string][] = [['auth', '#2563eb'], ['web', '#0e7c86'], ['sys', '#8b5cf6'], ['audit', '#d97706']];
  // heatmap pivot
  const hmHosts = [...new Map(heat.map((r) => [r.host_id, r.name])).entries()];
  const hmDays = [...new Set(heat.map((r) => r.day))].sort();
  const hmVal = new Map(heat.map((r) => [`${r.host_id}|${r.day}`, Number(r.n)]));
  const hostMax = new Map(hmHosts.map(([id]) => [id, Math.max(1, ...hmDays.map((d) => hmVal.get(`${id}|${d}`) ?? 0))]));
  const heatColor = (rel: number) => rel <= 0 ? 'var(--bg)' : rel < 0.35 ? '#cfe6e8' : rel < 0.6 ? '#8fcbd0' : rel < 0.85 ? '#f6c343' : '#e8743b';

  return (
    <>
      <ExploreTabs />
      {paused && (
        <div className="rounded-md border border-orange-400 bg-orange-50 px-4 py-3 text-sm text-orange-900 dark:bg-orange-950 dark:text-orange-100">
          ディスク使用率が上限（{policy.diskGuardPercent}%）を超えたため、生ログの保存を停止しています。ルール判定と集計は続けています。
        </div>
      )}

      {/* host scope */}
      <form className="flex flex-wrap items-center gap-2 text-sm" action="/logs">
        <span className="text-xs text-muted">ホスト</span>
        <select name="host" defaultValue={hostOk ?? ''} className="input sm:w-auto">
          <option value="">すべて</option>
          {hosts.map((h) => <option key={h.id} value={h.id}><Masked kind="host">{h.name}</Masked></option>)}
        </select>
        <button className="btn">表示</button>
        <span className="ml-auto text-xs text-muted">俯瞰して気になった所をタップ → 下の生ログに連動します</span>
      </form>

      {/* ログ脅威 */}
      <Card title={`ログ脅威（直近24時間・未対応 ${threats.length}件）`}>
        {threats.length === 0 ? <p className="text-sm text-green-600">✅ 直近24時間に未対応のログ脅威はありません。</p> : (
          <ul className="divide-y divide-line">
            {threats.map((t) => {
              const ip = t.title.match(IP_RE)?.[1];
              return (
                <li key={t.id} className="flex flex-col gap-2 py-2 sm:flex-row sm:items-start sm:gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm"><span className="mr-1">⚠</span><MaskFree>{t.title}</MaskFree></div>
                    <div className="text-xs text-muted">{t.host ? <><Masked kind="host">{t.host}</Masked> · </> : ''}{ago(t.created_at)}</div>
                  </div>
                  <div className="flex flex-wrap gap-1 sm:shrink-0">
                    {ip && <form action={trustIp}><input type="hidden" name="id" value={t.id} /><input type="hidden" name="ip" value={ip} /><button className="btn-ghost">自分です（<Masked kind="addr">{ip}</Masked>）</button></form>}
                    {t.host_id && <Link href={`/logs?host=${t.host_id}#raw`} className="btn-ghost">調べる</Link>}
                    <form action={alertFormAction}><input type="hidden" name="id" value={t.id} /><button name="status" value="ack" className="btn-ghost">確認済み</button></form>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {/* A: category volume */}
      <Card title="ログ量の推移（30日・カテゴリ別）">
        {catDays.length < 2 ? <p className="text-sm text-muted">まだ集計がたまっていません。</p> : (
          <>
            <div className="flex items-end gap-1" style={{ height: 150 }}>
              {catDays.map((d) => {
                const tot = Number(d.web) + Number(d.auth) + Number(d.audit) + Number(d.sys);
                return (
                  <div key={d.day} title={`${d.day}: ${tot.toLocaleString()}行`} className="flex flex-1 flex-col justify-end" style={{ maxWidth: 26, height: '100%' }}>
                    {CATC.map(([k, c]) => { const h = (Number(d[k]) / catMax) * 140; return h > 0.3 ? <div key={k} style={{ height: `${h}px`, background: c }} /> : null; })}
                  </div>
                );
              })}
            </div>
            <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted">
              {CATC.map(([k, c]) => <Link key={k} href={link({ cat: k, source: undefined, vhost: undefined, status: undefined })} className="inline-flex items-center gap-1.5 hover:text-fg"><span className="inline-block h-3 w-3 rounded-sm" style={{ background: c }} />{CAT_LABEL[k]}</Link>)}
              <span className="ml-auto">凡例をタップでそのカテゴリの生ログへ</span>
            </div>
          </>
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* D: web */}
        <Card title="Web の俯瞰（最新日・サイト別）">
          {web.length === 0 ? <p className="text-sm text-muted">Webアクセスログの集計がありません。</p> : (
            <div className="overflow-x-auto"><table className="tbl">
              <thead><tr><th>サイト</th><th className="text-right">req</th><th>エラー率</th><th className="text-right">転送</th></tr></thead>
              <tbody>
                {web.map((w) => { const req = Number(w.req), err = req ? ((Number(w.c4) + Number(w.c5)) / req) * 100 : 0;
                  const col = err >= 5 ? 'text-red-600' : err >= 2 ? 'text-amber-600' : 'text-green-600';
                  return (
                    <tr key={w.vhost}>
                      <td><Link href={link({ cat: 'web', vhost: w.vhost, source: undefined, status: undefined })} className="text-accent">{w.vhost}</Link></td>
                      <td className="whitespace-nowrap text-right font-mono">{req.toLocaleString()}</td>
                      <td className="whitespace-nowrap"><span className={`font-mono ${col}`}>{err.toFixed(1)}%</span>{Number(w.c5) > 0 && <Link href={link({ cat: 'web', vhost: w.vhost, status: '5xx', source: undefined })} className="ml-2 text-xs text-accent">5xx {w.c5}</Link>}</td>
                      <td className="whitespace-nowrap text-right font-mono">{fmtBytes(Number(w.bytes))}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table></div>
          )}
          <p className="mt-2 text-xs text-muted">サイト名/5xx をタップでその条件の生ログへ。</p>
        </Card>

        {/* C: auth */}
        <Card title="認証の俯瞰（7日）">
          <div className="grid grid-cols-2 gap-2 text-sm">
            {[['SSH初見IP成功', authN('ssh_accept_new_ip'), 'Accepted', 'text-red-600'], ['SSH失敗集中', authN('ssh_bruteforce'), 'Failed', 'text-amber-600'], ['sudo初見ユーザー', authN('sudo_new_user'), 'COMMAND=', 'text-muted'], ['sudo認証失敗', authN('sudo_auth_failure'), 'authentication failure', 'text-amber-600']].map(([label, n, qq, col]) => (
              <Link key={label as string} href={link({ cat: 'auth', q: qq as string, source: undefined, vhost: undefined, status: undefined })} className="rounded-lg border border-line bg-bg p-3 hover:border-accent">
                <div className="text-xs text-muted">{label as string}</div>
                <div className={`font-mono text-xl font-bold ${n ? (col as string) : 'text-muted'}`}>{n as number}</div>
              </Link>
            ))}
          </div>
          {brute.length > 0 && (
            <div className="mt-3">
              <p className="mb-1 text-xs font-semibold">失敗元の上位IP（7日）</p>
              <ul className="divide-y divide-line text-sm">
                {brute.map((b) => <li key={b.grp} className="flex items-center justify-between py-1.5"><Link href={link({ cat: 'auth', q: b.grp, source: undefined, vhost: undefined, status: undefined })} className="font-mono text-accent"><Masked kind="addr">{b.grp}</Masked></Link><span className="font-mono text-xs text-muted">×{b.n}</span></li>)}
              </ul>
            </div>
          )}
        </Card>
      </div>

      {/* E: rule top */}
      <Card title="検知ルール Top（7日・前週比）" right={<span className="text-xs text-muted">Sigma {sigmaFeed?.item_count ?? 0} ルール適用中</span>}>
        {ruleTop.length === 0 ? <p className="text-sm text-muted">一致はありません。</p> : (
          <ul className="space-y-1.5">
            {ruleTop.map((r) => { const wk = Number(r.wk), prev = Number(r.prev), d = wk - prev, max = Math.max(1, ...ruleTop.map((x) => Number(x.wk)));
              return (
                <li key={r.rule_id} className="grid grid-cols-[1fr_auto_auto] items-center gap-3">
                  <div className="min-w-0"><div className="truncate text-sm">{title(r.rule_id)}</div><div className="mt-1 h-2 rounded bg-soft" style={{ background: 'var(--soft)' }}><div className="h-full rounded" style={{ width: `${Math.max(4, (wk / max) * 100)}%`, background: 'var(--accent)' }} /></div></div>
                  <span className="font-mono text-sm tabular-nums">{wk.toLocaleString()}</span>
                  <span className={`font-mono text-xs tabular-nums ${d > 0 ? 'text-red-600' : d < 0 ? 'text-green-600' : 'text-muted'}`}>{d > 0 ? '▲' : d < 0 ? '▼' : '－'}{Math.abs(d)}</span>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {/* B: heatmap */}
      {hmHosts.length > 0 && hmDays.length > 1 && (
        <Card title="ホスト×日 ログ量ヒートマップ（14日・各ホストの平常比）">
          <div className="space-y-1 text-xs">
            {hmHosts.map(([id, name]) => (
              <div key={id} className="grid items-center gap-1.5" style={{ gridTemplateColumns: '84px 1fr' }}>
                <Link href={`/logs?host=${id}#raw`} className="truncate font-mono text-accent"><Masked kind="host">{name}</Masked></Link>
                <div className="grid gap-0.5" style={{ gridTemplateColumns: `repeat(${hmDays.length}, 1fr)` }}>
                  {hmDays.map((d) => { const v = hmVal.get(`${id}|${d}`) ?? 0; const rel = v / (hostMax.get(id) ?? 1);
                    return <div key={d} title={`${name} ${d}: ${v.toLocaleString()}行`} style={{ aspectRatio: '1', borderRadius: 3, background: heatColor(rel) }} />;
                  })}
                </div>
              </div>
            ))}
            <div className="grid gap-1.5" style={{ gridTemplateColumns: '84px 1fr' }}><span /><div className="flex justify-between text-[11px] text-muted"><span>14日前</span><span>今日</span></div></div>
          </div>
        </Card>
      )}

      {/* ---- 詳細: raw logs (linked to the condition) ---- */}
      <div id="raw" className="scroll-mt-20">
        <Card title={`生ログ（新しい順・最大300行／保存 ${policy.logRetentionDays}日）`}>
          {conds.length > 0 && (
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted">条件：</span>
              {conds.map((c) => <Link key={c.k} href={link({ [c.k]: undefined })} className="inline-flex items-center gap-1 rounded-full border border-line bg-accent-weak px-2 py-0.5 text-xs" style={{ background: 'var(--soft)' }}>{c.label}<span className="text-muted">✕</span></Link>)}
              <Link href="/logs#raw" className="ml-auto text-xs text-accent">すべて解除</Link>
            </div>
          )}
          <form className="mb-3 grid grid-cols-2 gap-2 text-sm sm:flex sm:flex-wrap" action="/logs">
            {hostOk && <input type="hidden" name="host" value={hostOk} />}
            <select name="cat" defaultValue={catOk ?? ''} className="input sm:w-auto"><option value="">カテゴリ：すべて</option>{Object.keys(CAT).map((k) => <option key={k} value={k}>{CAT_LABEL[k]}</option>)}</select>
            <input name="status" defaultValue={statusOk ?? ''} placeholder="ステータス(例 4xx,403)" className="input sm:w-36" />
            <select name="hours" defaultValue={String(hours)} className="input sm:w-auto">{[1, 6, 24, 72, 168, 720].map((h) => <option key={h} value={h}>{h < 24 ? `${h}時間` : `${h / 24}日`}以内</option>)}</select>
            <input name="q" defaultValue={sp.q ?? ''} placeholder="本文を検索" className="input sm:w-48" />
            <input type="hidden" name="_" value="raw" />
            <button className="btn">絞り込み</button>
          </form>
          {lines.length === 0 ? <p className="text-sm text-muted">この条件に該当する生ログはありません。</p> : (
            <div className="font-mono text-xs">
              {lines.map((l, i) => (
                <div key={i} className="flex flex-wrap gap-x-3 border-b border-line py-1 sm:flex-nowrap">
                  <span className="whitespace-nowrap text-muted">{l.ts ? new Date(l.ts).toLocaleString('ja-JP') : ago(l.received_at)}</span>
                  <span className="whitespace-nowrap text-muted"><Masked kind="host">{l.host}</Masked></span>
                  <Link href={link({ source: l.source, cat: undefined, vhost: undefined, status: undefined })} className="max-w-[14rem] truncate whitespace-nowrap text-accent">{l.source}</Link>
                  <span className="w-full min-w-0 break-all sm:w-auto sm:flex-1"><MaskFree>{l.message}</MaskFree></span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
