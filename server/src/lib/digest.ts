// Daily summary mail. Vulnerability-first and de-duplicated: one block per host, findings sorted by
// priority (KEV → public → EPSS → severity), each line carrying the CVE id + title, when it was made
// public to the world (vulns.published, + how many days ago) and when WE first detected it on the host
// (findings.first_seen). New (last 24h) and existing open findings are both shown; resolved items are
// not. Intrusion / monitoring signals are a separate, per-host-collapsed section.
import { q } from './db';
import { sendMail } from './mail';
import { getMail } from './settings';
import { CVE_SELECT, CVE_JOIN, cveLines, cveScore, cveSort, opsLine, type CveRow } from './mailfmt';

type Row = CveRow & { host_id: string; host: string };

const PER_HOST = 8;

export async function buildDigest(since: Date): Promise<{ subject: string; body: string } | null> {
  const url = (process.env.PUBLIC_URL ?? '').replace(/\/+$/, '');
  // Notified findings are KEV + critical ONLY. "高"（high）and below are tracked in the app but never
  // e-mailed — the mail is a "緊急だけ" channel, matching the home/findings "KEV・緊急" surface.
  const rows = await q<Row>(
    `SELECT f.host_id, h.name AS host, ${CVE_SELECT('$1')}
     FROM findings f JOIN hosts h ON h.id=f.host_id
     ${CVE_JOIN}
     WHERE f.status='open' AND NOT h.disabled AND (f.kev OR f.severity='critical')`,
    [since],
  );
  // per-host KEV/critical totals (for the header) + new-count among those
  const totals = await q<{ host_id: string; kev: string; crit: string; neww: string }>(
    `SELECT host_id,
            count(*) FILTER (WHERE kev) AS kev,
            count(*) FILTER (WHERE NOT kev AND severity='critical') AS crit,
            count(*) FILTER (WHERE first_seen >= $1) AS neww
     FROM findings WHERE status='open' AND (kev OR severity='critical') GROUP BY host_id`, [since],
  );
  const tot = new Map(totals.map((t) => [t.host_id, t]));
  // intrusion / monitoring, collapsed to one line per host
  const ops = await q<{ host: string; kind: string; n: string }>(
    `SELECT COALESCE(h.name, '(ホスト不明)') AS host, a.kind, count(*) AS n FROM alerts a LEFT JOIN hosts h ON h.id=a.host_id
     WHERE a.status='open' AND a.kind IN ('state','log','stale','feed','disk','agent') AND a.created_at >= $1
     GROUP BY h.name, a.kind ORDER BY h.name`, [since],
  );
  if (!rows.length && !ops.length) return null;

  const byHost = new Map<string, Row[]>();
  for (const r of rows) byHost.set(r.host, [...(byHost.get(r.host) ?? []), r]);
  // hosts ordered by their most urgent finding
  const hosts = [...byHost.entries()].sort((a, b) => Math.max(...b[1].map(cveScore)) - Math.max(...a[1].map(cveScore)));

  const grandKev = [...tot.values()].reduce((a, t) => a + Number(t.kev), 0);
  const grandCrit = [...tot.values()].reduce((a, t) => a + Number(t.crit), 0);

  const lines: string[] = [
    '過去24時間時点の、未対応の脆弱性です（重要な順・ホストごと）。',
    '各行：深刻度 / CVE・タイトル / EPSS / 公開日（世界に明らかになった日）/ 当システムが検出した日時。',
    '',
  ];
  for (const [host, frs] of hosts) {
    const t = tot.get(frs[0].host_id);
    const head = t ? `KEV ${t.kev}・緊急 ${t.crit}${Number(t.neww) ? `（新規 +${t.neww}）` : ''}` : '';
    lines.push(`■ ${host}　${head}`);
    frs.sort(cveSort).slice(0, PER_HOST).forEach((r, i) => lines.push(...cveLines(r, i)));
    if (frs.length > PER_HOST) lines.push(`  …ほか ${frs.length - PER_HOST}件`);
    lines.push(`  ▶ ${url}/hosts/${frs[0].host_id}`);
    lines.push('');
  }
  if (ops.length) {
    lines.push('■ 要確認（侵入の兆候・監視の停止など）');
    const opByHost = new Map<string, { kind: string; n: number }[]>();
    for (const o of ops) opByHost.set(o.host, [...(opByHost.get(o.host) ?? []), { kind: o.kind, n: Number(o.n) }]);
    for (const [host, kinds] of opByHost) lines.push(opsLine(host, kinds));
    lines.push('');
  }
  lines.push('――――――', `今日やること（優先度順）: ${url}/`, `すべての対応: ${url}/actions`);

  const subject = `[minisoc2] 日次まとめ（未対応 KEV ${grandKev} / 緊急 ${grandCrit}）`;
  const body = lines.filter((x, i, a) => !(x === '' && a[i - 1] === '')).join('\n');
  return { subject, body };
}

export async function sendDigest(since: Date): Promise<'sent' | 'empty' | 'disabled'> {
  const mail = await getMail();
  if (!mail.enabled) return 'disabled';
  const d = await buildDigest(since);
  if (!d) return 'empty';
  await sendMail(d.subject, d.body);
  return 'sent';
}
