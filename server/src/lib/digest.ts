// Daily summary mail — a fixed, at-a-glance template. One line per active host with its open-finding
// counts (KEV / 緊急 / 高 / 新規 / 監視) and a status flag, ALWAYS including hosts that are at zero, so the
// mail reads the same every day and "0 means 0" is explicit. Numbers only; the per-CVE detail lives behind
// each host's page. Sent once a day at digestHour regardless of whether anything changed.
import { q } from './db';
import { sendMail } from './mail';
import { getMail } from './settings';

// Visual width: CJK / full-width characters occupy two monospace cells. Used to align the table in a
// plain-text mail where host names mix ASCII and Japanese.
const vwidth = (s: string): number =>
  [...s].reduce((w, c) => w + (/[ᄀ-ᅟ⺀-꓏가-힣豈-﫿︰-﹏＀-｠￠-￦]/.test(c) ? 2 : 1), 0);
const padEndV = (s: string, w: number) => s + ' '.repeat(Math.max(0, w - vwidth(s)));
const padStartV = (s: string, w: number) => ' '.repeat(Math.max(0, w - vwidth(s))) + s;

export async function buildDigest(since: Date): Promise<{ subject: string; body: string } | null> {
  const url = (process.env.PUBLIC_URL ?? '').replace(/\/+$/, '');
  // Per-host open-finding counts. KEV counts regardless of severity; 緊急/高 are the non-KEV criticals/highs;
  // 新規 is the KEV/緊急 that first appeared in the digest window.
  const hosts = await q<{ id: string; name: string; kev: string; crit: string; high: string; neww: string }>(
    `SELECT h.id, h.name,
       count(*) FILTER (WHERE f.kev) AS kev,
       count(*) FILTER (WHERE NOT f.kev AND f.severity='critical') AS crit,
       count(*) FILTER (WHERE NOT f.kev AND f.severity='high') AS high,
       count(*) FILTER (WHERE f.first_seen >= $1 AND (f.kev OR f.severity='critical')) AS neww
     FROM hosts h LEFT JOIN findings f ON f.host_id=h.id AND f.status='open'
     WHERE NOT h.disabled
     GROUP BY h.id, h.name ORDER BY h.name`, [since]);
  if (!hosts.length) return null; // no managed hosts at all → nothing to send

  // 監視 = open intrusion / health signals in the window, per host (+ instance-wide ones with no host).
  const ops = await q<{ host_id: string | null; n: string }>(
    `SELECT a.host_id, count(*) AS n FROM alerts a
     WHERE a.status='open' AND a.kind IN ('state','log','stale','feed','disk','agent') AND a.created_at >= $1
     GROUP BY a.host_id`, [since]);
  const opsBy = new Map(ops.map((o) => [o.host_id, Number(o.n)]));
  const globalOps = opsBy.get(null) ?? 0;

  const rows = hosts.map((h) => ({
    name: h.name, kev: +h.kev, crit: +h.crit, high: +h.high, neww: +h.neww, mon: opsBy.get(h.id) ?? 0,
  }));
  const totKev = rows.reduce((a, x) => a + x.kev, 0);
  const totCrit = rows.reduce((a, x) => a + x.crit, 0);

  const nameW = Math.max(10, ...rows.map((r) => vwidth(r.name)));
  const nnew = (n: number) => (n > 0 ? `+${n}` : '0');
  const line = (name: string, kev: string, crit: string, high: string, nw: string, mon: string, stat: string) =>
    `${padEndV(name, nameW)} ${padStartV(kev, 3)} ${padStartV(crit, 4)} ${padStartV(high, 3)} ${padStartV(nw, 4)} ${padStartV(mon, 4)}  ${stat}`;

  const body: string[] = [
    '過去24時間時点の未対応（全ホスト・数値のみ。詳細は各ホストの画面へ）。',
    '',
    line('ホスト', 'KEV', '緊急', '高', '新規', '監視', '状態'),
  ];
  for (const r of rows) {
    const stat = r.kev > 0 || r.crit > 0 ? '⚠要対応' : '○良好';
    body.push(line(r.name, String(r.kev), String(r.crit), String(r.high), nnew(r.neww), String(r.mon), stat));
  }
  if (globalOps > 0) body.push('', `インスタンス全体（ホスト外）：監視 ${globalOps}`);
  body.push('', '――――――', `▶ ${url}/`);

  const today = new Date();
  const subject = `[minisoc2] 日次まとめ ${today.getMonth() + 1}/${today.getDate()}（KEV ${totKev} / 緊急 ${totCrit}）`;
  return { subject, body: body.join('\n') };
}

export async function sendDigest(since: Date): Promise<'sent' | 'empty' | 'disabled'> {
  const mail = await getMail();
  if (!mail.enabled) return 'disabled';
  const d = await buildDigest(since);
  if (!d) return 'empty';
  await sendMail(d.subject, d.body);
  return 'sent';
}
