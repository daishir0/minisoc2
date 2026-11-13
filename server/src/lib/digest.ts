// Daily summary mail. Vulnerability-first and de-duplicated: one block per host, findings sorted by
// priority (KEV → public → EPSS → severity), each line carrying the CVE id + title, when it was made
// public to the world (vulns.published, + how many days ago) and when WE first detected it on the host
// (findings.first_seen). New (last 24h) and existing open findings are both shown; resolved items are
// not. Intrusion / monitoring signals are a separate, per-host-collapsed section.
import { q } from './db';
import { sendMail } from './mail';
import { getMail } from './settings';
import { CVE_SELECT, CVE_JOIN, cveLines, cveScore, cveSort, groupByCve, opsLine, type CveRow } from './mailfmt';

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
  // intrusion / monitoring, collapsed to one line per host
  const ops = await q<{ host: string; kind: string; n: string }>(
    `SELECT COALESCE(h.name, '(ホスト不明)') AS host, a.kind, count(*) AS n FROM alerts a LEFT JOIN hosts h ON h.id=a.host_id
     WHERE a.status='open' AND a.kind IN ('state','log','stale','feed','disk','agent') AND a.created_at >= $1
     GROUP BY h.name, a.kind ORDER BY h.name`, [since],
  );
  if (!rows.length && !ops.length) return null;

  // Collapse each host's findings to one entry per CVE (httpd/httpd-core/httpd-tools/… → one line),
  // then order hosts by their most urgent CVE. Header/subject counts are CVE-level so they match the lines.
  const byHost = new Map<string, Row[]>();
  for (const r of rows) byHost.set(r.host, [...(byHost.get(r.host) ?? []), r]);
  const hostGroups = [...byHost.entries()]
    .map(([host, frs]) => ({ host, host_id: frs[0].host_id, groups: groupByCve(frs).sort(cveSort) }))
    .sort((a, b) => Math.max(...b.groups.map(cveScore)) - Math.max(...a.groups.map(cveScore)));

  const grandKev = hostGroups.reduce((a, h) => a + h.groups.filter((g) => g.kev).length, 0);
  const grandCrit = hostGroups.reduce((a, h) => a + h.groups.filter((g) => !g.kev && g.severity === 'critical').length, 0);

  const lines: string[] = [
    '過去24時間時点の、未対応の脆弱性です（重要な順・ホストごと）。',
    '各行：深刻度 / CVE・タイトル / EPSS / 公開日（世界に明らかになった日）/ 当システムが検出した日時。',
    '※同じCVEが複数パッケージ（例: httpd と httpd-core）に出る場合は1行にまとめています。',
    '',
  ];
  for (const { host, host_id, groups } of hostGroups) {
    const kev = groups.filter((g) => g.kev).length;
    const crit = groups.filter((g) => !g.kev && g.severity === 'critical').length;
    const neww = groups.filter((g) => g.is_new).length;
    lines.push(`■ ${host}　KEV ${kev}・緊急 ${crit}${neww ? `（新規 +${neww}）` : ''}`);
    groups.slice(0, PER_HOST).forEach((r, i) => lines.push(...cveLines(r, i)));
    if (groups.length > PER_HOST) lines.push(`  …ほか ${groups.length - PER_HOST}件`);
    lines.push(`  ▶ ${url}/hosts/${host_id}`);
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
