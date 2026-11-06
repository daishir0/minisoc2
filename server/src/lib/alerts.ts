import { q, q1 } from './db';
import { sendMail } from './mail';
import { getMail } from './settings';
import { CVE_SELECT, CVE_JOIN, cveLines, cveScore, cveSort, opsLine, type CveRow } from './mailfmt';
import { riskBucket } from './risk';

const nul = (x: string) => x.replace(/\u0000/g, '|'); // Postgres text rejects NUL

export interface NewAlert {
  kind: 'vuln' | 'kev' | 'watch' | 'stale' | 'feed' | 'baseline' | 'agent' | 'state' | 'log' | 'disk';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  hostId?: string | null;
  title: string;
  detail?: string;
  dedupeKey: string;
}

// Idempotent: the same dedupe key never creates a second alert.
export async function raiseAlert(a: NewAlert): Promise<boolean> {
  const r = await q1<{ id: string }>(
    `INSERT INTO alerts(kind, severity, host_id, title, detail, dedupe_key) VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (dedupe_key) DO NOTHING RETURNING id`,
    [a.kind, a.severity, a.hostId ?? null, nul(a.title).slice(0, 500), nul(a.detail ?? '').slice(0, 10000), nul(a.dedupeKey).slice(0, 1000)],
  );
  return !!r;
}

// What gets emailed immediately = the "Act now" bucket, to stop the flood of ordinary critical vulns.
// - KEV, watched CVEs, host/feed/disk health, baselines, info: always immediate (curated / low volume).
// - Non-vuln critical (intrusion-ish state/log/agent): immediate.
// - Plain `vuln` findings: immediate ONLY when exploit probability is high (EPSS >= ACT_EPSS). Everything
//   else goes to the daily digest. This is what cuts the hundreds of low-EPSS critical-CVE mails.
const IMMEDIATE_KINDS = new Set(['kev', 'watch', 'stale', 'feed', 'disk', 'baseline']);
const ACT_EPSS = 0.5;

// Resolve the EPSS score of a `vuln` alert from the CVE embedded in its dedupe key
// (`vuln:<hostId>:<vulnId>|<ecosystem>|<pkg>:<ts>`). Returns null when unknown.
async function vulnEpss(dedupeKey: string): Promise<number | null> {
  const m = /^vuln:[0-9a-f-]+:([^|]+)\|/.exec(dedupeKey);
  if (!m) return null;
  const vid = m[1];
  const cve = vid.replace(/^(UBUNTU|DEBIAN)-/, '');
  const r = await q1<{ s: number | null }>(
    'SELECT max(e.score) AS s FROM epss e WHERE e.cve=$1 OR e.cve = ANY(SELECT unnest(aliases) FROM vulns v WHERE v.id=$2)', [cve, vid]);
  return r?.s ?? null;
}

async function immediate(a: { kind: string; severity: string; dedupe_key: string }): Promise<boolean> {
  if (a.kind === 'vuln') { const e = await vulnEpss(a.dedupe_key); return e != null && e >= ACT_EPSS; }
  return IMMEDIATE_KINDS.has(a.kind) || a.severity === 'critical' || a.severity === 'info';
}

// Send one mail covering the new urgent (KEV/critical) alerts. The body is grouped by REMEDIATION TASK
// (host × project), because the Claude Code fix prompt is generated per task — so each line links
// straight to the page where that prompt is one click to copy.
export async function notifyPending(publicUrl: string): Promise<{ sent: number; skipped: number; error?: string }> {
  const pending = await q<{ id: string; kind: string; severity: string; title: string; detail: string; created_at: Date; host_id: string | null; host_name: string | null; dedupe_key: string }>(
    "SELECT a.id, a.kind, a.severity, a.title, a.detail, a.created_at, a.host_id, (SELECT name FROM hosts WHERE id=a.host_id) AS host_name, a.dedupe_key FROM alerts a WHERE a.notified_at IS NULL ORDER BY a.created_at LIMIT 500",
  );
  if (!pending.length) return { sent: 0, skipped: 0 };
  const mail = await getMail();
  const flags = await Promise.all(pending.map(immediate));
  const toSend = pending.filter((_, i) => flags[i]);
  const skip = pending.filter((_, i) => !flags[i]);
  if (skip.length) await q("UPDATE alerts SET notified_at=now(), notify_error='digest only' WHERE id = ANY($1::bigint[])", [skip.map((a) => a.id)]);
  if (!toSend.length) return { sent: 0, skipped: skip.length };
  if (!mail.enabled) {
    await q("UPDATE alerts SET notified_at=now(), notify_error='mail disabled' WHERE id = ANY($1::bigint[])", [toSend.map((a) => a.id)]);
    return { sent: 0, skipped: pending.length };
  }
  const kevN = toSend.filter((a) => a.kind === 'kev').length;
  const PER_HOST = 6;
  const since = new Date(Date.now() - 24 * 3600_000);

  // "Act now" findings on the hosts that just raised vulnerability alerts — same per-CVE format as the
  // daily digest (CVE id + title, EPSS, publish date, detection time), grouped by host, priority-sorted.
  // KEV + critical ONLY: "高"（high）and below are never e-mailed (mail is a 緊急-only channel).
  const vulnHosts = [...new Set(toSend.filter((a) => (a.kind === 'kev' || a.kind === 'vuln') && a.host_id).map((a) => a.host_id as string))];
  const actByHost = new Map<string, (CveRow & { host: string; host_id: string })[]>();
  if (vulnHosts.length) {
    const rows = await q<CveRow & { host_id: string; host: string }>(
      `SELECT f.host_id, h.name AS host, ${CVE_SELECT('$2')}
       FROM findings f JOIN hosts h ON h.id=f.host_id ${CVE_JOIN}
       WHERE f.status='open' AND f.host_id = ANY($1::uuid[]) AND (f.kev OR f.severity='critical')`,
      [vulnHosts, since],
    );
    for (const r of rows) {
      if (riskBucket({ kev: r.kev, epss: r.epss ?? null, exposure: r.pub ? 'public' : '', severity: r.severity }) !== 'act') continue;
      actByHost.set(r.host, [...(actByHost.get(r.host) ?? []), r]);
    }
  }
  const actTotal = [...actByHost.values()].reduce((a, v) => a + v.length, 0);
  // Everything else = intrusion signals / monitoring health (stale / feed / disk / baseline / critical state).
  const others = toSend.filter((a) => a.kind !== 'kev' && a.kind !== 'vuln');

  // Nothing above the 緊急 bar to show (e.g. a triggering alert whose findings are all "高" or below,
  // which the body now excludes): don't send an empty mail — just mark the alerts handled.
  if (!actTotal && !others.length) {
    await q("UPDATE alerts SET notified_at=now(), notify_error='緊急・KEVなし（メール対象外）' WHERE id = ANY($1::bigint[])", [toSend.map((a) => a.id)]);
    return { sent: 0, skipped: pending.length };
  }

  const sections: string[] = [
    'minisoc2 セキュリティ通知（即時）。',
    '悪用の可能性が高い脆弱性（KEV・EPSS高）と、侵入・監視系の重要な通知だけをお届けします。',
    '緊急でない脆弱性は毎日の「まとめメール（ダイジェスト）」に回しています。',
    '各行：深刻度 / CVE・タイトル / EPSS / 公開日（世界に明らかになった日）/ 当システムが検出した日時。',
  ];
  if (actTotal) {
    sections.push('', `■ 今すぐ対応（${actTotal}件）— 各ホストを開く → プロンプトをコピー → 実行 → 「今すぐ収集」で確認`);
    const hostsSorted = [...actByHost.entries()].sort((a, b) => Math.max(...b[1].map(cveScore)) - Math.max(...a[1].map(cveScore)));
    for (const [host, frs] of hostsSorted) {
      const kev = frs.filter((f) => f.kev).length, crit = frs.filter((f) => !f.kev && f.severity === 'critical').length;
      sections.push(`■ ${host}　KEV ${kev}・緊急 ${crit}`);
      frs.sort(cveSort).slice(0, PER_HOST).forEach((r, i) => sections.push(...cveLines(r, i)));
      if (frs.length > PER_HOST) sections.push(`  …ほか ${frs.length - PER_HOST}件`);
      sections.push(`  ▶ ${publicUrl}/hosts/${frs[0].host_id}`);
    }
  }
  if (others.length) {
    sections.push('', '■ 要確認（侵入の兆候・監視の停止など）');
    const opByHost = new Map<string, Map<string, number>>();
    for (const a of others) {
      const h = a.host_name ?? '(ホスト不明)';
      const m = opByHost.get(h) ?? new Map<string, number>();
      m.set(a.kind, (m.get(a.kind) ?? 0) + 1);
      opByHost.set(h, m);
    }
    for (const [host, kinds] of opByHost) sections.push(opsLine(host, [...kinds.entries()].map(([kind, n]) => ({ kind, n }))));
  }
  sections.push(
    '',
    '――――――',
    `今日やること（優先度順）: ${publicUrl}/`,
    `すべての対応: ${publicUrl}/actions`,
    `脆弱性を絞り込む（KEV/EPSS/公開）: ${publicUrl}/findings`,
  );
  const subject = actTotal
    ? `[minisoc2] 今すぐ対応 ${actTotal}件${kevN ? `（KEV ${kevN}含む）` : ''}`
    : `[minisoc2] 監視通知 ${others.length}件`;
  const body = sections.filter((x, i, arr) => !(x === '' && arr[i - 1] === '')).join('\n');
  try {
    await sendMail(subject.slice(0, 200), body);
    await q('UPDATE alerts SET notified_at=now(), notify_error=NULL WHERE id = ANY($1::bigint[])', [toSend.map((a) => a.id)]);
    return { sent: toSend.length, skipped: skip.length };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await q('UPDATE alerts SET notify_error=$2 WHERE id = ANY($1::bigint[])', [toSend.map((a) => a.id), msg.slice(0, 500)]);
    return { sent: 0, skipped: skip.length, error: msg };
  }
}
