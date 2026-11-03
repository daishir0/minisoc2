import { q, q1 } from './db';
import { sendMail } from './mail';
import { getMail } from './settings';
import { listTasks } from './tasks';

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
  const pending = await q<{ id: string; kind: string; severity: string; title: string; detail: string; created_at: Date; host_id: string | null; dedupe_key: string }>(
    'SELECT id, kind, severity, title, detail, created_at, host_id, dedupe_key FROM alerts WHERE notified_at IS NULL ORDER BY created_at LIMIT 500',
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
  const L: Record<string, string> = { critical: '緊急', high: '高', medium: '中', low: '低', info: '情報' };
  const kevN = toSend.filter((a) => a.kind === 'kev').length;
  const MAX = 15;
  const pct = (e: number | null) => (e != null ? `EPSS ${Math.round(e * 100)}%` : '');

  // "Act now" remediation tasks (host × unit), each a single click to the page whose Claude Code fix
  // prompt is one copy away. Only the Act bucket is surfaced here — the rest is the daily digest.
  const hasFix = toSend.some((a) => a.kind === 'kev' || a.kind === 'vuln');
  const actTasks = hasFix ? (await listTasks()).filter((t) => (t.kev + t.critical > 0) && t.bucket === 'act') : [];
  // Everything else = intrusion signals / monitoring health (stale / feed / disk / baseline / critical state).
  const others = toSend.filter((a) => a.kind !== 'kev' && a.kind !== 'vuln');

  const sections: string[] = [
    'minisoc2 セキュリティ通知（即時）。',
    '悪用の可能性が高い脆弱性（KEV・EPSS高）と、侵入・監視系の重要な通知だけをお届けします。',
    '緊急でない脆弱性は毎日の「まとめメール（ダイジェスト）」に回しています。',
  ];
  if (actTasks.length) {
    sections.push('', `■ 今すぐ対応（${actTasks.length}件）`, '  各行を開く → 「Claude Code で修正」をコピー → 対象ホストで実行 → 「今すぐ収集」で解消を確認。');
    for (const t of actTasks.slice(0, MAX)) {
      const where = t.root === '__os__' ? `${t.host} ／ OSパッケージ` : `${t.host} ／ ${t.name}`;
      const badge = [t.kev && `KEV ${t.kev}`, t.critical && `緊急 ${t.critical}`, t.exposure === 'public' && '公開', pct(t.epss)].filter(Boolean).join(' ・ ');
      const pkgs = t.packages.map((p) => p.name).slice(0, 5).join('、');
      sections.push(`  • ${where}\n    ${badge}${pkgs ? `\n    対象: ${pkgs}` : ''}\n    ▶ 対応ページ: ${publicUrl}/actions/${t.key}`);
    }
    if (actTasks.length > MAX) sections.push(`  …ほか ${actTasks.length - MAX} 件は対応一覧で。`);
  }
  if (others.length) {
    sections.push('', '■ 侵入・監視系の通知（要確認）');
    for (const a of others.slice(0, MAX)) {
      sections.push(`  • 【${L[a.severity] ?? a.severity}】${a.title}${a.detail ? '\n    ' + a.detail.split('\n').slice(0, 2).join('\n    ') : ''}\n    ▶ ${publicUrl}/${a.host_id ? `hosts/${a.host_id}` : 'alerts'}`);
    }
    if (others.length > MAX) sections.push(`  …ほか ${others.length - MAX} 件`);
  }
  sections.push(
    '',
    '――――――',
    `今日やること（優先度順）: ${publicUrl}/`,
    `すべての対応: ${publicUrl}/actions`,
    `脆弱性を絞り込む（KEV/EPSS/公開）: ${publicUrl}/findings`,
  );
  const subject = actTasks.length
    ? `[minisoc2] 今すぐ対応 ${actTasks.length}件${kevN ? `（KEV ${kevN}含む）` : ''}`
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
