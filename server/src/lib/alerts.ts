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

// What gets emailed immediately. Only ORDINARY, non-critical vulnerability findings are held back for
// the daily digest (these were the flood). Everything worth knowing now stays immediate: KEV, anything
// critical, watched CVEs, host/feed/disk health, baselines and informational notices. (Non-critical
// file-integrity / log intrusion signals follow the same critical threshold as before.)
const IMMEDIATE_KINDS = new Set(['kev', 'watch', 'stale', 'feed', 'disk', 'baseline']);
const immediate = (a: { kind: string; severity: string }) => IMMEDIATE_KINDS.has(a.kind) || a.severity === 'critical' || a.severity === 'info';

// Send one mail covering the new urgent (KEV/critical) alerts. The body is grouped by REMEDIATION TASK
// (host × project), because the Claude Code fix prompt is generated per task — so each line links
// straight to the page where that prompt is one click to copy.
export async function notifyPending(publicUrl: string): Promise<{ sent: number; skipped: number; error?: string }> {
  const pending = await q<{ id: string; kind: string; severity: string; title: string; detail: string; created_at: Date; host_id: string | null }>(
    'SELECT id, kind, severity, title, detail, created_at, host_id FROM alerts WHERE notified_at IS NULL ORDER BY created_at LIMIT 500',
  );
  if (!pending.length) return { sent: 0, skipped: 0 };
  const mail = await getMail();
  const toSend = pending.filter(immediate);
  const skip = pending.filter((a) => !immediate(a));
  if (skip.length) await q("UPDATE alerts SET notified_at=now(), notify_error='digest only' WHERE id = ANY($1::bigint[])", [skip.map((a) => a.id)]);
  if (!toSend.length) return { sent: 0, skipped: skip.length };
  if (!mail.enabled) {
    await q("UPDATE alerts SET notified_at=now(), notify_error='mail disabled' WHERE id = ANY($1::bigint[])", [toSend.map((a) => a.id)]);
    return { sent: 0, skipped: pending.length };
  }
  const L: Record<string, string> = { critical: '緊急', high: '高', medium: '中', low: '低', info: '情報' };
  const kevN = toSend.filter((a) => a.kind === 'kev').length;
  const MAX = 15;

  // Fixable vulnerabilities (KEV / vuln findings) → grouped per remediation task (host × project), so
  // each line links straight to the page where the Claude Code fix prompt is one click to copy.
  const hasFix = toSend.some((a) => a.kind === 'kev' || a.kind === 'vuln');
  const tasks = hasFix ? (await listTasks()).filter((t) => t.kev + t.critical > 0) : [];
  // Everything else (stale / feed / disk / baseline / info / critical intrusion signals) → listed as-is.
  const others = toSend.filter((a) => a.kind !== 'kev' && a.kind !== 'vuln');

  const sections: string[] = [`minisoc2 から新しい通知が ${toSend.length} 件あります。`];
  if (tasks.length) {
    sections.push('', `■ 修正が必要な脆弱性（タスクごと・計 ${tasks.length}件／開いて「Claude Code で修正」をコピー）`);
    for (const t of tasks.slice(0, MAX)) {
      const where = t.root === '__os__' ? `${t.host}／OS パッケージ` : `${t.host}／${t.name}`;
      const badge = [t.kev && `KEV ${t.kev}`, t.critical && `緊急 ${t.critical}`].filter(Boolean).join('・');
      const pkgs = t.packages.map((p) => p.name).slice(0, 5).join('、');
      sections.push(`  • ${where}（${badge}）${pkgs ? ' ／ ' + pkgs : ''}\n    → ${publicUrl}/actions/${t.key}`);
    }
    if (tasks.length > MAX) sections.push(`  …ほか ${tasks.length - MAX} 件は一覧で確認してください。`);
  }
  if (others.length) {
    sections.push('', '■ その他の通知');
    for (const a of others.slice(0, MAX)) {
      sections.push(`  • 【${L[a.severity] ?? a.severity}】${a.title}${a.detail ? '\n    ' + a.detail.split('\n').slice(0, 2).join('\n    ') : ''}\n    → ${publicUrl}/${a.host_id ? `hosts/${a.host_id}` : 'alerts'}`);
    }
    if (others.length > MAX) sections.push(`  …ほか ${others.length - MAX} 件`);
  }
  sections.push('', `対応の一覧：${publicUrl}/actions`);
  const subject = `[minisoc2] 新しい通知 ${toSend.length}件${kevN ? `（KEV ${kevN}）` : tasks.length ? `（緊急タスク ${tasks.length}）` : ''}`;
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
