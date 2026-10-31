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

// Immediate mail is limited to the urgent signal: CISA KEV and critical (CVSS 9.0+). Everything else
// (high/medium/low vulns, stale hosts, feed/disk health, baselines, informational) is NOT emailed
// immediately — it stays in the console and is summarised in the daily digest.
const immediate = (a: { kind: string; severity: string }) => a.kind === 'kev' || a.severity === 'critical';

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
  const kevN = toSend.filter((a) => a.kind === 'kev').length;
  const subject = `[minisoc2] 緊急の対応が必要です（新規 ${toSend.length}件${kevN ? `・うち KEV ${kevN}` : ''}）`;

  // The current urgent work, one entry per task, with a direct link to copy its fix prompt.
  const tasks = (await listTasks()).filter((t) => t.kev + t.critical > 0);
  const MAX = 15;
  let body: string;
  if (tasks.length) {
    const lines = tasks.slice(0, MAX).map((t) => {
      const where = t.root === '__os__' ? `${t.host}／OS パッケージ` : `${t.host}／${t.name}`;
      const pkgs = t.packages.map((p) => p.name).slice(0, 5).join('、');
      const badge = [t.kev && `KEV ${t.kev}`, t.critical && `緊急 ${t.critical}`].filter(Boolean).join('・');
      return `■ ${where}（${badge}）\n    対象: ${pkgs || '—'}\n    修正プロンプトをコピー → ${publicUrl}/actions/${t.key}`;
    });
    body = [
      `新しい KEV / 緊急の脆弱性が ${toSend.length} 件見つかりました。`,
      `対応が必要なタスクは現在 ${tasks.length} 件です（下は各タスクのページ。開いて「Claude Code で修正」のプロンプトをコピー→対象ホストで実行）。`,
      '',
      ...lines,
      tasks.length > MAX ? `\n…ほか ${tasks.length - MAX} 件は一覧で確認してください。` : '',
      '',
      `対応の一覧：${publicUrl}/actions`,
    ].filter((x, i, arr) => !(x === '' && arr[i - 1] === '')).join('\n');
  } else {
    // Fallback: no task mapped (e.g. a KEV on a host-level package) — list the alerts themselves.
    body = [
      `新しい KEV / 緊急の通知が ${toSend.length} 件あります。`,
      '',
      ...toSend.slice(0, MAX).map((a) => `■ ${a.title}${a.detail ? '\n    ' + a.detail.split('\n').slice(0, 2).join('\n    ') : ''}\n    → ${publicUrl}/actions${a.host_id ? `?host=${a.host_id}` : ''}`),
      '',
      `対応の一覧：${publicUrl}/actions`,
    ].join('\n');
  }
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
