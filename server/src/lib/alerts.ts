import { q, q1 } from './db';
import { sendMail } from './mail';
import { atLeast } from './severity';
import { getMail, getPolicy } from './settings';

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

// Kinds that always notify immediately, regardless of the severity threshold.
const ALWAYS = new Set(['watch', 'stale', 'feed', 'kev', 'disk']);
// Informational kinds that only appear in the daily digest.
const DIGEST_ONLY = new Set(['baseline']);

// Send one digest mail with every alert not yet notified. Below-threshold alerts are marked as
// handled without mail (they stay visible in the UI).
export async function notifyPending(publicUrl: string): Promise<{ sent: number; skipped: number; error?: string }> {
  const pending = await q<{ id: string; kind: string; severity: string; title: string; detail: string; created_at: Date; host_id: string | null }>(
    'SELECT id, kind, severity, title, detail, created_at, host_id FROM alerts WHERE notified_at IS NULL ORDER BY created_at LIMIT 500',
  );
  if (!pending.length) return { sent: 0, skipped: 0 };
  const policy = await getPolicy();
  const mail = await getMail();
  const toSend = pending.filter((a) => !DIGEST_ONLY.has(a.kind) && (ALWAYS.has(a.kind) || (a.severity !== 'info' && atLeast(a.severity, policy.notifyMinSeverity))));
  const skip = pending.filter((a) => !toSend.includes(a));
  if (skip.length) await q("UPDATE alerts SET notified_at=now(), notify_error='below threshold' WHERE id = ANY($1::bigint[])", [skip.map((a) => a.id)]);
  // (below-threshold and informational alerts still reach the daily digest through change events)
  if (!toSend.length) return { sent: 0, skipped: skip.length };
  if (!mail.enabled) {
    await q("UPDATE alerts SET notified_at=now(), notify_error='mail disabled' WHERE id = ANY($1::bigint[])", [toSend.map((a) => a.id)]);
    return { sent: 0, skipped: pending.length };
  }
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const L: Record<string, string> = { critical: '緊急', high: '高', medium: '中', low: '低', info: '情報' };
  // KEV and watched CVEs first, then by severity
  const rank = (a: (typeof toSend)[number]) => (a.kind === 'kev' ? -2 : a.kind === 'watch' ? -1 : 0) * 10 + order.indexOf(a.severity);
  toSend.sort((x, y) => rank(x) - rank(y));
  const top = toSend[0];
  const MAX_ITEMS = 10; // a mail is a prompt to look, not the full list
  const counts = order.map((sv) => [sv, toSend.filter((a) => a.severity === sv).length] as const).filter(([, n]) => n);
  const kevN = toSend.filter((a) => a.kind === 'kev').length;
  const subject = toSend.length === 1
    ? `[minisoc2][${L[top.severity]}] ${top.title}`
    : `[minisoc2] 新しい通知 ${toSend.length}件（${kevN ? `KEV ${kevN} / ` : ''}${counts.map(([sv, n]) => `${L[sv]} ${n}`).join(' / ')}）`;
  const body = [
    `minisoc2 から新しい通知が ${toSend.length} 件あります。`,
    toSend.length > 1 ? `内訳：${kevN ? `KEV ${kevN}件、` : ''}${counts.map(([sv, n]) => `${L[sv]} ${n}件`).join('、')}` : '',
    '',
    ...toSend.slice(0, MAX_ITEMS).map((a) => `【${L[a.severity] ?? a.severity}】${a.title}${a.detail ? '\n    ' + a.detail.split('\n').slice(0, 3).join('\n    ') : ''}\n    → ${publicUrl}/actions${a.host_id ? `?host=${a.host_id}` : ''}`),
    toSend.length > MAX_ITEMS ? `\n…ほか ${toSend.length - MAX_ITEMS} 件は管理画面で確認してください。` : '',
    '',
    `対応の一覧：${publicUrl}/actions`,
  ].filter((x, i, arr) => !(x === '' && arr[i - 1] === '')).join('\n');
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
