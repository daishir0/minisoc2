// Daily summary mail: what changed in the last 24 hours, important items first. Nothing changed -> no mail.
import { q } from './db';
import { sendMail } from './mail';
import { getMail } from './settings';

export async function buildDigest(since: Date): Promise<{ subject: string; body: string } | null> {
  const ev = await q<{ title: string; important: boolean; kind: string }>(
    'SELECT title, important, kind FROM change_events WHERE ts >= $1 ORDER BY important DESC, ts DESC', [since],
  );
  if (!ev.length) return null;
  const imp = ev.filter((e) => e.important);
  const other = ev.filter((e) => !e.important);
  const totals = await q<{ kev: string; critical: string; stale: string }>(
    `SELECT (SELECT count(*) FROM findings WHERE status='open' AND kev) AS kev,
            (SELECT count(*) FROM findings WHERE status='open' AND NOT kev AND severity='critical') AS critical,
            (SELECT count(*) FROM hosts WHERE stale_alerted AND NOT disabled) AS stale`,
  );
  const t = totals[0];
  const subject = imp.length
    ? `[minisoc2] 日次まとめ：重要な変化 ${imp.length}件（未対応 KEV ${t.kev} / 緊急 ${t.critical}）`
    : `[minisoc2] 日次まとめ：重要な変化なし（未対応 KEV ${t.kev} / 緊急 ${t.critical}）`;
  const body = [
    `過去24時間の変化です。`,
    `現在の未対応：KEV ${t.kev}件 / 緊急 ${t.critical}件${Number(t.stale) ? ` / 報告停止のホスト ${t.stale}台` : ''}`,
    '',
    imp.length ? '■ 重要（KEV・緊急・侵入の兆候・監視の停止）' : '■ 重要な変化はありません',
    ...imp.slice(0, 15).map((e) => `・${e.title}`),
    imp.length > 15 ? `  …ほか ${imp.length - 15}件` : '',
    other.length ? `\n■ その他の変化 ${other.length}件（高以下の脆弱性・基準線・運用の記録など。詳細は管理画面）` : '',
    ...other.slice(0, 5).map((e) => `・${e.title}`),
    '',
    `対応の一覧：${(process.env.PUBLIC_URL ?? '').replace(/\/+$/, '')}/actions`,
    `変化の履歴：${(process.env.PUBLIC_URL ?? '').replace(/\/+$/, '')}/changes`,
  ].filter((x, i, a) => !(x === '' && a[i - 1] === '')).join('\n');
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
