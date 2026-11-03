// Daily summary mail: action-first (today's top priorities with direct links), then what changed in the
// last 24 hours and the improvement (how many were resolved). Nothing to say -> no mail.
import { q } from './db';
import { sendMail } from './mail';
import { getMail } from './settings';
import { listTasks } from './tasks';

export async function buildDigest(since: Date): Promise<{ subject: string; body: string } | null> {
  const url = (process.env.PUBLIC_URL ?? '').replace(/\/+$/, '');
  const ev = await q<{ title: string; important: boolean; kind: string }>(
    'SELECT title, important, kind FROM change_events WHERE ts >= $1 ORDER BY important DESC, ts DESC', [since],
  );
  const totals = await q<{ kev: string; critical: string; stale: string; resolved: string }>(
    `SELECT (SELECT count(*) FROM findings WHERE status='open' AND kev) AS kev,
            (SELECT count(*) FROM findings WHERE status='open' AND NOT kev AND severity='critical') AS critical,
            (SELECT count(*) FROM hosts WHERE stale_alerted AND NOT disabled) AS stale,
            (SELECT count(*) FROM findings WHERE status='resolved' AND resolved_at >= $1) AS resolved`,
    [since],
  );
  const t = totals[0];
  // Top remediation tasks, already risk-ranked (Act → Attend → Track, then EPSS/exposure).
  const tasks = (await listTasks()).filter((x) => x.kev + x.critical > 0);
  if (!ev.length && !tasks.length) return null;
  const imp = ev.filter((e) => e.important);
  const other = ev.filter((e) => !e.important);
  const pct = (e: number | null) => (e != null ? ` ・ EPSS ${Math.round(e * 100)}%` : '');
  const BK: Record<string, string> = { act: '今すぐ', attend: '今週', track: '様子見' };
  const subject = tasks.length
    ? `[minisoc2] 日次まとめ：今日やる ${Math.min(tasks.length, 3)}件ほか（未対応 KEV ${t.kev} / 緊急 ${t.critical}）`
    : `[minisoc2] 日次まとめ：未対応なし（KEV ${t.kev} / 緊急 ${t.critical}）`;
  const body = [
    '過去24時間のまとめです。',
    `現在の未対応：KEV ${t.kev}件 / 緊急 ${t.critical}件${Number(t.stale) ? ` / 報告停止 ${t.stale}台` : ''}`,
    Number(t.resolved) ? `この24時間で解消：${t.resolved}件 ✅` : '',
    '',
    tasks.length ? '■ 今日やる（優先度順・各行を開いてプロンプトをコピー）' : '■ 対応が必要な脆弱性はありません',
    ...tasks.slice(0, 5).map((x) => {
      const where = x.root === '__os__' ? `${x.host} ／ OSパッケージ` : `${x.host} ／ ${x.name}`;
      const badge = [`[${BK[x.bucket]}]`, x.kev && `KEV ${x.kev}`, x.critical && `緊急 ${x.critical}`, x.exposure === 'public' && '公開'].filter(Boolean).join(' ');
      return `・${badge}${pct(x.epss)}\n    ${where}\n    ▶ ${url}/actions/${x.key}`;
    }),
    tasks.length > 5 ? `  …ほか ${tasks.length - 5}件` : '',
    '',
    imp.length ? '■ 重要な変化（侵入の兆候・監視の停止など）' : '',
    ...imp.slice(0, 10).map((e) => `・${e.title}`),
    imp.length > 10 ? `  …ほか ${imp.length - 10}件` : '',
    other.length ? `\n■ その他の変化 ${other.length}件（高以下・基準線・運用の記録など）` : '',
    ...other.slice(0, 5).map((e) => `・${e.title}`),
    '',
    '――――――',
    `今日やること（優先度順）: ${url}/`,
    `すべての対応: ${url}/actions`,
    `変化の履歴: ${url}/changes`,
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
