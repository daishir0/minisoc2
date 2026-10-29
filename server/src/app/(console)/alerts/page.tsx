import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, Sev, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { alertFormAction } from '../actions';

const ALERT_STATUS: Record<string, string> = { open: '重要', other: 'その他', ack: '確認済み', resolved: '解決済み' };
const MAIL_NOTE: Record<string, string> = { 'below threshold': '通知の基準未満', 'mail disabled': 'メール通知オフ' };
const KIND: Record<string, string> = { vuln: '脆弱性', kev: 'KEV', watch: 'CVE監視', stale: '報告停止', feed: 'フィード', baseline: '基準線', agent: 'エージェント', state: 'ホスト状態', log: 'ログ', disk: 'ディスク' };

export default async function AlertsPage({ searchParams }: { searchParams: Promise<{ status?: string }> }) {
  const { status: s } = await searchParams;
  const tab = ['open', 'other', 'ack', 'resolved'].includes(s ?? '') ? s! : 'open';
  const status = tab === 'other' ? 'open' : tab;
  // "important" = what the policy surfaces: critical, KEV, watched CVEs, monitoring health
  const IMPORTANT = "(severity='critical' OR kind IN ('kev','watch','stale','feed','disk'))";
  const scope = tab === 'open' ? `AND ${IMPORTANT}` : tab === 'other' ? `AND NOT ${IMPORTANT}` : '';
  const rows = await q<{ id: string; kind: string; severity: string; title: string; detail: string; created_at: Date; notified_at: Date | null; notify_error: string | null; host_id: string | null }>(
    `SELECT id, kind, severity, title, detail, created_at, notified_at, notify_error, host_id FROM alerts WHERE status=$1 ${scope} ORDER BY created_at DESC LIMIT 300`,
    [status],
  );
  const otherN = Number((await q<{ n: string }>(`SELECT count(*) AS n FROM alerts WHERE status='open' AND NOT ${IMPORTANT}`))[0].n);
  return (
    <>
    <Breadcrumbs items={[CRUMB.home, { label: "検知" }]} />
      <ExploreTabs />
    <Card
      title="検知の記録"
      right={
        <div className="flex gap-2 text-sm">
          {['open', 'other', 'ack', 'resolved'].map((x) => (
            <Link key={x} href={`/alerts?status=${x}`} className={x === tab ? 'font-semibold' : 'text-muted'}>{ALERT_STATUS[x]}{x === 'other' ? `（${otherN}）` : ''}</Link>
          ))}
        </div>
      }
    >
      {tab === 'open' && <p className="mb-3 text-xs text-muted">KEV・緊急・侵入の兆候・監視の停止など、すぐ通知する対象の未対応アラートです。高以下は「その他」にあります。</p>}
      {tab === 'other' && <p className="mb-3 text-xs text-muted">通知の対象外（高以下・情報）の未対応アラートです。日次まとめと詳細画面でのみ扱います。</p>}
      {rows.length === 0 ? <p className="text-sm text-muted">該当するアラートはありません。</p> : (
        <ul className="divide-y divide-line">
          {rows.map((a) => (
            <li key={a.id} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-start sm:gap-3">
              <div className="flex min-w-0 flex-1 gap-3">
              <Sev s={a.severity} />
              <div className="min-w-0 flex-1 break-words">
                <div className="text-sm">{a.title}</div>
                {a.detail && <pre className="mt-1 whitespace-pre-wrap text-xs text-muted">{a.detail}</pre>}
                <div className="mt-1 text-xs text-muted">
                  {KIND[a.kind] ?? a.kind} · {ago(a.created_at)} · {a.notified_at ? (a.notify_error ? `メール送信なし（${MAIL_NOTE[a.notify_error] ?? a.notify_error}）` : 'メール送信済み') : a.notify_error ? `メール送信失敗：${a.notify_error}` : 'メール送信待ち'}
                  {a.host_id && <> · <Link className="text-accent" href={`/hosts/${a.host_id}`}>ホスト</Link></>}
                </div>
              </div>
              </div>
              <form action={alertFormAction} className="flex gap-1 pl-10 sm:pl-0">
                <input type="hidden" name="id" value={a.id} />
                {status !== 'ack' && <button name="status" value="ack" className="btn-ghost">確認済み</button>}
                {status !== 'resolved' && <button name="status" value="resolved" className="btn-ghost">解決</button>}
                {status !== 'open' && <button name="status" value="open" className="btn-ghost">未対応に戻す</button>}
              </form>
            </li>
          ))}
        </ul>
      )}
    </Card>
    </>
  );
}
