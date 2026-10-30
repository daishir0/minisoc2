import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { CveSearch } from '@/components/CveSearch';
import { Card, Kev, Sev, ago } from '@/components/ui';
import { lookupCve, normalizeCve, type HostState } from '@/lib/cvelookup';
import { watchCve } from '../../actions';

const STATE: Record<HostState, { icon: string; label: string; cls: string }> = {
  affected: { icon: '🔴', label: '影響あり', cls: 'text-red-600' },
  fixed: { icon: '🟢', label: '影響なし（修正済み・対象外）', cls: 'text-green-600' },
  not_present: { icon: '🟢', label: '影響なし（対象ソフトなし）', cls: 'text-green-600' },
  vex: { icon: '🟢', label: '影響なし（判断済み）', cls: 'text-green-600' },
  potential: { icon: '🟠', label: '要確認（勧告待ち）', cls: 'text-orange-600' },
  unknown: { icon: '⚪', label: '判定できない', cls: 'text-muted' },
};

const OVERALL = {
  affected: { icon: '🔴', title: '影響を受けるホストがあります', cls: 'border-red-500 bg-red-50 dark:bg-red-950' },
  clear: { icon: '🟢', title: 'すべてのホストで影響はありません', cls: 'border-green-500 bg-green-50 dark:bg-green-950' },
  unknown: { icon: '⚪', title: '判定できないホストがあります', cls: 'border-line bg-panel' },
};

export default async function CveDetail({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ refresh?: string }> }) {
  const { id } = await params;
  const { refresh } = await searchParams;
  const cve = normalizeCve(decodeURIComponent(id));
  if (!cve) notFound();
  const v = await lookupCve(cve, refresh === '1');
  const o = OVERALL[v.overall];
  const ext = v.external;

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, CRUMB.detect, CRUMB.cveLookup]} />
      <CveSearch />
      <section className={`rounded-lg border-2 p-4 ${o.cls}`}>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="font-mono text-xl font-semibold">{cve}</h1>
          {v.kev && <Kev />}
          {ext.nvd?.severity && <Sev s={ext.nvd.severity === 'moderate' ? 'medium' : ext.nvd.severity} />}
          {ext.nvd?.score != null && <span className="text-sm text-muted">CVSS {ext.nvd.score}</span>}
        </div>
        <p className="mt-2 text-lg font-semibold">{o.icon} {o.title}</p>
        {v.overall === 'unknown' && <p className="mt-1 text-sm text-muted">「判定できない」は安全という意味ではありません。理由を確認し、必要なら CVE監視に入れておくと、ホストで検出された時点で通知します。</p>}
        <div className="mt-3 flex flex-wrap gap-2">
          {!v.watched ? (
            <form action={watchCve}><input type="hidden" name="cve" value={cve} /><button className="btn">CVE監視に追加</button></form>
          ) : <Link href="/watch" className="btn-ghost">監視中</Link>}
          <Link href={`/cve/${cve}?refresh=1`} className="btn-ghost">最新の情報を取り直す</Link>
          <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer" className="btn-ghost">NVD</a>
        </div>
      </section>

      <Card title="ホストごとの判定">
        <ul className="divide-y divide-line">
          {v.hosts.map((h) => (
            <li key={h.hostId} className="py-3">
              <div className="flex flex-wrap items-baseline gap-2">
                <Link href={`/hosts/${h.hostId}`} className="font-medium text-accent">{h.host}</Link>
                <span className="text-xs text-muted">{h.os}</span>
                <span className={`ml-auto text-sm font-semibold ${STATE[h.state].cls}`}>{STATE[h.state].icon} {STATE[h.state].label}</span>
              </div>
              <ul className="mt-1 list-disc pl-5 text-sm text-muted">
                {h.reasons.map((r, i) => <li key={i} className="break-words">{r}</li>)}
              </ul>
            </li>
          ))}
        </ul>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="この CVE について（NVD）">
          {ext.nvd ? (
            <div className="space-y-2 text-sm">
              <p className="break-words">{ext.nvd.description || '説明はまだ登録されていません。'}</p>
              <p className="text-xs text-muted">公開 {ext.nvd.published?.slice(0, 10) ?? '-'} · 状態 {ext.nvd.status ?? '-'}</p>
              {ext.nvd.products.length > 0 && <p className="text-xs text-muted">対象製品（CPE）：{ext.nvd.products.join('、')}</p>}
              {v.kev && <p className="text-xs text-red-600">CISA KEV 登録 {v.kev.date_added}：{v.kev.name}</p>}
            </div>
          ) : <p className="text-sm text-muted">NVD にこの CVE の情報がありません（公開直後や予約中の番号の場合があります）。</p>}
        </Card>
        <Card title="影響するパッケージ（GitHub Advisory）">
          {ext.ghsa.length === 0 ? <p className="text-sm text-muted">登録がありません。アプリの依存ライブラリ向けの情報が無い CVE です（OS やミドルウェア本体の脆弱性に多い）。</p> : (
            <ul className="space-y-3 text-sm">
              {ext.ghsa.map((a) => (
                <li key={a.id}>
                  <a href={`https://github.com/advisories/${a.id}`} target="_blank" rel="noreferrer" className="font-mono text-accent">{a.id}</a>
                  <span className="ml-2 text-muted">{a.summary}</span>
                  <ul className="mt-1 pl-4 font-mono text-xs">
                    {a.packages.map((p, i) => <li key={i} className="break-all">{p.ecosystem} {p.name}：{p.range}{p.patched ? ` → ${p.patched}` : ''}</li>)}
                  </ul>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      <p className="text-xs text-muted">
        外部情報の取得：{ago(ext.fetchedAt)}（6時間キャッシュ）{ext.errors.length ? ` · 取得エラー：${ext.errors.join(' / ')}` : ''}
        ／ ホストの情報は各エージェントの最新の報告にもとづきます。
      </p>
    </>
  );
}
