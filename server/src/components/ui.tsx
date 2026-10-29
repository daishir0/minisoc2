import Link from 'next/link';

const SEV: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-400 text-black',
  low: 'bg-sky-500 text-white',
  info: 'bg-slate-400 text-white',
  unknown: 'bg-slate-300 text-black',
};

export const SEV_LABEL: Record<string, string> = { critical: '緊急', high: '高', medium: '中', low: '低', info: '情報', unknown: '不明' };

export function Sev({ s }: { s: string }) {
  return <span className={`inline-block whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-semibold ${SEV[s] ?? SEV.unknown}`}>{SEV_LABEL[s] ?? s}</span>;
}

export function Kev() {
  return <span className="inline-block rounded bg-red-900 px-1.5 py-0.5 text-[11px] font-semibold text-white" title="CISA KEV：実際に悪用が確認された脆弱性">KEV</span>;
}

export function Card({ title, children, right }: { title?: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="min-w-0 rounded-lg border border-line bg-panel">
      {title && (
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {right}
        </div>
      )}
      <div className="overflow-x-auto p-4">{children}</div>
    </section>
  );
}

export function Stat({ label, value, href, tone }: { label: string; value: number | string; href?: string; tone?: string }) {
  const body = (
    <div className="rounded-lg border border-line bg-panel p-4">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${tone ?? ''}`}>{value}</div>
    </div>
  );
  return href ? <Link href={href}>{body}</Link> : body;
}

export function ago(d: Date | string | null | undefined): string {
  if (!d) return 'なし';
  const s = Math.round((Date.now() - new Date(d).getTime()) / 1000);
  if (s < 60) return `${s}秒前`;
  if (s < 3600) return `${Math.round(s / 60)}分前`;
  if (s < 86400) return `${Math.round(s / 3600)}時間前`;
  return `${Math.round(s / 86400)}日前`;
}

export function vulnLink(id: string) {
  const href = /^CVE-/.test(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://osv.dev/vulnerability/${id}`;
  return (
    <a href={href} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">
      {id}
    </a>
  );
}
