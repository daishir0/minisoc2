'use client';

import { useState } from 'react';
import { CopyBlock } from '@/components/CopyBlock';
import { DrillLink } from '@/components/DrillLink';
import { Masked, MaskFree } from '@/components/Mask';
import { logThreatPrompt } from '@/lib/logprompt';

// One row per open log threat. The server page passes these down already-shaped (ago as text, ip
// pre-extracted) so this client component stays free of server-only imports.
export interface ThreatRow {
  id: string;
  host: string | null;
  hostId: string | null;
  address: string;
  title: string;
  detail: string | null;
  agoText: string;
  ip: string | null;
  topic: string;              // dedupe stem (no date) — the benign-review key
  benignReviewable: boolean;  // show the "benign (downgrade future)" action
}

// Mirrors the vulnerability page's RemediationPicker: tick the threats you want, get ONE copy-paste
// Claude Code investigation prompt. Because the prompt opens with a host-guard (hostname must match),
// one prompt == one host: selections spanning hosts produce one prompt per host (never mixed).
export function LogThreatPicker({ threats, ackAction, trustAction, benignAction }: {
  threats: ThreatRow[];
  ackAction: (fd: FormData) => void | Promise<void>;
  trustAction: (fd: FormData) => void | Promise<void>;
  benignAction: (fd: FormData) => void | Promise<void>;
}) {
  const [sel, setSel] = useState<Set<string>>(() => new Set(threats.map((t) => t.id)));
  const [show, setShow] = useState(false);
  const toggle = (id: string) => setSel((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const allOn = threats.length > 0 && sel.size === threats.length;

  // Selected threats grouped by host → one prompt per host.
  const byHost = new Map<string, { host: string; address: string; hostId: string; items: ThreatRow[] }>();
  for (const t of threats) {
    if (!sel.has(t.id) || !t.hostId) continue;
    const g = byHost.get(t.hostId) ?? { host: t.host ?? '', address: t.address, hostId: t.hostId, items: [] };
    g.items.push(t);
    byHost.set(t.hostId, g);
  }
  const groups = [...byHost.values()];
  const sevClear = { source: '', vhost: '', rule: '', q: '', status: '', day: '' } as const;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-xs text-muted">
          <input type="checkbox" checked={allOn} onChange={(e) => setSel(e.target.checked ? new Set(threats.map((t) => t.id)) : new Set())} />
          すべて選択
        </label>
        <button type="button" onClick={() => setShow((v) => !v)} disabled={!sel.size} className="btn text-xs disabled:opacity-50">
          {show ? '閉じる' : `📋 選択した脅威の調査プロンプトを生成（${sel.size}）`}
        </button>
        {show && groups.length > 1 && <span className="text-xs text-muted">※ 複数ホストはホストごとに分割（取り違え防止）</span>}
      </div>

      <ul className="divide-y divide-line">
        {threats.map((t) => {
          // Land the explorer in the right context for this anomaly: its journal source (exact), or the
          // web category, plus the anomaly's day when the title/detail names one. The 観点 switcher then
          // flips between angles from there.
          const srcM = t.title.match(/source:(journal:[^\s（）]+)/);
          const dayM = (t.detail ?? t.title).match(/\d{4}-\d{2}-\d{2}/);
          const isWeb = /access[_.]log|Web|4xx|5xx|リクエスト/i.test(t.title);
          const drillPatch = {
            host: t.hostId ?? '', ...sevClear,
            source: srcM ? srcM[1] : '',
            cat: !srcM && isWeb ? 'web' : '',
            day: dayM ? dayM[0] : '',
          };
          return (
            <li key={t.id} className="flex flex-col gap-2 py-2 sm:flex-row sm:items-start sm:gap-3">
              <input type="checkbox" checked={sel.has(t.id)} onChange={() => toggle(t.id)} className="mt-1 sm:mt-1.5" aria-label="この脅威を選択" />
              <div className="min-w-0 flex-1">
                <div className="text-sm"><span className="mr-1">⚠</span><MaskFree>{t.title}</MaskFree></div>
                <div className="text-xs text-muted">{t.host ? <><Masked kind="host">{t.host}</Masked> · </> : ''}{t.agoText}</div>
              </div>
              <div className="flex flex-wrap gap-1 sm:shrink-0">
                {t.ip && <form action={trustAction}><input type="hidden" name="id" value={t.id} /><input type="hidden" name="ip" value={t.ip} /><button className="btn-ghost">自分です（<Masked kind="addr">{t.ip}</Masked>）</button></form>}
                {t.hostId && <DrillLink patch={drillPatch} className="btn-ghost">調べる</DrillLink>}
                <form action={ackAction}><input type="hidden" name="id" value={t.id} /><button name="status" value="ack" className="btn-ghost">確認済み</button></form>
                {t.benignReviewable && t.hostId && (
                  <form action={benignAction}>
                    <input type="hidden" name="id" value={t.id} />
                    <input type="hidden" name="hostId" value={t.hostId} />
                    <input type="hidden" name="topic" value={t.topic} />
                    <button className="btn-ghost" title="この種別の再発を今後は日次まとめのみに格下げ（偵察ノイズの抑制）">今後は確認不要（benign）</button>
                  </form>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      {show && groups.map((g) => (
        <div key={g.hostId} className="rounded-lg border border-line p-2">
          {groups.length > 1 && <div className="mb-1 text-xs font-semibold"><Masked kind="host">{g.host}</Masked>（{g.items.length}件）</div>}
          <CopyBlock
            text={logThreatPrompt({ host: g.host, address: g.address, hostId: g.hostId }, g.items.map((t) => ({ title: t.title, detail: t.detail })))}
            mask={[{ from: g.host, kind: 'host' }, { from: g.address, kind: 'addr' }]}
          />
        </div>
      ))}
    </div>
  );
}
