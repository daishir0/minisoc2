'use client';

import { useState } from 'react';
import { bestFixTarget, recommendedTarget } from '@/lib/version';

export interface PickFinding {
  id: string;
  cve: string; // vuln_id (CVE preferred)
  pkg: string;
  version: string;
  fixed: string;
  severity: string;
  kev: boolean;
}

// Lets the user tick specific CVEs on a project and generates a copy-paste Claude Code prompt that
// asks for a safe, backup-first upgrade plan. Advisory only — the human runs Claude Code on the host.
export function RemediationPicker({ host, address, path, system, findings }: {
  host: string; address: string; path: string; system: string; findings: PickFinding[];
}) {
  const [sel, setSel] = useState<Set<string>>(() => new Set(findings.filter((f) => f.kev || f.severity === 'critical').map((f) => f.id)));
  const [copied, setCopied] = useState(false);

  const toggle = (id: string) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const setAll = (on: boolean) => setSel(on ? new Set(findings.map((f) => f.id)) : new Set());
  const chosen = findings.filter((f) => sel.has(f.id));
  const cves = [...new Set(chosen.map((f) => f.cve))];
  // One row per package@version, with a single branch-aware target that clears every selected CVE on
  // it (the highest of each CVE's own same-major fix) — never a cross-major downgrade.
  const byPkg = new Map<string, { pkg: string; version: string; kev: boolean; fixes: string[] }>();
  for (const f of chosen) {
    const key = `${f.pkg}@${f.version}`;
    const e = byPkg.get(key) ?? { pkg: f.pkg, version: f.version, kev: false, fixes: [] };
    e.kev = e.kev || f.kev;
    if (f.fixed) e.fixes.push(f.fixed);
    byPkg.set(key, e);
  }
  const pkgs = [...byPkg.values()].map((e) => ({ ...e, target: recommendedTarget(e.version, e.fixes) }));

  const prompt = cves.length === 0 ? '（上の一覧で対象のCVEにチェックを入れてください）' : [
    `${host} のホスト（ホスト名：${host}、接続先：${address || '不明'}）の、${path} にあるシステム「${system}」について、脆弱性 ${cves.join('、')} の対応可否を判断し、必要なら安全に解消してください。`,
    ``,
    `# 対象パッケージ（現状 → 修正版の目安）`,
    ...pkgs.map((p) => `- ${p.pkg}: ${p.version || '(現行不明)'}${p.target ? ` → ${p.target} 以上（できれば同一メジャー系列の最新安定版）` : '（修正版は要確認）'}${p.kev ? '  ［KEV: 悪用確認済み・最優先］' : ''}`),
    ``,
    `# まず判定（重要）`,
    `${path} 配下のコード・依存・設定・実行環境を精査し、各CVEが**このシステムで実際に到達・悪用可能か**を評価してください（例：ランタイムが無い／該当コードが配置・実行されない／ビルド専用の devDependency で本番に関与しない、等）。その上で**結論を最初に明示**してください：`,
    `  (a) 修正する（到達可能、または予防的に妥当）`,
    `  (b) 影響なし＝対処不要（理由を明記。この場合は**ファイルを変更せず**、理由と、minisoc2 に登録できる VEX 区分 code_not_present / code_not_reachable / requires_environment / requires_configuration などを併記）`,
    `  (c) 要確認（判断材料が足りない点を具体的に）`,
    `**対処が無意味なとき（(b)）は、無理にアップグレードせず、その旨をはっきり報告**してください（lockfileだけの書き換え等、実害ゼロの"作業のための作業"はしない）。`,
    ``,
    `# (a) 修正する場合のお願い`,
    `1. バージョンは上記「→」の版**以上**にする。ダウングレード（別メジャー系列の修正版へ落とす）はしない。可能なら同一メジャー系列の最新安定版まで上げる。`,
    `2. 変更前のバックアップ／スナップショット取得と、問題時のロールバック手順を必ず含める。`,
    `3. 段階的なアップグレード手順（最小差分）と、各段階の動作確認・テスト計画を提示。`,
    `4. 実行は人間の承認後。破壊的操作やサービス停止は必要最小限に。`,
  ].join('\n');

  const copy = async () => {
    try { await navigator.clipboard.writeText(prompt); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };

  // Findings not pre-selected by default (default = KEV + critical only). Surfaced so the user knows
  // the lower-severity issues are detected and selectable, not missing.
  const extra = { high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const f of findings) if (!f.kev && f.severity !== 'critical' && f.severity in extra) extra[f.severity]++;
  const extraNote = [extra.high && `高 ${extra.high}`, extra.medium && `中 ${extra.medium}`, extra.low && `低 ${extra.low}`].filter(Boolean).join('・');

  const sevOrder = (s: string) => ({ critical: 0, high: 1, medium: 2, low: 3 } as Record<string, number>)[s] ?? 4;
  const sorted = [...findings].sort((a, b) => Number(b.kev) - Number(a.kev) || sevOrder(a.severity) - sevOrder(b.severity));
  // row tint + severity chip by how critical it is (KEV = actively exploited, treated as highest)
  const tier = (f: PickFinding) => (f.kev ? 'kev' : f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'medium' : 'low');
  const ROW: Record<string, string> = {
    kev: 'border-l-4 border-red-600 bg-red-50 dark:bg-red-950/40',
    critical: 'border-l-4 border-red-500 bg-red-50/60 dark:bg-red-950/20',
    high: 'border-l-4 border-orange-400',
    medium: 'border-l-4 border-yellow-400',
    low: 'border-l-4 border-slate-300 dark:border-slate-600',
  };
  const CHIP: Record<string, string> = {
    kev: 'bg-red-600 text-white', critical: 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-200',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200', low: 'bg-bg text-muted',
  };
  const LABEL: Record<string, string> = { kev: 'KEV', critical: '緊急', high: '高', medium: '中', low: '低' };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span className="text-muted">{sel.size} / {findings.length} 件を選択中</span>
        <button type="button" onClick={() => setAll(true)} className="text-accent hover:underline">すべて選択</button>
        <button type="button" onClick={() => setAll(false)} className="text-accent hover:underline">選択解除</button>
        <span className="ml-auto flex flex-wrap items-center gap-1.5">
          <span className="text-muted">凡例：</span>
          {(['kev', 'critical', 'high', 'medium', 'low'] as const).map((t) => (
            <span key={t} className={`rounded px-1.5 py-0.5 text-[10px] ${CHIP[t]}`}>{LABEL[t]}</span>
          ))}
        </span>
      </div>
      {extraNote && (
        <p className="text-xs text-muted">
          初期選択は KEV・緊急のみです。これ以外に{extraNote}の脆弱性も検出しています（下の一覧でチェックすれば同じプロンプトに含められます）。
        </p>
      )}
      <div className="max-h-64 overflow-y-auto rounded border border-line">
        <table className="tbl"><thead><tr><th className="w-8"></th><th>深刻度</th><th>CVE</th><th>パッケージ</th><th>現状→修正</th></tr></thead><tbody>
          {sorted.map((f) => {
            const t = tier(f);
            return (
              <tr key={f.id} className={`cursor-pointer ${ROW[t]}`} onClick={() => toggle(f.id)}>
                <td><input type="checkbox" checked={sel.has(f.id)} onChange={() => toggle(f.id)} onClick={(e) => e.stopPropagation()} /></td>
                <td><span className={`rounded px-1.5 py-0.5 text-[10px] ${CHIP[t]}`}>{LABEL[t]}</span></td>
                <td className="whitespace-nowrap font-mono text-xs">{f.cve}</td>
                <td className="break-all font-mono text-xs">{f.pkg}</td>
                <td className="whitespace-nowrap font-mono text-xs text-muted">{f.version.slice(0, 20)}{(() => { const t = bestFixTarget(f.version, (f.fixed || '').split(/,\s*/)); return t ? ` → ${t.slice(0, 20)}` : ''; })()}</td>
              </tr>
            );
          })}
        </tbody></table>
      </div>
      <div className="flex justify-end">
        <button type="button" onClick={copy} disabled={cves.length === 0} className="btn-ghost text-xs disabled:opacity-50">{copied ? 'コピーしました' : 'クリップボードにコピー'}</button>
      </div>
      <pre className="max-h-96 select-all overflow-auto whitespace-pre-wrap break-words rounded bg-bg p-3 text-xs">{prompt}</pre>
    </div>
  );
}
