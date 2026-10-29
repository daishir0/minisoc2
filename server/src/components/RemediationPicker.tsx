'use client';

import { useState } from 'react';

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
  const pkgs = [...new Map(chosen.map((f) => [`${f.pkg}@${f.version}`, f])).values()];

  const prompt = cves.length === 0 ? '（上の一覧で対象のCVEにチェックを入れてください）' : [
    `${host} のホスト（ホスト名：${host}、接続先：${address || '不明'}）の、${path} にあるシステム「${system}」について、脆弱性 ${cves.join('、')} の解消が必要です。それぞれの脆弱性を理解した上で、対象ディレクトリ配下を詳細まで調査して、安全にアップグレードする方法を提案して。なお、その提案には、脆弱性の対策実行プランとテスト計画も含みますが、途中なんらかの有事・対処前に戻すことも確保する必要があるため、バックアップ処理なども含めた、きわめて安全なプランとして提案をすること。`,
    ``,
    `# 対象パッケージ（現状 → 修正版の目安）`,
    ...pkgs.map((f) => `- ${f.pkg}: ${f.version || '(現行不明)'}${f.fixed ? ` → ${f.fixed}` : '（修正版は要確認）'}${f.kev ? '  ［KEV: 悪用確認済み・最優先］' : ''}`),
    ``,
    `# お願いしたいこと`,
    `1. まず上記CVEの内容と、このシステムへの実際の影響範囲を調査（${path} 配下のコード・依存・設定を精査）。`,
    `2. 変更前のバックアップ／スナップショット取得と、問題時のロールバック手順を必ず含める。`,
    `3. 段階的なアップグレード手順（最小差分）と、各段階の動作確認・テスト計画を提示。`,
    `4. 実行は人間の承認後。破壊的操作やサービス停止は必要最小限に。`,
  ].join('\n');

  const copy = async () => {
    try { await navigator.clipboard.writeText(prompt); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };

  const sevOrder = (s: string) => ({ critical: 0, high: 1, medium: 2, low: 3 } as Record<string, number>)[s] ?? 4;
  const sorted = [...findings].sort((a, b) => Number(b.kev) - Number(a.kev) || sevOrder(a.severity) - sevOrder(b.severity));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span className="text-muted">{sel.size} / {findings.length} 件を選択中</span>
        <button type="button" onClick={() => setAll(true)} className="text-accent hover:underline">すべて選択</button>
        <button type="button" onClick={() => setAll(false)} className="text-accent hover:underline">選択解除</button>
      </div>
      <div className="max-h-64 overflow-y-auto rounded border border-line">
        <table className="tbl"><thead><tr><th className="w-8"></th><th>CVE</th><th>パッケージ</th><th>現状→修正</th></tr></thead><tbody>
          {sorted.map((f) => (
            <tr key={f.id} className="cursor-pointer" onClick={() => toggle(f.id)}>
              <td><input type="checkbox" checked={sel.has(f.id)} onChange={() => toggle(f.id)} onClick={(e) => e.stopPropagation()} /></td>
              <td className="whitespace-nowrap font-mono text-xs">{f.kev && <span className="mr-1 rounded bg-red-600 px-1 text-[10px] text-white">KEV</span>}{f.cve}</td>
              <td className="break-all font-mono text-xs">{f.pkg}</td>
              <td className="whitespace-nowrap font-mono text-xs text-muted">{f.version.slice(0, 20)}{f.fixed ? ` → ${f.fixed.slice(0, 20)}` : ''}</td>
            </tr>
          ))}
        </tbody></table>
      </div>
      <div className="flex justify-end">
        <button type="button" onClick={copy} disabled={cves.length === 0} className="btn-ghost text-xs disabled:opacity-50">{copied ? 'コピーしました' : 'クリップボードにコピー'}</button>
      </div>
      <pre className="max-h-96 select-all overflow-auto whitespace-pre-wrap break-words rounded bg-bg p-3 text-xs">{prompt}</pre>
    </div>
  );
}
