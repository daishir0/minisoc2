'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { bestFixTarget, recommendedTarget } from '@/lib/version';
import { suppressSelected } from '@/app/(console)/actions';

// Plain-language reasons, mapped to CycloneDX VEX justifications. Covers the common cases without the
// jargon; "迷ったら①" is the safe default for unused / build-only dependencies.
const VEX_PRESETS: { code: string; label: string }[] = [
  { code: 'code_not_present', label: '① 使われていない・実行されない（開発/ビルド用の依存、未インストール 等）' },
  { code: 'requires_environment', label: '② この環境では動かない（必要なランタイム/設定/依存がない）' },
  { code: 'code_not_reachable', label: '③ コードはあるが、呼び出されない（到達しない）' },
  { code: 'protected_by_mitigating_control', label: '④ 別の対策で防いでいる（WAF・設定・緩和策 等）' },
];

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
export function RemediationPicker({ host, address, path, system, systemId, osId, findings }: {
  host: string; address: string; path: string; system: string; systemId: number; osId?: string; findings: PickFinding[];
}) {
  const isOs = osId !== undefined;
  const pm = osId && ['debian', 'ubuntu'].includes(osId) ? 'apt' : 'dnf';
  const [sel, setSel] = useState<Set<string>>(() => new Set(findings.filter((f) => f.kev || f.severity === 'critical').map((f) => f.id)));
  const [copied, setCopied] = useState(false);
  const router = useRouter();
  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [vexBusy, startVex] = useTransition();
  const [vexMsg, setVexMsg] = useState('');
  // Rows marked "not affected" this session are hidden at once; the server re-match (which drops them
  // from picks) can lag a few seconds, especially on pull hosts, so we don't wait for it.
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const visible = findings.filter((f) => !hidden.has(f.id));

  const markNotAffected = () => {
    const ids = [...sel];
    if (!ids.length || !reason) return;
    setVexMsg('');
    startVex(async () => {
      try {
        const r = await suppressSelected(ids, reason, note, path, `/systems/${systemId}`);
        setVexMsg(`✅ ${r.n}件を「影響なし」で登録しました（アラート停止・緊急件数から除外）`);
        setHidden((prev) => new Set([...prev, ...ids]));
        setSel(new Set());
        router.refresh();
      } catch { setVexMsg('⚠ 登録に失敗しました。'); }
    });
  };

  const toggle = (id: string) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const setAll = (on: boolean) => setSel(on ? new Set(visible.map((f) => f.id)) : new Set());
  const chosen = visible.filter((f) => sel.has(f.id));
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

  // OS packages are fixed with the system package manager (apt/dnf), not pip/npm — generate a distinct prompt.
  const osPkgList = [...new Set(chosen.map((f) => f.pkg.replace(/^(kernel|linux)[\w.-]*$/, (m) => (m.startsWith('kernel') ? 'kernel*' : 'linux-*'))))].slice(0, 20).join(' ');
  const osCmd = pm === 'apt' ? `sudo apt-get update && sudo apt-get install --only-upgrade ${osPkgList}` : `sudo dnf upgrade${osId === 'amzn' ? ' --releasever=latest' : ''} ${osPkgList}`;
  const osPkgNames = [...new Set(chosen.map((f) => f.pkg))];
  const cveSummary = cves.length <= 6 ? cves.join('、') : `${cves.slice(0, 6).join('、')} 他${cves.length - 6}件`;
  const kevN2 = chosen.filter((f) => f.kev).length;
  const osPrompt = cves.length === 0 ? '（上の一覧で対象のCVEにチェックを入れてください）' : [
    `ホスト「${host}」の **OS パッケージ（kernel 等・ホスト全体）** に、脆弱性が ${cves.length} 件（${kevN2 ? `KEV ${kevN2}・` : ''}緊急含む）あります。`,
    `OSパッケージ（特に kernel）は累積更新です。**最新のセキュリティ更新を1回当てれば、旧バージョンにあるこれらのCVEはまとめて解消**します。CVEを1件ずつ個別に当てる必要はありません。`,
    ``,
    `# 推奨アクション`,
    `1. まずこのホストで該当機能の使用有無などから影響を評価し、結論を明示：(a) 更新する ／ (b) 影響なし＝対処不要（理由＋VEX区分）／ (c) 要確認。`,
    `2. (a) の場合、OSのセキュリティ更新を適用（kernel は最新へ）：`,
    ``,
    `    ${osCmd}`,
    `    （または全体更新：${pm === 'apt' ? 'sudo apt-get update && sudo apt-get upgrade' : `sudo dnf upgrade${osId === 'amzn' ? ' --releasever=latest' : ''}`}）`,
    ``,
    `3. kernel を更新したら **再起動**（\`sudo reboot\`）。稼働中カーネルは再起動で新版に切り替わります（利用者影響があれば事前合意）。`,
    `4. 変更前にスナップショット/バックアップとロールバック手順を用意。配布元が修正版を未リリースの場合は無理に上げず「要確認」で報告。`,
    `5. 完了後、minisoc2 の「今すぐ収集」で確認（更新＋再起動で該当 ${cves.length} 件がまとめて解消します）。`,
    ``,
    `# 参考（対象）`,
    `- 対象パッケージ：${osPkgNames.slice(0, 12).join('、')}${osPkgNames.length > 12 ? ` 他${osPkgNames.length - 12}件` : ''}`,
    `- 対象CVE（${cves.length}件）：${cveSummary}`,
  ].join('\n');
  const appPrompt = cves.length === 0 ? '（上の一覧で対象のCVEにチェックを入れてください）' : [
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
    `2. **実インストールと、minisoc2 が参照するマニフェストの両方を一致させること**（これをしないと解消が正しく捕捉されません）：`,
    `   - Python：実行環境で \`pip install 'パッケージ==版'\` と、**requirements.txt の該当ピンも同じ版に更新**（共用envでも各プロジェクトの requirements.txt を更新）。`,
    `   - npm：\`npm install パッケージ@版\` で **package-lock.json を再生成**。`,
    `   - PHP(composer)：\`composer update パッケージ\` で **composer.lock を更新**。`,
    `   - ★片方だけは不可：**実環境だけ**上げてマニフェスト未更新＝minisoc2 は『未解消』のまま／**マニフェストだけ**書き換えて実体を上げない＝実害ゼロの偽修正。`,
    `3. 変更前のバックアップ／スナップショット取得と、問題時のロールバック手順を必ず含める。`,
    `4. 段階的なアップグレード手順（最小差分）と、各段階の動作確認・テスト計画を提示。`,
    `5. 実行は人間の承認後。破壊的操作やサービス停止は必要最小限に。`,
    `6. 完了後、対象ホストで収集を実行（minisoc2 画面の「今すぐ収集」ボタンでも可）し、minisoc2 上で解消を確認する。`,
  ].join('\n');
  const prompt = isOs ? osPrompt : appPrompt;

  const copy = async () => {
    try { await navigator.clipboard.writeText(prompt); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };

  // Findings not pre-selected by default (default = KEV + critical only). Surfaced so the user knows
  // the lower-severity issues are detected and selectable, not missing.
  const extra = { high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const f of visible) if (!f.kev && f.severity !== 'critical' && f.severity in extra) extra[f.severity]++;
  const extraNote = [extra.high && `高 ${extra.high}`, extra.medium && `中 ${extra.medium}`, extra.low && `低 ${extra.low}`].filter(Boolean).join('・');

  const sevOrder = (s: string) => ({ critical: 0, high: 1, medium: 2, low: 3 } as Record<string, number>)[s] ?? 4;
  const sorted = [...visible].sort((a, b) => Number(b.kev) - Number(a.kev) || sevOrder(a.severity) - sevOrder(b.severity));
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
        <span className="text-muted">{sel.size} / {visible.length} 件を選択中</span>
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

      {/* One-click bulk VEX: mark all checked CVEs "not affected" with a single justification. */}
      <div className="flex flex-wrap items-center gap-2 rounded border border-line bg-bg p-2 text-xs">
        <span className="w-full text-muted">このシステムで悪用できないと判断した場合、理由を選んで登録（迷ったら①）：</span>
        <select value={reason} onChange={(e) => setReason(e.target.value)} className="input text-xs sm:w-auto">
          <option value="">理由を選択…</option>
          {VEX_PRESETS.map((p) => <option key={p.code} value={p.code}>{p.label}</option>)}
        </select>
        <input value={note} onChange={(e) => setNote(e.target.value)} className="input text-xs sm:w-56" placeholder="メモ（任意・例：node実行環境なし）" />
        <button type="button" onClick={markNotAffected} disabled={vexBusy || !sel.size || !reason} className="btn disabled:opacity-50">
          {vexBusy ? '登録中…' : `選択を影響なしで登録（${sel.size}）`}
        </button>
        {vexMsg && <span className="w-full text-green-600">{vexMsg}</span>}
      </div>

      <pre className="max-h-96 select-all overflow-auto whitespace-pre-wrap break-words rounded bg-bg p-3 text-xs">{prompt}</pre>
    </div>
  );
}
