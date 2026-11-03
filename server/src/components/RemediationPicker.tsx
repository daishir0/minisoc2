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
  // OS findings only: vendor-tracker classification of a still-open item.
  //   'released' = fixed version shipped → upgrading resolves it (上げれば直る)
  //   'pending'  = vendor fix未リリース → nothing to apply yet (配布元待ち)
  osStatus?: 'pending' | 'released';
  osFixed?: string; // vendor fixed version (upgrade target) when released
}

// Lets the user tick specific CVEs on a project and generates a copy-paste Claude Code prompt that
// asks for a safe, backup-first upgrade plan. Advisory only — the human runs Claude Code on the host.
export function RemediationPicker({ host, address, path, system, systemId, osId, findings, title, emptyNote, bulk }: {
  host: string; address: string; path: string; system: string; systemId: number; osId?: string; findings: PickFinding[];
  title?: string;      // optional heading (used when the OS picker is split into kernel / non-kernel cards)
  emptyNote?: string;  // shown instead of the table when there are no findings in this scope (e.g. 対処不要)
  bulk?: boolean;      // OS "everything else" mode: one distro-wide security-update prompt, not per-CVE
}) {
  const isOs = osId !== undefined;
  const oid = osId ?? '';
  // Map the OS to its package manager so the generated commands are correct across distros.
  const mgr: 'apt' | 'dnf' | 'apk' | 'zypper' | 'unknown' =
    ['debian', 'ubuntu', 'raspbian', 'linuxmint', 'pop'].includes(oid) ? 'apt'
      : ['amzn', 'rhel', 'centos', 'rocky', 'almalinux', 'fedora', 'ol', 'oracle'].includes(oid) ? 'dnf'
        : oid === 'alpine' ? 'apk'
          : /suse|sles/.test(oid) ? 'zypper'
            : 'unknown';
  const pm = mgr; // back-compat alias used below
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

  // OS packages are fixed with apt/dnf. Kernel CVEs are cumulative (latest kernel + reboot clears them);
  // NON-kernel OS packages each need their own fix. Keep them apart and tell the human to verify first.
  const isKernel = (n: string) => /^(linux|kernel)([-.]|$)/.test(n);
  const osKernelPkgs = [...new Set(chosen.filter((f) => isKernel(f.pkg)).map((f) => f.pkg))];
  const osOtherPkgs = [...new Set(chosen.filter((f) => !isKernel(f.pkg)).map((f) => f.pkg))];
  const osPkgNames = [...new Set(chosen.map((f) => f.pkg))];
  const cveSummary = cves.length <= 6 ? cves.join('、') : `${cves.slice(0, 6).join('、')} 他${cves.length - 6}件`;
  const kevN2 = chosen.filter((f) => f.kev).length;
  // Use the actual installed kernel METApackages (no version digits), e.g. linux-aws / linux-image-aws
  // on Ubuntu AWS, linux-image-amd64 on Debian, linux-lts on Alpine — never a guessed name.
  const kernelMetas = osKernelPkgs.filter((n) => !/\d/.test(n));
  const rel = oid === 'amzn' ? ' --releasever=latest' : ''; // AL2023 only needs this; harmless note otherwise
  const others = osOtherPkgs.slice(0, 20).join(' ');
  const km = kernelMetas.join(' ') || '<カーネルのメタパッケージ>';
  const CMDS = {
    apt: { kernel: `sudo apt-get install --only-upgrade ${km}`, other: `sudo apt-get install --only-upgrade ${others}`, dry: 'sudo apt-get update && apt list --upgradable && sudo apt-get -s upgrade' },
    dnf: { kernel: `sudo dnf upgrade${rel} "kernel*"`, other: `sudo dnf upgrade${rel} ${others}`, dry: `sudo dnf check-update --security${rel}` },
    apk: { kernel: `sudo apk upgrade ${km}`, other: `sudo apk upgrade ${others}`, dry: "sudo apk update && apk version -l '<'" },
    zypper: { kernel: `sudo zypper update ${km}`, other: `sudo zypper update ${others}`, dry: 'sudo zypper refresh && zypper list-updates' },
    unknown: { kernel: '（このOSのパッケージマネージャでカーネルを最新へ）', other: '（このOSのパッケージマネージャで該当パッケージを更新）', dry: '（このOSのパッケージマネージャで未適用のセキュリティ更新を確認）' },
  }[mgr];
  const kernelCmd = CMDS.kernel;
  const otherCmd = osOtherPkgs.length ? CMDS.other : '';
  const dryRun = CMDS.dry;
  const osPrompt = cves.length === 0 ? '（上の一覧で対象のCVEにチェックを入れてください）' : [
    `ホスト「${host}」の **OS パッケージ（ホスト全体）** について、minisoc2 が ${cves.length} 件（${kevN2 ? `KEV ${kevN2}・` : ''}緊急含む）を検出しています。これは**対処の起点リスト**です。件数・CVEを鵜呑みにせず、まず実データで残存を確認してから、安全に適用してください。`,
    ``,
    `# 重要（誤解しやすい点）`,
    `- **kernel 系は累積更新**：修正版以上のカーネルに上げて再起動すれば旧版の kernel CVE は**まとめて解消**（1件ずつ不要）。ただし**「最新を入れた＝対応済み」ではありません**。下の「修正版」以上に達しているかで判断してください（例：稼働が 1066 でも修正版が 1069 なら未解消。より新しいカーネルが配信されていないか確認）。`,
    `- **kernel 以外の OS パッケージ**${osOtherPkgs.length ? `（例：${osOtherPkgs.slice(0, 5).join('、')}）` : ''}は**各パッケージごとに修正版を適用**して初めて解消。カーネル更新や再起動では消えません。`,
    ``,
    `# 手順`,
    `1. **現状確認（読み取りのみ）**：未適用の更新と差分を把握し、minisoc2 の一覧・USN/配布元トラッカーと突合（件数やCVEの実在も確認）：`,
    ``,
    `    ${dryRun}`,
    `    uname -r   # 稼働中カーネル`,
    ``,
    `2. **影響評価して結論を明示**：(a) 更新する ／ (b) 影響なし＝対処不要（理由＋VEX区分 code_not_present / requires_configuration 等）／ (c) 要確認。使っていない機能・パッケージは (b)。`,
    `3. **スナップショット/AMI 取得後に適用**（EC2 等クラウドは特に）。グロブや kernel とアプリの混在指定は避け、明示パッケージで分けて：`,
    ...(osKernelPkgs.length ? [`    - kernel（累積・最新へ）： ${kernelCmd}`] : []),
    ...(osOtherPkgs.length ? [`    - その他OSパッケージ（各々）： ${otherCmd}`] : []),
    `4. **再起動は kernel を更新した場合のみ**（\`sudo reboot\`）。配下サービスが停止するため時間帯を合意。起動不能時は旧カーネルで起動 or スナップショットから復元。`,
    ``,
    `# 解消の確認（重要・誤完了を防ぐ）`,
    `「最新を入れた」ではなく **「修正版以上に実際に達したか」** で判断してください（最新≠修正版のことがある：例として稼働カーネルが 1066 でも修正版が 1069 なら**未解消**）。`,
    ...(() => { const m = new Map(chosen.filter((f) => f.fixed).map((f) => [f.pkg, f.fixed])); const l = [...m.entries()].slice(0, 12).map(([p, fx]) => `    - ${p}: ${fx} 以上`); return l.length ? [`- 修正版が判明している対象（これ以上で解消）：`, ...l] : []; })(),
    ...(chosen.filter((f) => !f.fixed).length ? [`- 修正版情報が無い対象 ${chosen.filter((f) => !f.fixed).length}件：OSVに修正版が無いだけのこともあるので、USN/配布元トラッカーで最新の修正版・状況を確認。`] : []),
    `5. **更新後に導入版を確認**：各対象が上記「修正版以上」になったか（\`dpkg -l <pkg>\` / \`rpm -q <pkg>\`、kernel は \`uname -r\`）。達していれば可。**未達（修正版が未配信・リポジトリに無い等）なら「未解消・配布元待ち」として報告し、完了扱いにしない**。`,
    `6. 最後に minisoc2 の「今すぐ収集」で反映を確認。修正版に達したものから解消されます（達していないものは残るのが正しい）。`,
    ...(mgr === 'unknown' ? [`※このOS（${oid || '不明'}）のパッケージマネージャを自動判定できませんでした。上のコマンドは雛形です。dnf/apt/apk/zypper 等、実際のツールに読み替えてください。`] : []),
    `※ root 権限が無い環境（共用ホスティング等）では CLI 更新ができないことがあります。その場合はホスティングのコントロールパネルで更新してください。`,
    ``,
    `# 参考（minisoc2 の検出・起点）`,
    `- 対象パッケージ：${osPkgNames.slice(0, 12).join('、')}${osPkgNames.length > 12 ? ` 他${osPkgNames.length - 12}件` : ''}`,
    `- 対象CVE（${cves.length}件）：${cveSummary}`,
  ].join('\n');
  // Python environments are where "pip show version ≠ on-disk reality ≠ imported version" bites hardest
  // (user-site ~/.local shadows the env; a vulnerable copy can sit unused in the env while a newer one in
  // ~/.local is what imports). Detect by path and add an explicit "verify the real artifact" section.
  const isPy = /(?:miniforge3|anaconda3|miniconda3|\/envs\/|site-packages|\/venv|\.local)/i.test(path);
  const pyTrap = [
    ``,
    `# Python 実行環境の罠（この対象は Python 環境です・必読）`,
    `同じパッケージが複数の場所に同居し、「\`pip show\` の版」「ディスク上の実体」「実際に import される版」が食い違うことがあります（今回の典型的な誤対応の原因）。必ず**実体**で確認してください：`,
    `- \`<このenvのpython> -m pip show <pkg>\` の **Location 行**を見る（env本体か \`~/.local/lib/...\` か）。\`~/.local\` は**このホストの全Python環境に効く共有領域**で、env を上書きします。`,
    `- env本体の実体：\`ls -d <このenv>/lib/python*/site-packages/<pkg>-*.dist-info\``,
    `- 実行時にどれが勝つか：\`<このenvのpython> -c "import <mod>; print(<mod>.__version__, <mod>.__file__)"\`（sys.path は先頭が勝つ）`,
    `- minisoc2 は**ディスク上の実体**を棚卸しします。\`~/.local\` に新しい版があっても、env本体に古い脆弱な実体が残っていれば「脆弱」と正しく出ます。**両方**を修正版以上に揃えるか、不要な旧実体を削除してください。`,
    `- **別env・別プロジェクトの同名パッケージと混同しない**こと。版は必ず Location／\`__file__\` 付きで報告してください。`,
  ];
  const appPrompt = cves.length === 0 ? '（上の一覧で対象のCVEにチェックを入れてください）' : [
    `${host} のホスト（ホスト名：${host}、接続先：${address || '不明'}）の、${path} にあるシステム「${system}」について、脆弱性 ${cves.join('、')} の対応可否を判断し、必要なら安全に解消してください。`,
    ``,
    `# 対象パッケージ（現状 → 修正版の目安）`,
    ...pkgs.map((p) => `- ${p.pkg}: ${p.version || '(現行不明)'}${p.target ? ` → ${p.target} 以上（できれば同一メジャー系列の最新安定版）` : '（修正版は要確認）'}${p.kev ? '  ［KEV: 悪用確認済み・最優先］' : ''}`),
    ``,
    `# まず判定（重要）`,
    `${path} 配下のコード・依存・設定・実行環境を精査し、各CVEが**このシステムで実際に到達・悪用可能か**を評価してください（例：ランタイムが無い／該当コードが配置・実行されない／ビルド専用の devDependency で本番に関与しない、等）。その上で**結論を最初に明示**してください：`,
    `  (a) 修正する（到達可能、または予防的に妥当）`,
    `  (b) 影響なし＝対処不要（理由を明記。この場合は**ファイルを変更せず**、理由と、minisoc2 に登録できる VEX 区分 code_not_present / code_not_reachable / requires_environment / requires_configuration などを併記）。★この判断は **minisoc2 の該当システム画面の「影響なし」ボタンから登録**してください。プロンプトでの報告やパッケージのアンインストールだけでは、画面の脆弱性は消えません（minisoc2 はあなたの頭の中の判断ではなく、登録された VEX と実体の版だけを見ます）。`,
    `  (c) 要確認（判断材料が足りない点を具体的に）`,
    `**対処が無意味なとき（(b)）は、無理にアップグレードせず、その旨をはっきり報告**してください（lockfileだけの書き換え等、実害ゼロの"作業のための作業"はしない）。`,
    ...(isPy ? pyTrap : []),
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
  // OS "everything else" = a single distro security update, not per-CVE. Scope lists use ALL findings
  // (not the selection) because the bulk command patches them together regardless of what's ticked.
  const allPkgs = [...new Set(findings.map((f) => f.pkg))];
  const allCves = [...new Set(findings.map((f) => f.cve))];
  const kevAll = findings.filter((f) => f.kev).length;
  const bulkCmd = { apt: 'sudo apt-get update && sudo apt-get upgrade', dnf: "sudo dnf upgrade --security --exclude='kernel*'", apk: 'sudo apk upgrade', zypper: 'sudo zypper patch', unknown: '（このOSのパッケージマネージャで利用可能なセキュリティ更新を一括適用）' }[mgr];
  const restartChk = { apt: 'sudo needs-restarting -r 2>/dev/null || sudo checkrestart || true', dnf: 'sudo needs-restarting -r || true', apk: '（再起動が要るサービスを手動確認）', zypper: 'sudo zypper ps -s', unknown: '' }[mgr];
  const osBulkPrompt = findings.length === 0 ? '（未解消のOSパッケージ脆弱性はありません＝対処不要）' : [
    `ホスト「${host}」の **OSパッケージ（カーネル以外）** に minisoc2 が ${allCves.length} 件（${kevAll ? `KEV ${kevAll}・` : ''}緊急含む／パッケージ ${allPkgs.length}種）を検出しています。これは**1件ずつ上げるものではなく、ディストロのセキュリティ更新で一括適用**するのが正道です。CVE一覧は「この更新で解消される範囲（根拠）」であって、個別選択の対象ではありません。`,
    ``,
    `# 手順（一括）`,
    `1. **現状確認（読み取り）**：\`${dryRun}\``,
    `2. **スナップショット/AMI 取得**（クラウドは特に。問題時はここへ戻す）。`,
    `3. **一括適用（カーネルは別枠で計画実行するため除外）**：`,
    `    ${bulkCmd}`,
    `4. **稼働サービスの再起動**：更新後も旧ライブラリを掴んだプロセスが残ると実質未解消。要再起動を確認して再起動：`,
    ...(restartChk ? [`    ${restartChk}`] : []),
    `    例：\`sudo systemctl restart httpd\`（Apache/OpenSSL 等を更新した場合）。カーネルを更新した場合のみ再起動が必要だが、本手順ではカーネルは除外している。`,
    `5. **止めたいものは個別に hold**（使っていない/互換性懸念があるパッケージ）。意味の無い更新の強行はしない。`,
    `6. 完了後、minisoc2 の「今すぐ収集」で解消を確認。残るのは配布元待ち（修正版未リリース）等＝それは正しい。`,
    ``,
    `# 解消される範囲（根拠・抜粋）`,
    `- 対象パッケージ（${allPkgs.length}種）：${allPkgs.slice(0, 30).join('、')}${allPkgs.length > 30 ? ` 他${allPkgs.length - 30}種` : ''}`,
    `- 対象CVE（${allCves.length}件）：${allCves.slice(0, 20).join('、')}${allCves.length > 20 ? ` 他${allCves.length - 20}件` : ''}`,
  ].join('\n');
  const prompt = bulk ? osBulkPrompt : isOs ? osPrompt : appPrompt;

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

  if (findings.length === 0 && emptyNote) {
    return (
      <div className="space-y-2">
        {title && <h3 className="text-sm font-semibold">{title}</h3>}
        <p className="rounded border border-line bg-bg p-3 text-xs text-muted">{emptyNote}</p>
      </div>
    );
  }

  const listBody = (
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
      {extraNote && !bulk && (
        <p className="text-xs text-muted">
          初期選択は KEV・緊急のみです。これ以外に{extraNote}の脆弱性も検出しています（下の一覧でチェックすれば同じプロンプトに含められます）。
        </p>
      )}
      {(() => {
        const pend = findings.filter((f) => f.osStatus === 'pending').length;
        const rel = findings.filter((f) => f.osStatus === 'released').length;
        if (!pend && !rel) return null;
        return (
          <p className="text-xs text-muted">
            OSの脆弱性のうち
            {rel > 0 && <> <span className="rounded px-1 bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200">上げれば直る {rel}件</span></>}
            {pend > 0 && <> <span className="rounded px-1 bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-300">配布元待ち {pend}件</span>（修正版が未リリースのため現時点では対処不能）</>}
            。
          </p>
        );
      })()}
      <div className="max-h-64 overflow-y-auto rounded border border-line">
        <table className="tbl"><thead><tr><th className="w-8"></th><th>深刻度</th><th>CVE</th><th>パッケージ</th><th>現状→修正</th><th>対処可否</th></tr></thead><tbody>
          {sorted.map((f) => {
            const t = tier(f);
            return (
              <tr key={f.id} className={`cursor-pointer ${ROW[t]}`} onClick={() => toggle(f.id)}>
                <td><input type="checkbox" checked={sel.has(f.id)} onChange={() => toggle(f.id)} onClick={(e) => e.stopPropagation()} /></td>
                <td><span className={`rounded px-1.5 py-0.5 text-[10px] ${CHIP[t]}`}>{LABEL[t]}</span></td>
                <td className="whitespace-nowrap font-mono text-xs">{f.cve}</td>
                <td className="break-all font-mono text-xs">{f.pkg}</td>
                <td className="whitespace-nowrap font-mono text-xs text-muted">{f.version.slice(0, 20)}{(() => { const t = bestFixTarget(f.version, (f.fixed || '').split(/,\s*/)); return t ? ` → ${t.slice(0, 20)}` : ''; })()}</td>
                <td className="whitespace-nowrap">{f.osStatus === 'pending'
                  ? <span className="rounded px-1.5 py-0.5 text-[10px] bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-300" title="配布元が修正版を未リリース。現時点では適用できません（Livepatch等の緩和のみ）">配布元待ち</span>
                  : f.osStatus === 'released'
                  ? <span className="rounded px-1.5 py-0.5 text-[10px] bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200" title={`修正版あり：${f.osFixed || '（更新で解消）'}。アップグレードで解消します`}>上げれば直る{f.osFixed ? ` → ${f.osFixed.slice(0, 18)}` : ''}</span>
                  : null}</td>
              </tr>
            );
          })}
        </tbody></table>
      </div>
    </div>
  );

  return (
    <div className="space-y-3">
      {title && <h3 className="text-sm font-semibold">{title}</h3>}
      {bulk && (
        <p className="text-xs text-muted">このOSは<b>個別に選ぶのではなく一括更新</b>が正道です。下のプロンプトをそのまま対象ホストで実行してください。対象一覧（{findings.length}件）は参考として折りたたんであります。</p>
      )}
      {bulk ? (
        <details className="rounded border border-line p-2">
          <summary className="cursor-pointer text-xs text-muted">対象一覧（{findings.length}件・参考）／特定パッケージを「影響なし」登録したい時もここから</summary>
          <div className="mt-3">{listBody}</div>
        </details>
      ) : listBody}
      {/* On phones the CVE list is long; keep the primary copy action within thumb reach as a sticky
          bottom bar. On >=sm it returns to a normal right-aligned button. */}
      <div className="sticky bottom-0 z-10 flex justify-end border-t border-line bg-bg/95 py-2 backdrop-blur sm:static sm:border-0 sm:bg-transparent sm:py-0 sm:backdrop-blur-none">
        <button type="button" onClick={copy} disabled={prompt.startsWith('（')} className="btn w-full text-sm disabled:opacity-50 sm:w-auto sm:text-xs">{copied ? 'コピーしました' : '📋 プロンプトをコピー'}</button>
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
