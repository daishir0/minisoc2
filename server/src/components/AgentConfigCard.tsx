'use client';

import { useState } from 'react';

export interface AgentConfig {
  scanPaths: string[]; skipDirs: string[]; aidePaths: string[]; aideExcludes: string[];
  logFiles: string[]; journal: boolean; useSudo: boolean; autoUpdate: boolean; aide: boolean; pin?: string;
}

function Copy({ text, label = 'コピー' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="btn-ghost text-xs" onClick={async () => {
      try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); } catch { /* blocked */ }
    }}>{done ? 'コピーしました' : label}</button>
  );
}

const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

// Shows the agent's effective settings (read-only), its update status, and generates ready-to-paste
// SSH commands to change settings / collect now / change frequency. The server never runs these.
export function AgentConfigCard({ cfg, invoke, root, version, latest, intervalHours }: {
  cfg: AgentConfig; invoke: string; root: boolean; version: string; latest: string; intervalHours?: number;
}) {
  const [scan, setScan] = useState(cfg.scanPaths.join('\n'));
  const [aide, setAide] = useState((cfg.aidePaths ?? []).join('\n'));
  const [aideEx, setAideEx] = useState((cfg.aideExcludes ?? []).join('\n'));
  const [logs, setLogs] = useState((cfg.logFiles ?? []).join('\n'));
  const [every, setEvery] = useState(intervalHours ?? 1);

  const P = `${root ? 'sudo ' : ''}${invoke}`;
  const flag = (name: string, vals: string[]) => `--${name} ${vals.join(',')}`;
  const configCmd = `${P} config ${flag('scan', lines(scan))} ${flag('aide-paths', lines(aide))} ${flag('aide-excludes', lines(aideEx))} ${flag('log-files', lines(logs))} && ${P} run`;
  const runCmd = `${P} run`;
  const everyCmd = `${P} schedule install --every ${Math.max(1, Math.min(24, Number(every) || 1))} && ${P} run`;

  const updateState = version === latest ? 'up' : latest && version < latest ? 'old' : 'unknown';
  const row = 'grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm';
  const ta = 'input font-mono text-xs';

  return (
    <div className="space-y-4">
      {/* D: update status */}
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted">エージェント</span>
        <span className="font-mono">{version}</span>
        {updateState === 'up' && <span className="rounded bg-green-600 px-2 py-0.5 text-xs text-white">最新</span>}
        {updateState === 'old' && <span className="rounded bg-orange-500 px-2 py-0.5 text-xs text-white">要更新（最新 {latest}）</span>}
        {updateState === 'unknown' && latest && <span className="text-xs text-muted">最新: {latest}</span>}
        {cfg.autoUpdate
          ? <span className="text-xs text-muted">自動更新オン：次回の収集で最新に更新されます</span>
          : <span className="text-xs text-orange-600">自動更新オフ：下の「今すぐ収集」で更新されません。手動更新が必要です</span>}
      </div>

      {/* A: current settings (read-only) */}
      <div>
        <h3 className="mb-1 text-xs font-semibold text-muted">現在の監視設定（エージェントが報告）</h3>
        <dl className={row}>
          <dt className="text-muted">スキャン対象</dt><dd className="break-all font-mono text-xs">{cfg.scanPaths.join('  ') || '（なし）'}</dd>
          <dt className="text-muted">改ざん監視</dt><dd className="break-all font-mono text-xs">{cfg.aide ? (cfg.aidePaths?.join('  ') || '（既定）') : '無効'}</dd>
          <dt className="text-muted">改ざん除外</dt><dd className="break-all font-mono text-xs">{cfg.aideExcludes?.join('  ') || '（なし）'}</dd>
          <dt className="text-muted">ログ収集</dt><dd className="break-all font-mono text-xs">{cfg.journal ? 'journald + ' : ''}{cfg.logFiles?.join('  ') || '（ファイルなし）'}</dd>
          <dt className="text-muted">sudo / 自動更新</dt><dd>{cfg.useSudo ? 'sudo あり' : 'sudo なし'} ・ {cfg.autoUpdate ? '自動更新オン' : '自動更新オフ'}{cfg.pin ? ` ・ 版固定 ${cfg.pin}` : ''}</dd>
          <dt className="text-muted">収集間隔</dt><dd>{intervalHours ? `${intervalHours} 時間ごと` : '不明'}</dd>
        </dl>
      </div>

      {/* C: collect now */}
      <div>
        <h3 className="mb-1 text-xs font-semibold text-muted">今すぐ収集する（SSHで接続して貼り付け）</h3>
        <p className="mb-1 text-xs text-muted">次回の定期収集を待たず、1回だけ即実行して送信します（間隔は変わりません）。{cfg.autoUpdate ? '実行時にエージェントも最新へ自動更新されます。' : ''}</p>
        <div className="flex items-start gap-2"><pre className="min-w-0 flex-1 select-all overflow-x-auto rounded bg-bg p-2 text-xs">{runCmd}</pre><Copy text={runCmd} /></div>
      </div>

      {/* B: change settings */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold text-muted">監視設定を変更する（下を編集 → 生成コマンドをSSHで貼り付け）</h3>
        <label className="block text-xs text-muted">スキャン対象ディレクトリ（改行区切り）<textarea className={ta} rows={2} value={scan} onChange={(e) => setScan(e.target.value)} /></label>
        <label className="block text-xs text-muted">改ざん監視ディレクトリ（改行区切り。空欄で既定）<textarea className={ta} rows={2} value={aide} onChange={(e) => setAide(e.target.value)} /></label>
        <label className="block text-xs text-muted">改ざん除外（改行区切り）<textarea className={ta} rows={2} value={aideEx} onChange={(e) => setAideEx(e.target.value)} /></label>
        <label className="block text-xs text-muted">収集するログファイル（改行区切り）<textarea className={ta} rows={2} value={logs} onChange={(e) => setLogs(e.target.value)} /></label>
        <div className="flex items-start gap-2"><pre className="min-w-0 flex-1 select-all overflow-x-auto whitespace-pre-wrap break-all rounded bg-bg p-2 text-xs">{configCmd}</pre><Copy text={configCmd} /></div>
        <p className="text-xs text-muted">設定を保存し、その場で1回収集します（<code>&amp;&amp; run</code>）。</p>
      </div>

      {/* interval change */}
      <div>
        <h3 className="mb-1 text-xs font-semibold text-muted">収集の頻度を変える</h3>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <label>間隔 <input type="number" min={1} max={24} value={every} onChange={(e) => setEvery(Number(e.target.value))} className="input w-16" /> 時間ごと</label>
          <Copy text={everyCmd} label="コマンドをコピー" />
        </div>
        <div className="mt-1 flex items-start gap-2"><pre className="min-w-0 flex-1 select-all overflow-x-auto break-all rounded bg-bg p-2 text-xs">{everyCmd}</pre></div>
      </div>
    </div>
  );
}
