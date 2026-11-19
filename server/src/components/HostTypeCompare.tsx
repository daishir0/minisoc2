// Comparison of the two host-registration types, shown where the user chooses a type (host-add) and on a
// pull host's detail page (so missing OS/service/auditd data is explained in place). Generic: no host
// names; limitations are attributed to the host kind (e.g. "FreeDSD has no rpm/auditd") in general terms.
const ROWS: { label: string; agent: string; pull: string }[] = [
  { label: '導入方法', agent: 'cron等でエージェントが定期起動', pull: 'サーバーから読み取り専用SSHで定期接続（エージェント不要）' },
  { label: '向くホスト', agent: '自分で管理するLinux', pull: '共用ホスティング等（エージェントを置けない環境）' },
  { label: 'OSパッケージの脆弱性（kernel/openssl等）', agent: '✅', pull: '△ rpm/dpkg のある Linux のみ（FreeBSD等は✗）' },
  { label: '未適用のOSセキュリティ更新', agent: '✅', pull: '✗' },
  { label: 'アプリ依存の脆弱性（npm/composer/pip）', agent: '✅', pull: '✅（lockfileを収集）' },
  { label: 'ファイル改ざん（AIDE相当）', agent: '✅', pull: '✅（監視パス設定時）' },
  { label: '待受ポートの検知', agent: '✅', pull: '✅' },
  { label: 'ログ脅威／Web分析', agent: '✅ 継続収集', pull: '△ 定期・上限ありで取りこぼし得る' },
  { label: 'auditd 監視キー', agent: '✅', pull: '✗' },
  { label: '稼働サービスの把握', agent: '✅', pull: '✗' },
  { label: 'ログイン可能アカウントの増減', agent: '✅', pull: '✗' },
  { label: 'リアルタイム性', agent: '✅ 継続報告・オンライン表示', pull: '△ ポーリング（遅延）' },
  { label: '収集タイミング', agent: 'ホスト主導', pull: 'サーバー主導（間隔設定・「今すぐ収集」可）' },
];

const cls = (v: string) => (v.startsWith('✗') ? 'text-red-600' : v.startsWith('△') ? 'text-amber-600 dark:text-amber-400' : '');

export function HostTypeCompare() {
  return (
    <div>
      <div className="overflow-x-auto">
        <table className="tbl">
          <thead><tr><th>項目</th><th>通常（エージェント）</th><th>プル型（SSH・読み取り専用）</th></tr></thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.label}>
                <td className="whitespace-nowrap font-medium">{r.label}</td>
                <td className={`whitespace-nowrap ${cls(r.agent)}`}>{r.agent}</td>
                <td className={cls(r.pull)}>{r.pull}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-muted">凡例：✅対応／△条件付き・制限あり／✗非対応。△・✗の多くは<b>ホストの種類</b>によるもの（例：FreeBSD には rpm/dpkg や auditd が無い）で、プル型でも Linux なら OS パッケージの脆弱性を検知できます。</p>
    </div>
  );
}
