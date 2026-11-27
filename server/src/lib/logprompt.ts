// Pure, client-safe builder (no server imports) for a copy-paste Claude Code prompt that investigates
// one or more log threats on ONE host, read-only, and judges each. Shared by the logs page (server)
// and LogThreatPicker (client). Advisory only — the human reviews it and runs Claude Code themselves;
// minisoc2 never executes anything on a host. Mirrors the CVE remediation prompt (host guard +
// READ-ONLY + per-item観点 + 🔴/🟡/🟢 verdict) but for log anomalies instead of CVEs.
export interface LogThreatItem {
  title: string;        // human-readable detection summary, e.g. "[host] Web 4xx が平常の23.2倍：access_log"
  detail?: string | null; // a short raw-log sample, if the detector captured one
}

export function logThreatPrompt(
  host: { host: string; address: string; hostId: string },
  threats: LogThreatItem[],
): string {
  const n = threats.length;
  const items = threats.flatMap((t, i) => [
    `${i + 1}. ${t.title}`,
    ...(t.detail ? ['   記録サンプル（minisoc2の事前分析＝上位IP・ステータス内訳・探索検出）:', '   ```', ...t.detail.slice(0, 900).split('\n').map((l) => '   ' + l), '   ```'] : []),
  ]);
  const lines = [
    `あなたはホスト「${host.host}」上で動作している Claude Code です。以下のログ脅威${n}件を、変更を一切加えずに（READ-ONLY）調査し、それぞれ脅威かどうかを判定してください。`,
    ``,
    `# 実行対象ホスト（取り違え防止・必ず確認）`,
    `- ホスト名 : ${host.host}`,
    `- 接続先   : ${host.address || '不明'}`,
    `- ホストID : ${host.hostId}（minisoc2 の識別子）`,
    `- 対象     : ログ脅威（anomaly）${n}件`,
    `作業前に \`hostname\` を実行し、このプロンプトが想定するホスト（上記）と一致することを確認してください。別のホストでは実行しないこと（一致しなければ中止）。`,
    ``,
    `# これは調査専用プロンプトです（READ-ONLY・絶対に変更しない）`,
    `禁止：設定変更 / サービス再起動 / ファイル編集 / 遮断ルール追加 / パッケージ操作。`,
    `許可：ログ・journal・ss・ps 等の読み取りコマンドのみ。遮断や恒久対処は「推奨」として提示するだけで実行しない。`,
    ``,
    `# 対象の脅威（minisoc2 の検出・${n}件）`,
    ...items,
    ``,
    `# 進め方`,
    `脅威を1件ずつ上から順に調査する。ただし同一ソースの関連事象（例：同じ access_log のリクエスト増と4xx増）はまとめて調査してよい。各脅威について下記の観点を必ず実データで確認する。`,
    ``,
    `# 調べる観点（各脅威について、必ず実データで）`,
    `1. 実在性：警告の数値が実ログと一致するか。対象ソースの対象日のレコードを自分で数え直す（ローテーション／.gz／当日分の未収集・タイムゾーン境界の取りこぼしを疑う）。一致しなければ「誤検知」を明記。`,
    `2. 正体：増減の中身を分解する。アクセスログなら送信元IP上位・ステータス内訳・リクエストパス上位・UA（単一IP集中か分散か）。journal なら反復メッセージ上位（UUID/数値は正規化）・エラーか正常ログか・NRestarts と稼働状態。`,
    `3. 悪性度：スキャン／探索（.env/.git/phpinfo/設定ファイル等）か、正規トラフィックか、アプリの入力不備か。`,
    `4. 影響の裏取り：機微パスに 200 を返していないか（情報漏洩の有無）。認証突破・5xx連鎖・クラッシュ/再起動の有無。`,
    `5. 露出：外部からの到達経路（公開ポート・vhost・認証）。ss -tlnp 等は読み取りのみ。`,
    `6. 既知性：既知の攻撃キャンペーン・スキャナか（必要ならネット調査）。KEV相当の実悪用があるか。`,
    ``,
    `# 出力（脅威ごとに結論を先頭に）`,
    `各脅威について次のいずれかで判定する：`,
    `- 🔴 実脅威：到達・悪用または実害あり。根拠（IP/パス/ステータス/漏洩有無）とともに推奨対処（遮断・fail2ban・修正）を提示（実行はしない）。`,
    `- 🟡 要確認：判断材料が不足。追加で見るべきログ・コマンドを具体的に。`,
    `- 🟢 問題なし：理由を明記し、区分を併記 → false_positive（誤検知）／ benign_traffic（正規）／ blocked_no_impact（遮断済・実害なし）／ app_input_error（アプリ入力不備）／ expected_spike（想定内増加）。`,
    ``,
    `# 最後に要約表`,
    `脅威番号｜判定（🔴/🟡/🟢）｜区分｜1行結論（対処する／確認中／問題なし＝確認済みにしてよい）を一覧化する。`,
  ];
  return lines.join('\n');
}
